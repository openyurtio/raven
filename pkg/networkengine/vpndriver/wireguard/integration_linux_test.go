//go:build linux

/*
Copyright 2026 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// These tests require an isolated, privileged Linux container, iproute2,
// iptables/ipset, ping, and the built wireguard-go at wireguardBinary.
// Userspace forcing is test-internal; it is not an agent configuration option.
const integrationAutoFallback = "auto-fallback"

type integrationConfig struct {
	Node       string
	Backend    string
	Key        wgtypes.Key
	Network    *types.Network
	Directory  string
	DeviceOnly bool
}

type integrationManager struct{ manager.Manager }

func (integrationManager) GetClient() client.Client { return nil }

func TestWireGuardIntegrationNode(t *testing.T) {
	path := os.Getenv("RAVEN_WG_NODE_CONFIG")
	if path == "" {
		return
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c integrationConfig
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	cfg := &config.Config{NodeName: c.Node, Manager: integrationManager{}, Tunnel: &config.TunnelConfig{VPNPort: "4500", MACPrefix: "aa:0f"}}
	driver, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	w := driver.(*wireguard)
	w.SetLifecycle(ctx, nil)
	if err := w.Init(); err != nil {
		t.Fatal(err)
	}
	w.privateKey = c.Key
	if c.Backend == backendUserspace {
		w.device.selected = backendUserspace
	}
	if c.DeviceOnly {
		w.applyNAT = func(*types.Network) error { return nil }
		w.cleanupNAT = func() error { return nil }
	}
	route, err := vxlan.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !c.DeviceOnly {
		if err := route.Init(); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		if err := w.Cleanup(); err != nil {
			t.Error(err)
		}
		if !c.DeviceOnly {
			if err := route.Cleanup(); err != nil {
				t.Error(err)
			}
		}
		if _, err := netlink.LinkByName(DeviceName); !linkMissing(err) {
			t.Error("WireGuard link remains after cleanup")
		}
		if w.device.process.Running() {
			t.Error("wireguard-go remains after cleanup")
		}
		if _, err := os.Stat(wireguardSocket); !os.IsNotExist(err) {
			t.Error("UAPI socket remains after cleanup")
		}
		rules, err := netlink.RuleList(netlink.FAMILY_V4)
		if err != nil {
			t.Error(err)
		}
		for _, rule := range rules {
			if rule.Table == 9027 || rule.Table == 9028 {
				t.Errorf("Raven rule remains: %v", rule)
			}
		}
		for _, table := range []int{9027, 9028} {
			routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
			if err != nil || len(routes) > 0 {
				t.Errorf("routes remain in table %d: %v %v", table, routes, err)
			}
		}
	}()
	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if _, err := os.Stat(filepath.Join(c.Directory, c.Node+".freeze")); err == nil {
			_ = os.Remove(filepath.Join(c.Directory, c.Node+".freeze"))
			p := w.device.process.(*subprocess)
			if p.cmd != nil {
				_ = p.cmd.Process.Signal(syscall.SIGSTOP)
			}
		}
		if _, err := os.Stat(filepath.Join(c.Directory, c.Node+".kill")); err == nil {
			_ = os.Remove(filepath.Join(c.Directory, c.Node+".kill"))
			p := w.device.process.(*subprocess)
			if p.cmd != nil {
				_ = p.cmd.Process.Kill()
			}
			continue
		}
		_ = os.Remove(filepath.Join(c.Directory, c.Node+".ready"))
		mtu := route.MTU
		if c.DeviceOnly {
			mtu = func(*types.Network) (int, error) { return 1450, nil }
		}
		if err := w.Apply(c.Network.Copy(), mtu); err != nil {
			_ = os.WriteFile(filepath.Join(c.Directory, c.Node+".error"), []byte("VPN: "+err.Error()), 0600)
			continue
		}
		if !c.DeviceOnly {
			if err := route.Apply(c.Network.Copy(), w.MTU); err != nil {
				_ = os.WriteFile(filepath.Join(c.Directory, c.Node+".error"), []byte("route: "+err.Error()), 0600)
				continue
			}
		}
		w.SetNetworkReady(true)
		_ = os.Remove(filepath.Join(c.Directory, c.Node+".error"))
		if w.wgClient != nil {
			if dev, err := w.wgClient.Device(DeviceName); err == nil {
				if c.Backend == integrationAutoFallback && c.Node == string(c.Network.LocalEndpoint.NodeName) {
					if w.device.selected != backendUserspace || dev.Type != wgtypes.Userspace || dev.PublicKey != c.Key.PublicKey() {
						t.Fatal("automatic fallback did not retain the expected userspace backend and key")
					}
				}
				state := fmt.Sprintf("backend=%v port=%d publicKey=%s\n", dev.Type, dev.ListenPort, dev.PublicKey)
				for _, p := range dev.Peers {
					state += fmt.Sprintf("peer=%s endpoint=%v handshake=%v rx=%d tx=%d\n", p.PublicKey, p.Endpoint, p.LastHandshakeTime, p.ReceiveBytes, p.TransmitBytes)
				}
				_ = os.WriteFile(filepath.Join(c.Directory, c.Node+".state"), []byte(state), 0600)
			}
		}
		if p, ok := w.device.process.(*subprocess); ok {
			p.mu.Lock()
			pid := 0
			if p.cmd != nil {
				pid = p.cmd.Process.Pid
			}
			p.mu.Unlock()
			pidPath := filepath.Join(c.Directory, c.Node+".pid")
			if err := os.WriteFile(pidPath+".tmp", []byte(strconv.Itoa(pid)), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(pidPath+".tmp", pidPath); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(c.Directory, c.Node+".ready"), []byte(w.device.selected), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

// A UDP echo exposes the observed Pod source address, checking that traffic
// crossing VXLAN and the VPN was not inadvertently SNATed.
func TestWireGuardIntegrationUDP(t *testing.T) {
	mode := os.Getenv("RAVEN_WG_UDP")
	if mode == "" {
		return
	}
	if mode == "server" {
		conn, err := net.ListenPacket("udp4", ":7999")
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		if ready := os.Getenv("RAVEN_WG_UDP_READY"); ready != "" {
			if err := os.WriteFile(ready, nil, 0600); err != nil {
				t.Fatal(err)
			}
		}
		buf := make([]byte, 64)
		for {
			_, addr, err := conn.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = conn.WriteTo([]byte(addr.String()), addr)
		}
	}
	dialer := net.Dialer{Timeout: time.Second, LocalAddr: &net.UDPAddr{IP: net.ParseIP(os.Getenv("RAVEN_WG_SOURCE"))}}
	conn, err := dialer.Dial("udp4", os.Getenv("RAVEN_WG_TARGET"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte("source")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(buf[:n]), os.Getenv("RAVEN_WG_SOURCE")+":") {
		t.Fatalf("source address changed: %s", buf[:n])
	}
}

func TestWireGuardDeviceIntegration(t *testing.T) {
	if os.Getenv("RAVEN_WG_DEVICE_INTEGRATION") != "1" {
		t.Skip("requires isolated privileged Linux")
	}
	for _, tc := range []struct {
		name     string
		backends []string
		relay    bool
	}{
		{"kernel-kernel", []string{backendKernel, backendKernel}, false},
		{"kernel-userspace", []string{backendKernel, backendUserspace}, false},
		{"userspace-userspace", []string{backendUserspace, backendUserspace}, false},
		{"central-relay", []string{backendKernel, backendUserspace, backendUserspace}, true},
	} {
		t.Run(tc.name, func(t *testing.T) { runNetworkIntegration(t, tc.backends, tc.relay, true) })
	}
}

func TestWireGuardNetworkIntegration(t *testing.T) {
	if os.Getenv("RAVEN_WG_INTEGRATION") != "1" {
		t.Skip("requires isolated privileged Linux network environment")
	}
	for _, tc := range []struct {
		name     string
		backends []string
		relay    bool
	}{
		{"kernel-kernel", []string{backendKernel, backendKernel}, false},
		{"kernel-userspace", []string{backendKernel, backendUserspace}, false},
		{"userspace-userspace", []string{backendUserspace, backendUserspace}, false},
		{"central-relay", []string{backendKernel, backendUserspace, backendUserspace}, true},
	} {
		t.Run(tc.name, func(t *testing.T) { runNetworkIntegration(t, tc.backends, tc.relay, false) })
	}
}

// Unlike the forced-backend suites, this test requires the real kernel to
// reject WireGuard creation. No backend or netlink dependency is substituted.
func TestWireGuardAutomaticFallbackIntegration(t *testing.T) {
	mode := os.Getenv("RAVEN_WG_AUTO_FALLBACK_INTEGRATION")
	if mode == "" {
		t.Skip("requires isolated Linux with kernel WireGuard unavailable; set device or network")
	}
	if mode != "device" && mode != "network" {
		t.Fatal("RAVEN_WG_AUTO_FALLBACK_INTEGRATION must be device or network")
	}
	attrs := netlink.NewLinkAttrs()
	attrs.Name = "r193wgprobe"
	probe := &netlink.GenericLink{LinkAttrs: attrs, LinkType: wgLinkType}
	err := netlink.LinkAdd(probe)
	if err == nil {
		if cleanupErr := netlink.LinkDel(probe); cleanupErr != nil {
			t.Fatal(cleanupErr)
		}
		t.Fatal("kernel WireGuard is available; this environment cannot validate automatic fallback")
	}
	if !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("kernel probe returned %v, want EOPNOTSUPP (permissions errors do not qualify)", err)
	}
	t.Logf("real kernel WireGuard creation returned %v", err)
	for _, tc := range []struct {
		name  string
		count int
		relay bool
	}{
		{"direct", 2, false},
		{"central-relay", 3, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backends := make([]string, tc.count)
			for i := range backends {
				backends[i] = integrationAutoFallback
			}
			runNetworkIntegration(t, backends, tc.relay, mode == "device")
		})
	}
}

func runNetworkIntegration(t *testing.T, backends []string, relay bool, deviceOnly bool) {
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := exec.Command(args[0], args[1:]...).CombinedOutput(); err != nil {
			t.Fatalf("%v: %v\n%s", args, err, out)
		}
	}
	// Resolve the image's iptables wrapper once before concurrent helpers.
	run("iptables", "--version")
	if !deviceOnly {
		run("ipset", "create", "r193check", "hash:net,net")
		run("ipset", "destroy", "r193check")
	}
	const bridge = "r193br"
	run("ip", "link", "add", bridge, "type", "bridge")
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", bridge).Run() })
	run("ip", "addr", "add", "172.31.193.254/24", "dev", bridge)
	run("ip", "link", "set", bridge, "up")
	var nodes []string
	var keys []wgtypes.Key
	for i := range backends {
		key, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, key)
		for j := 0; j < 2; j++ {
			name := fmt.Sprintf("r193n%d", 2*i+j)
			nodes = append(nodes, name)
			run("ip", "netns", "add", name)
			t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
			peer := fmt.Sprintf("r193v%d", 2*i+j)
			run("ip", "link", "add", peer, "type", "veth", "peer", "name", "eth0", "netns", name)
			t.Cleanup(func() { _ = exec.Command("ip", "link", "del", peer).Run() })
			run("ip", "link", "set", peer, "master", bridge)
			run("ip", "link", "set", peer, "up")
			run("ip", "-n", name, "addr", "add", fmt.Sprintf("172.31.193.%d/24", 10+10*i+j), "dev", "eth0")
			run("ip", "-n", name, "link", "set", "eth0", "up")
			run("ip", "-n", name, "link", "set", "lo", "up")
			if deviceOnly && j == 0 {
				run("ip", "-n", name, "addr", "add", fmt.Sprintf("10.193.%d.1/32", 2*i), "dev", "lo")
			}
			run("ip", "-n", name, "route", "add", "default", "via", "172.31.193.254")
			run("ip", "netns", "exec", name, "sysctl", "-qw", "net.ipv4.ip_forward=1", "net.ipv4.conf.all.rp_filter=0", "net.ipv4.conf.default.rp_filter=0", "net.ipv4.conf.all.send_redirects=0")
		}
		pod := fmt.Sprintf("r193p%d", i)
		run("ip", "netns", "add", pod)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", pod).Run() })
		run("ip", "-n", nodes[2*i+1], "link", "add", "cni0", "type", "veth", "peer", "name", "eth0", "netns", pod)
		run("ip", "-n", nodes[2*i+1], "addr", "add", fmt.Sprintf("10.193.%d.1/24", 2*i+1), "dev", "cni0")
		run("ip", "-n", nodes[2*i+1], "link", "set", "cni0", "up")
		run("ip", "-n", pod, "addr", "add", fmt.Sprintf("10.193.%d.2/24", 2*i+1), "dev", "eth0")
		run("ip", "-n", pod, "link", "set", "eth0", "up")
		run("ip", "-n", pod, "link", "set", "lo", "up")
		run("ip", "-n", pod, "route", "add", "default", "via", fmt.Sprintf("10.193.%d.1", 2*i+1))
	}
	var children []*exec.Cmd
	// Registered after namespaces: stop helpers and check cleanup before deleting namespaces.
	t.Cleanup(func() {
		for _, cmd := range children {
			_ = cmd.Process.Signal(syscall.SIGTERM)
		}
		for i, cmd := range children {
			if err := cmd.Wait(); err != nil {
				b, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d.log", i)))
				t.Errorf("node helper: %v\n%s", err, tailLog(b))
			}
		}
	})
	for n, node := range nodes {
		pool := n / 2
		nw := &types.Network{LocalNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{}, RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{}, RemoteEndpoints: map[types.GatewayName]*types.Endpoint{}}
		for i := range backends {
			ep := &types.Endpoint{GatewayName: types.GatewayName(fmt.Sprintf("pool%d", i)), NodeName: types.NodeName(nodes[2*i]), PrivateIP: fmt.Sprintf("172.31.193.%d", 10+10*i), PublicIP: fmt.Sprintf("172.31.193.%d", 10+10*i), PublicPort: 4500, UnderNAT: relay && i > 0, ExposeType: v1beta1.ExposeTypePublicIP, Config: map[string]string{PublicKey: keys[i].PublicKey().String()}}
			for j := 0; j < 2; j++ {
				info := &v1beta1.NodeInfo{NodeName: nodes[2*i+j], PrivateIP: fmt.Sprintf("172.31.193.%d", 10+10*i+j), Subnets: []string{fmt.Sprintf("10.193.%d.0/24", 2*i+j)}}
				ep.Subnets = append(ep.Subnets, info.Subnets...)
				if i == pool {
					nw.LocalNodeInfo[types.NodeName(info.NodeName)] = info
				} else {
					nw.RemoteNodeInfo[types.NodeName(info.NodeName)] = info
				}
			}
			if i == pool {
				nw.LocalEndpoint = ep
			} else {
				nw.RemoteEndpoints[ep.GatewayName] = ep
			}
		}
		cfg := integrationConfig{Node: node, Backend: backends[pool], Key: keys[pool], Network: nw, Directory: dir, DeviceOnly: deviceOnly}
		b, _ := json.Marshal(cfg)
		path := filepath.Join(dir, node+".json")
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		// UAPI paths are filesystem-scoped, so each node needs its own mount namespace.
		cmd := exec.Command("ip", "netns", "exec", node, "unshare", "-m", "sh", "-c", "mount -t tmpfs tmpfs /var/run/wireguard && exec \"$1\" -test.run=^TestWireGuardIntegrationNode$", "sh", os.Args[0])
		cmd.Env = append(os.Environ(), "RAVEN_WG_NODE_CONFIG="+path)
		log, err := os.Create(filepath.Join(dir, fmt.Sprintf("node%d.log", n)))
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		_ = log.Close()
		children = append(children, cmd)
	}
	for n, node := range nodes {
		deadline := time.Now().Add(20 * time.Second)
		for {
			if ready, err := os.ReadFile(filepath.Join(dir, node+".ready")); err == nil {
				if backends[n/2] == integrationAutoFallback && n%2 == 0 && string(ready) != backendUserspace {
					t.Fatalf("node %s selected %q instead of automatically falling back", node, ready)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("node %s not ready", node)
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	first, last := 0, len(backends)-1
	if relay {
		first = 1
	}
	sourceNS, destNS := fmt.Sprintf("r193p%d", first), fmt.Sprintf("r193p%d", last)
	sourceIP, destIP := fmt.Sprintf("10.193.%d.2", 2*first+1), fmt.Sprintf("10.193.%d.2", 2*last+1)
	if deviceOnly {
		sourceNS, destNS = nodes[2*first], nodes[2*last]
		sourceIP, destIP = fmt.Sprintf("10.193.%d.1", 2*first), fmt.Sprintf("10.193.%d.1", 2*last)
	}
	ping := func() error {
		return exec.Command("ip", "netns", "exec", sourceNS, "ping", "-I", sourceIP, "-c", "1", "-W", "1", destIP).Run()
	}
	waitPing := func() {
		t.Helper()
		deadline := time.Now().Add(30 * time.Second)
		for {
			if ping() == nil {
				return
			}
			if time.Now().After(deadline) {
				for n := range children {
					b, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d.log", n)))
					t.Logf("node %d: %s", n, tailLog(b))
					state, _ := os.ReadFile(filepath.Join(dir, nodes[n]+".state"))
					t.Logf("state %s", state)
				}
				t.Fatal("cross-pool Pod ping failed")
			}
			time.Sleep(100 * time.Millisecond)
		}
	}
	waitPing()
	run("ip", "netns", "exec", destNS, "ping", "-I", destIP, "-c", "1", "-W", "2", sourceIP)
	server := exec.Command("ip", "netns", "exec", destNS, os.Args[0], "-test.run=^TestWireGuardIntegrationUDP$")
	serverReady := filepath.Join(dir, "udp-server.ready")
	server.Env = append(os.Environ(), "RAVEN_WG_UDP=server", "RAVEN_WG_UDP_READY="+serverReady)
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Process.Kill(); _ = server.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(serverReady); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("UDP echo server did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	probe := exec.Command("ip", "netns", "exec", sourceNS, os.Args[0], "-test.run=^TestWireGuardIntegrationUDP$")
	probe.Env = append(os.Environ(), "RAVEN_WG_UDP=client", "RAVEN_WG_TARGET="+net.JoinHostPort(destIP, "7999"), "RAVEN_WG_SOURCE="+sourceIP)
	if out, err := probe.CombinedOutput(); err != nil {
		t.Fatalf("Pod source-address check: %v\n%s", err, out)
	}
	usesUserspace := func(i int) bool {
		return backends[i] == backendUserspace || backends[i] == integrationAutoFallback
	}
	readPID := func() string {
		b, _ := os.ReadFile(filepath.Join(dir, nodes[2*last]+".pid"))
		return string(b)
	}
	waitReplacement := func(previous string) {
		t.Helper()
		if pid, err := strconv.Atoi(previous); err != nil || pid <= 0 {
			t.Fatalf("missing initial userspace PID: %q", previous)
		}
		deadline := time.Now().Add(35 * time.Second)
		for time.Now().Before(deadline) {
			if pid := readPID(); pid != "" && pid != "0" && pid != previous {
				t.Logf("userspace process recovered: PID %s -> %s", previous, pid)
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		b, _ := os.ReadFile(filepath.Join(dir, fmt.Sprintf("node%d.log", 2*last)))
		t.Logf("recovery log: %s", tailLog(b))
		lastError, _ := os.ReadFile(filepath.Join(dir, nodes[2*last]+".error"))
		t.Logf("last reconciliation error: %s", lastError)
		t.Logf("previous ready PID=%q latest ready PID=%q", previous, readPID())
		t.Fatal("replacement userspace process did not reach network readiness after fault injection")
	}
	if usesUserspace(last) {
		previous := readPID()
		marker := filepath.Join(dir, nodes[2*last]+".kill")
		if err := os.WriteFile(marker, []byte(strconv.Itoa(last)), 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(marker); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("kill request not processed")
			}
			time.Sleep(50 * time.Millisecond)
		}
		waitReplacement(previous)
		waitPing()
	}
	if usesUserspace(first) && usesUserspace(last) && !relay {
		previous := readPID()
		marker := filepath.Join(dir, nodes[2*last]+".freeze")
		if err := os.WriteFile(marker, nil, 0600); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(3 * time.Second)
		for {
			if _, err := os.Stat(marker); os.IsNotExist(err) {
				break
			}
			if time.Now().After(deadline) {
				t.Fatal("freeze request not processed")
			}
			time.Sleep(50 * time.Millisecond)
		}
		waitReplacement(previous)
		waitPing()
	}

}

func tailLog(b []byte) string {
	if len(b) > 6000 {
		b = b[len(b)-6000:]
	}
	return string(b)
}
