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
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Requires the same isolated, privileged Linux environment as the network
// integration suite, with both kernel WireGuard and wireguard-go available.
func TestWireGuardRegressionIntegration(t *testing.T) {
	if os.Getenv("RAVEN_WG_REGRESSION_INTEGRATION") != "1" {
		t.Skip("requires isolated privileged Linux")
	}
	if err := os.MkdirAll("/var/run/wireguard", 0755); err != nil {
		t.Fatal(err)
	}
	t.Run("learned-NAT-endpoint", testHealthReconcilePreservesNATTraffic)
	t.Run("UAPI-configuration-rejection", testRealUAPIRejectionPreservesHealthyProcess)
	t.Run("restart-kernel-cleanup", testRestartCleanupRemovesExistingKernelDevice)
}

func testRealUAPIRejectionPreservesHealthyProcess(t *testing.T) {
	driver, err := New(&config.Config{NodeName: "local", Manager: integrationManager{}, Tunnel: &config.TunnelConfig{VPNPort: "4500"}})
	if err != nil {
		t.Fatal(err)
	}
	w := driver.(*wireguard)
	if err = w.Init(); err != nil {
		t.Fatal(err)
	}
	w.device.selected = backendUserspace
	w.applyRoutes = func(*types.Network) error { return nil }
	w.applyNAT = func(*types.Network) error { return nil }
	w.withdrawRoutes = func() error { return nil }
	w.cleanupNAT = func() error { return nil }
	t.Cleanup(func() {
		if err := w.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	peerKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	nw := &types.Network{
		LocalEndpoint:   &types.Endpoint{NodeName: "local", Config: map[string]string{PublicKey: w.privateKey.PublicKey().String()}},
		RemoteEndpoints: map[types.GatewayName]*types.Endpoint{"good": {NodeName: "good", PublicIP: "198.51.100.20", Subnets: []string{"10.200.1.0/24"}, Config: map[string]string{PublicKey: peerKey.PublicKey().String()}}},
	}
	mtu := func(*types.Network) (int, error) { return 1400, nil }
	if err = w.Apply(nw, mtu); err != nil {
		t.Fatal(err)
	}
	if !w.device.process.Running() {
		t.Fatal("initial userspace process not running")
	}
	pid := w.device.process.(*subprocess).cmd.Process.Pid
	// Force a real userspace protocol rejection after a valid peer is installed.
	w.listenPort = 70000
	err = w.Apply(nw, mtu)
	if !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("real UAPI rejection not recognized: %v", err)
	}
	t.Logf("real backend rejection: %v", err)
	t.Logf("process running after rejection=%v; recovery pending=%v", w.device.process.Running(), w.recovery.err != nil)
	if !w.device.process.Running() || w.recovery.err != nil {
		t.Fatal("configuration rejection stopped the healthy process or scheduled recovery")
	}
	dev, err := w.wgClient.Device(DeviceName)
	if err != nil {
		t.Fatal(err)
	}
	if dev.ListenPort != 4500 || len(dev.Peers) != 1 || dev.Peers[0].PublicKey != peerKey.PublicKey() {
		t.Fatal("rejection lost the existing listener or peer")
	}
	w.listenPort = 4501
	if err = w.Apply(nw, mtu); err != nil {
		t.Fatal(err)
	}
	dev, err = w.wgClient.Device(DeviceName)
	if err != nil {
		t.Fatal(err)
	}
	if dev.ListenPort != 4501 || len(dev.Peers) != 1 || w.device.process.(*subprocess).cmd.Process.Pid != pid {
		t.Fatal("valid retry failed or replaced the healthy process")
	}
}

func testRestartCleanupRemovesExistingKernelDevice(t *testing.T) {
	link := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}, LinkType: wgLinkType}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if l, e := netlink.LinkByName(DeviceName); e == nil {
			_ = netlink.LinkDel(l)
		}
	})
	control, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := control.Close(); err != nil {
			t.Errorf("close WireGuard client: %v", err)
		}
	})
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	port := 4500
	if err = control.ConfigureDevice(DeviceName, wgtypes.Config{PrivateKey: &key, ListenPort: &port}); err != nil {
		t.Fatal(err)
	}
	fresh := &wireguard{device: newDeviceManager(nil), ctx: context.Background()}
	if err = fresh.Apply(nil, nil); err != nil {
		t.Fatal(err)
	}
	_, err = control.Device(DeviceName)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("cleanup left the previous kernel device: %v", err)
	}
}

type natPeerConfig struct{ PrivateKey, RemoteKey wgtypes.Key }

func TestWireGuardNATPeer(t *testing.T) {
	path := os.Getenv("RAVEN_WG_NAT_PEER")
	if path == "" {
		t.Skip("helper")
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg natPeerConfig
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	l := &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: "wg-edge"}, LinkType: wgLinkType}
	if err = netlink.LinkAdd(l); err != nil {
		t.Fatal(err)
	}
	c, err := wgctrl.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Errorf("close WireGuard client: %v", err)
		}
	})
	port := 4500
	_, subnet, _ := net.ParseCIDR("10.200.0.1/32")
	if err = c.ConfigureDevice("wg-edge", wgtypes.Config{PrivateKey: &cfg.PrivateKey, ListenPort: &port, Peers: []wgtypes.PeerConfig{{PublicKey: cfg.RemoteKey, Endpoint: &net.UDPAddr{IP: net.ParseIP("198.18.0.1"), Port: 4500}, AllowedIPs: []net.IPNet{*subnet}}}}); err != nil {
		t.Fatal(err)
	}
}

func testHealthReconcilePreservesNATTraffic(t *testing.T) {
	run := func(args ...string) {
		t.Helper()
		if out, e := exec.Command(args[0], args[1:]...).CombinedOutput(); e != nil {
			t.Fatalf("%v: %v: %s", args, e, out)
		}
	}
	const ns = "review-edge"
	run("ip", "netns", "add", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	run("ip", "link", "add", "review-cloud", "type", "veth", "peer", "name", "eth0", "netns", ns)
	t.Cleanup(func() { _ = exec.Command("ip", "link", "del", "review-cloud").Run() })
	run("ip", "addr", "add", "198.18.0.1/24", "dev", "review-cloud")
	run("ip", "link", "set", "review-cloud", "up")
	run("ip", "-n", ns, "addr", "add", "198.18.0.2/24", "dev", "eth0")
	run("ip", "-n", ns, "link", "set", "eth0", "up")
	run("ip", "-n", ns, "link", "set", "lo", "up")
	run("ip", "netns", "exec", ns, "iptables", "-t", "nat", "-A", "POSTROUTING", "-o", "eth0", "-p", "udp", "--sport", "4500", "-j", "SNAT", "--to-source", "198.18.0.2:62000")
	run("ip", "netns", "exec", ns, "iptables", "-A", "INPUT", "-i", "eth0", "-p", "udp", "--dport", "4500", "-m", "conntrack", "--ctstate", "NEW", "-j", "DROP")
	cloudKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	edgeKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	d := newDeviceManager(nil)
	d.selected = backendUserspace
	t.Cleanup(func() {
		if e := d.close(); e != nil {
			t.Error(e)
		}
	})
	if _, e := d.ensure(context.Background(), 1400, cloudKey, 4500); e != nil {
		t.Fatal(e)
	}
	run("ip", "addr", "add", "10.200.0.1/32", "dev", DeviceName)
	run("ip", "route", "add", "10.200.0.2/32", "dev", DeviceName)
	_, allowed, _ := net.ParseCIDR("10.200.0.2/32")
	desired := wgtypes.PeerConfig{PublicKey: edgeKey.PublicKey(), Endpoint: &net.UDPAddr{IP: net.ParseIP("198.18.0.2"), Port: 4500}, ReplaceAllowedIPs: true, AllowedIPs: []net.IPNet{*allowed}}
	w := &wireguard{device: d, wgClient: d.client}
	if e := w.configureChangedPeers([]wgtypes.PeerConfig{desired}, nil); e != nil {
		t.Fatal(e)
	}
	b, err := json.Marshal(natPeerConfig{PrivateKey: edgeKey, RemoteKey: cloudKey.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "edge.json")
	if e := os.WriteFile(path, b, 0600); e != nil {
		t.Fatal(e)
	}
	helper := exec.Command("ip", "netns", "exec", ns, os.Args[0], "-test.run=^TestWireGuardNATPeer$")
	helper.Env = append(os.Environ(), "RAVEN_WG_NAT_PEER="+path)
	if out, e := helper.CombinedOutput(); e != nil {
		t.Fatalf("kernel helper: %v %s", e, out)
	}
	run("ip", "-n", ns, "addr", "add", "10.200.0.2/32", "dev", "wg-edge")
	run("ip", "-n", ns, "link", "set", "wg-edge", "up")
	run("ip", "-n", ns, "route", "add", "10.200.0.1/32", "dev", "wg-edge")
	edgePing := func() error {
		return exec.Command("ip", "netns", "exec", ns, "ping", "-I", "10.200.0.2", "-c", "1", "-W", "1", "10.200.0.1").Run()
	}
	deadline := time.Now().Add(8 * time.Second)
	for edgePing() != nil {
		if time.Now().After(deadline) {
			t.Fatal("initial NAT tunnel did not work")
		}
	}
	run("ping", "-I", "10.200.0.1", "-c", "1", "-W", "1", "10.200.0.2")
	dev, e := d.client.Device(DeviceName)
	if e != nil {
		t.Fatal(e)
	}
	if len(dev.Peers) != 1 || dev.Peers[0].Endpoint.Port != 62000 {
		t.Fatalf("NAT mapping was not learned: %+v", dev.Peers)
	}
	t.Logf("before reconcile: learned endpoint=%v; bidirectional ping passed", dev.Peers[0].Endpoint)
	if e = w.configureChangedPeers([]wgtypes.PeerConfig{desired}, map[string]wgtypes.Peer{edgeKey.PublicKey().String(): dev.Peers[0]}); e != nil {
		t.Fatal(e)
	}
	dev, e = d.client.Device(DeviceName)
	if e != nil {
		t.Fatal(e)
	}
	t.Logf("after unchanged-topology reconcile: endpoint=%v", dev.Peers[0].Endpoint)
	out, pingErr := exec.Command("ping", "-I", "10.200.0.1", "-c", "1", "-W", "1", "10.200.0.2").CombinedOutput()
	if pingErr != nil {
		t.Errorf("unchanged health reconciliation interrupted working NAT traffic: %v: %s", pingErr, out)
	}
	if e = edgePing(); e != nil {
		t.Errorf("edge packet did not recover NAT mapping: %v", e)
	}
	run("ping", "-I", "10.200.0.1", "-c", "1", "-W", "1", "10.200.0.2")
	// A subnet change must also leave the learned endpoint intact.
	_, extra, _ := net.ParseCIDR("10.200.99.0/24")
	desired.AllowedIPs = append(desired.AllowedIPs, *extra)
	dev, e = d.client.Device(DeviceName)
	if e != nil {
		t.Fatal(e)
	}
	if e = w.configureChangedPeers([]wgtypes.PeerConfig{desired}, map[string]wgtypes.Peer{edgeKey.PublicKey().String(): dev.Peers[0]}); e != nil {
		t.Fatal(e)
	}
	dev, e = d.client.Device(DeviceName)
	if e != nil {
		t.Fatal(e)
	}
	if dev.Peers[0].Endpoint.Port != 62000 || len(dev.Peers[0].AllowedIPs) != 2 {
		t.Fatalf("subnet update changed learned endpoint or lost subnet: %+v", dev.Peers[0])
	}
	run("ping", "-I", "10.200.0.1", "-c", "1", "-W", "1", "10.200.0.2")
	t.Log("NAT traffic preserved through unchanged reconciliation and a subnet update")
}
