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
	"errors"
	"fmt"
	"net"
	"syscall"
	"testing"
	"time"

	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type fakeControl struct {
	dev      wgtypes.Device
	err      error
	closed   int
	closeErr error
	configs  []wgtypes.Config
}

func (c *fakeControl) Device(string) (*wgtypes.Device, error) { return &c.dev, c.err }
func (c *fakeControl) ConfigureDevice(_ string, cfg wgtypes.Config) error {
	if c.err != nil {
		return c.err
	}
	c.configs = append(c.configs, cfg)
	if cfg.PrivateKey != nil {
		c.dev.PrivateKey = *cfg.PrivateKey
	}
	if cfg.ListenPort != nil {
		c.dev.ListenPort = *cfg.ListenPort
	}
	return nil
}
func (c *fakeControl) Close() error { c.closed++; return c.closeErr }

type fakeProcess struct {
	running       bool
	starts, stops int
	start         func() error
	stopErr       error
	onStop        func()
}

func (p *fakeProcess) Start() error {
	p.starts++
	if p.start != nil {
		if err := p.start(); err != nil {
			return err
		}
	}
	p.running = true
	return nil
}
func (p *fakeProcess) Running() bool { return p.running }
func (p *fakeProcess) Stop() error {
	p.stops++
	if p.stopErr != nil {
		return p.stopErr
	}
	p.running = false
	if p.onStop != nil {
		p.onStop()
	}
	return nil
}

type deviceFixture struct {
	d                      *deviceManager
	link                   netlink.Link
	addErr                 error
	getErr                 error
	adds, deletes, clients int
	control                *fakeControl
	process                *fakeProcess
}

func newDeviceFixture() *deviceFixture {
	f := &deviceFixture{control: &fakeControl{}, process: &fakeProcess{}}
	f.process.start = func() error {
		f.link = &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: DeviceName, Index: 10, MTU: 1420}, Mode: netlink.TUNTAP_MODE_TUN}
		f.control.dev.Type = wgtypes.Userspace
		return nil
	}
	f.d = &deviceManager{
		process: f.process, startTimeout: 10 * time.Millisecond,
		newClient: func() (controlClient, error) {
			f.clients++
			if f.link == nil {
				return nil, errors.New("client constructed before device")
			}
			return f.control, nil
		},
		links: linkOperations{
			get: func(string) (netlink.Link, error) {
				if f.getErr != nil {
					return nil, f.getErr
				}
				if f.link == nil {
					return nil, netlink.LinkNotFoundError{}
				}
				return f.link, nil
			},
			add: func(l netlink.Link) error {
				f.adds++
				if f.addErr != nil {
					return f.addErr
				}
				f.link = l
				f.link.Attrs().Index = 10
				f.control.dev.Type = wgtypes.LinuxKernel
				return nil
			},
			del:    func(netlink.Link) error { f.deletes++; f.link = nil; return nil },
			setMTU: func(l netlink.Link, mtu int) error { l.Attrs().MTU = mtu; return nil },
			setUp:  func(netlink.Link) error { return nil },
		},
	}
	return f
}

func TestDeviceBackendSelection(t *testing.T) {
	for _, tt := range []struct {
		name    string
		err     error
		backend string
	}{
		{"kernel", nil, backendKernel},
		{"unsupported", syscall.EOPNOTSUPP, backendUserspace},
		{"wrapped unsupported", fmt.Errorf("netlink: %w", syscall.ENOTSUP), backendUserspace},
		{"permission", syscall.EPERM, ""},
		{"access", syscall.EACCES, ""},
		{"invalid configuration", syscall.EINVAL, ""},
		{"name conflict", syscall.EEXIST, ""},
		{"no device is ambiguous", syscall.ENODEV, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newDeviceFixture()
			f.addErr = tt.err
			_, err := f.d.ensure(context.Background(), 1340, wgtypes.Key{1}, 4500)
			if tt.backend == "" {
				if !errors.Is(err, tt.err) || f.process.starts != 0 {
					t.Fatalf("err=%v starts=%d", err, f.process.starts)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if f.d.selected != tt.backend || f.clients != 1 || f.adds != 1 {
				t.Fatalf("selection=%s clients=%d adds=%d", f.d.selected, f.clients, f.adds)
			}
			if f.link.Attrs().MTU != 1340 || f.control.dev.PrivateKey != (wgtypes.Key{1}) {
				t.Fatal("device configuration not applied")
			}
			if tt.backend == backendKernel && f.process.starts != 0 {
				t.Fatal("kernel path launched userspace")
			}
		})
	}
}

func TestDeviceConfigurationFailureDoesNotFallback(t *testing.T) {
	f := newDeviceFixture()
	f.control.err = syscall.EPERM
	_, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500)
	if !errors.Is(err, syscall.EPERM) || f.d.selected != backendKernel || f.process.starts != 0 {
		t.Fatalf("err=%v backend=%s", err, f.d.selected)
	}
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 1 || f.control.closed != 1 {
		t.Fatal("partial initialization not cleaned")
	}
}

func TestDevicePreservesBackendAndReconfiguresInPlace(t *testing.T) {
	f := newDeviceFixture()
	f.addErr = syscall.EOPNOTSUPP
	for _, key := range []wgtypes.Key{{1}, {2}} {
		if _, err := f.d.ensure(context.Background(), 1400, key, 4500); err != nil {
			t.Fatal(err)
		}
	}
	if f.process.starts != 1 || f.deletes != 0 || f.control.dev.PrivateKey != (wgtypes.Key{2}) {
		t.Fatal("TUN was recreated or key update lost")
	}
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.ensure(context.Background(), 1380, wgtypes.Key{2}, 4501); err != nil {
		t.Fatal(err)
	}
	if f.adds != 1 || f.process.starts != 2 || f.control.dev.ListenPort != 4501 {
		t.Fatal("backend choice or port was not preserved")
	}
}

func TestDeviceRejectsForeignLink(t *testing.T) {
	f := newDeviceFixture()
	f.link = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}}
	if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err == nil {
		t.Fatal("accepted foreign device")
	}
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 0 || f.process.starts != 0 {
		t.Fatal("modified foreign device")
	}
}

func TestUserspaceStartupFailures(t *testing.T) {
	for _, mode := range []string{"missing binary", "uapi timeout", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			f := newDeviceFixture()
			f.addErr = syscall.EOPNOTSUPP
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch mode {
			case "missing binary":
				f.process.start = func() error { return syscall.ENOENT }
			case "uapi timeout":
				f.control.err = syscall.ENOENT
			case "cancelled":
				f.control.err = syscall.ENOENT
				cancel()
			}
			if _, err := f.d.ensure(ctx, 1400, wgtypes.Key{1}, 4500); err == nil {
				t.Fatal("startup unexpectedly succeeded")
			}
			if err := f.d.close(); err != nil {
				t.Fatal(err)
			}
			if f.process.running || f.link != nil {
				t.Fatal("startup resources leaked")
			}
		})
	}
}

func TestCleanupContinuesAfterTUNDisappears(t *testing.T) {
	f := newDeviceFixture()
	f.addErr = syscall.EOPNOTSUPP
	if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err != nil {
		t.Fatal(err)
	}
	f.link, f.process.running = nil, false
	routes, nat := 0, 0
	w := &wireguard{device: f.d, withdrawRoutes: func() error { routes++; return nil }, cleanupNAT: func() error { nat++; return nil }}
	for i := 0; i < 2; i++ {
		if err := w.Cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	if routes != 2 || nat != 2 || f.control.closed != 1 {
		t.Fatal("cleanup skipped resources after device vanished")
	}
}

func TestCleanupAggregatesErrors(t *testing.T) {
	f := newDeviceFixture()
	f.process.stopErr = errors.New("stop failed")
	routeErr, natErr := errors.New("route failed"), errors.New("NAT failed")
	w := &wireguard{device: f.d, withdrawRoutes: func() error { return routeErr }, cleanupNAT: func() error { return natErr }}
	err := w.Cleanup()
	if !errors.Is(err, routeErr) || !errors.Is(err, natErr) || !errors.Is(err, f.process.stopErr) {
		t.Fatalf("lost cleanup errors: %v", err)
	}
}

func TestUnchangedDeviceDoesNotRebindUDP(t *testing.T) {
	f := newDeviceFixture()
	f.addErr = syscall.EOPNOTSUPP
	for i := 0; i < 3; i++ {
		if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.control.configs) != 1 || f.process.starts != 1 {
		t.Fatal("health checks rebound UDP or restarted the process")
	}
}

func TestChangedPeerConfiguration(t *testing.T) {
	key, psk := wgtypes.Key{1}, wgtypes.Key{2}
	ka := KeepAliveInterval
	ips := parseSubnets([]string{"10.1.0.0/16", "10.2.0.0/16"})
	endpoint := &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4500}
	cfg := wgtypes.PeerConfig{PublicKey: key, PresharedKey: &psk, Endpoint: endpoint,
		PersistentKeepaliveInterval: &ka, ReplaceAllowedIPs: true, AllowedIPs: ips}
	peer := wgtypes.Peer{PublicKey: key, PresharedKey: psk, Endpoint: endpoint,
		PersistentKeepaliveInterval: ka, AllowedIPs: []net.IPNet{ips[1], ips[0]}}
	control := &fakeControl{}
	w := &wireguard{wgClient: control}
	if err := w.configureChangedPeers([]wgtypes.PeerConfig{cfg}, map[string]wgtypes.Peer{key.String(): peer}); err != nil {
		t.Fatal(err)
	}
	if len(control.configs) != 0 {
		t.Fatal("unchanged peer was reconfigured")
	}
	cfg.AllowedIPs = parseSubnets([]string{"10.3.0.0/16"})
	if err := w.configureChangedPeers([]wgtypes.PeerConfig{cfg}, map[string]wgtypes.Peer{key.String(): peer}); err != nil {
		t.Fatal(err)
	}
	if len(control.configs) != 1 || control.configs[0].ReplacePeers {
		t.Fatal("topology change lost or other peers replaced")
	}
	if err := w.configureChangedPeers([]wgtypes.PeerConfig{cfg}, nil); err != nil {
		t.Fatal(err)
	}
	if len(control.configs) != 2 {
		t.Fatal("missing peers were not restored")
	}
}

func TestExitInvalidatesReadinessAndWithdrawsVPN(t *testing.T) {
	f := newDeviceFixture()
	f.addErr = syscall.EOPNOTSUPP
	key := wgtypes.Key{1}
	if _, err := f.d.ensure(context.Background(), 1400, key, 4500); err != nil {
		t.Fatal(err)
	}
	routes, notifications := 0, 0
	w := &wireguard{device: f.d, privateKey: key, configured: true,
		withdrawRoutes: func() error { routes++; return nil }}
	w.SetLifecycle(context.Background(), func() { notifications++ })
	w.SetNetworkReady(true)
	if !w.ready {
		t.Fatal("ready device not reported")
	}
	w.processExited(errors.New("killed"))
	if w.ready || notifications != 1 {
		t.Fatal("process exit not reported")
	}
	if err := w.CheckHealth(); err == nil {
		t.Fatal("fault not returned for backoff")
	}
	if routes != 1 || f.process.running || w.privateKey != key {
		t.Fatal("VPN not withdrawn or key lost")
	}
	if _, err := f.d.ensure(context.Background(), 1400, w.privateKey, 4500); err != nil {
		t.Fatal(err)
	}
	w.configured = true // The caller has reapplied peers and routes.
	w.SetNetworkReady(true)
	if f.adds != 1 || f.process.starts != 2 || !w.ready {
		t.Fatal("userspace recovery failed")
	}
}

type stalledControl struct {
	fakeControl
	stopped <-chan struct{}
}

func TestDriverLifecycleCancellationReachesUserspaceControl(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	f := newDeviceFixture()
	f.addErr = syscall.EOPNOTSUPP
	w := &wireguard{device: f.d, privateKey: wgtypes.Key{1}, listenPort: 4500}
	w.SetLifecycle(ctx, nil)
	if err := w.ensureWgLink(&types.Network{}, func(*types.Network) (int, error) { return 1400, nil }); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := f.d.close(); err != nil {
			t.Error(err)
		}
	}()
	cancel()
	if _, err := w.wgClient.Device(DeviceName); !errors.Is(err, context.Canceled) {
		t.Fatalf("userspace control ignored engine cancellation: %v", err)
	}
	if err := w.ensureWgLink(&types.Network{}, func(*types.Network) (int, error) { return 1400, nil }); !errors.Is(err, context.Canceled) {
		t.Fatalf("device initialization ignored engine cancellation: %v", err)
	}
	if f.process.starts != 1 {
		t.Fatal("cancelled driver started a replacement process")
	}
}

func (c *stalledControl) Device(string) (*wgtypes.Device, error) {
	<-c.stopped
	return nil, errors.New("closed UAPI")
}

func TestUserspaceControlDeadlineReapsProcess(t *testing.T) {
	stopped := make(chan struct{})
	p := &fakeProcess{running: true, onStop: func() { close(stopped) }}
	raw := &stalledControl{stopped: stopped}
	c := &userspaceControl{controlClient: raw, ctx: context.Background(), timeout: 10 * time.Millisecond, process: p}
	if _, err := c.Device(DeviceName); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	if p.running || p.stops != 1 {
		t.Fatal("stalled child not reaped")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.closed != 1 {
		t.Fatal("control client not closed")
	}
}

func TestOrdinaryNodesDoNotCreateDevice(t *testing.T) {
	f := newDeviceFixture()
	w := &wireguard{device: f.d, nodeName: "ordinary", ctx: context.Background()}
	for _, nw := range []*types.Network{nil, {LocalEndpoint: &types.Endpoint{NodeName: "gateway"},
		RemoteEndpoints: map[types.GatewayName]*types.Endpoint{"other": {NodeName: "other"}}}} {
		if err := w.Apply(nw, nil); err != nil {
			t.Fatal(err)
		}
	}
	if f.adds != 0 || f.process.starts != 0 {
		t.Fatal("ordinary node created VPN device")
	}
}

func TestStuckUAPIDoesNotAccumulateOperations(t *testing.T) {
	release := make(chan struct{})
	p := &fakeProcess{running: true}
	raw := &stalledControl{stopped: release}
	c := &userspaceControl{controlClient: raw, ctx: context.Background(), timeout: 10 * time.Millisecond, process: p}
	if _, err := c.Device(DeviceName); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline: %v", err)
	}
	pending := c.pending
	for i := 0; i < 20; i++ {
		if _, err := c.Device(DeviceName); err == nil {
			t.Fatal("timed-out client reused")
		}
		if c.pending != pending {
			t.Fatal("started another operation behind stuck call")
		}
	}
	if err := c.Close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close deadline: %v", err)
	}
	if raw.closed != 0 || p.stops != 1 {
		t.Fatal("closed active transport or repeatedly stopped child")
	}
	close(release)
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if raw.closed != 1 {
		t.Fatal("eventual transport cleanup lost")
	}
}

type stuckCloseControl struct {
	fakeControl
	release <-chan struct{}
}

func (c *stuckCloseControl) Close() error { <-c.release; return c.fakeControl.Close() }

func TestCloseIsBoundedAndRetriedWithoutReplacement(t *testing.T) {
	release := make(chan struct{})
	raw := &stuckCloseControl{release: release}
	c := &userspaceControl{controlClient: raw, ctx: context.Background(), timeout: 10 * time.Millisecond, process: &fakeProcess{}}
	f := newDeviceFixture()
	f.d.client = c
	if err := f.d.close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close deadline: %v", err)
	}
	done := c.closing
	if f.d.client != c {
		t.Fatal("lost outstanding client")
	}
	if err := f.d.close(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if c.closing != done {
		t.Fatal("started duplicate Close")
	}
	close(release)
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if f.d.client != nil || raw.closed != 1 {
		t.Fatal("client not closed exactly once")
	}
}

type budgetProcess struct {
	fakeProcess
	deadline time.Time
}

func (p *budgetProcess) StopContext(ctx context.Context) error {
	p.deadline, _ = ctx.Deadline()
	return p.Stop()
}

func TestCleanupSharesBudgetWithPendingUAPI(t *testing.T) {
	f := newDeviceFixture()
	f.d.selected = backendUserspace
	p := &budgetProcess{}
	f.d.process = p
	pending := make(chan struct{})
	raw := &fakeControl{}
	c := &userspaceControl{controlClient: raw, pending: pending, timeout: time.Second, process: p}
	f.d.client = c
	natCalls := 0
	w := &wireguard{device: f.d, cleanupNAT: func() error { natCalls++; return nil }}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Millisecond)
	defer cancel()
	deadline, _ := ctx.Deadline()
	start := time.Now()
	if err := w.CleanupContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shared deadline lost: %v", err)
	}
	if time.Since(start) > 500*time.Millisecond || !p.deadline.Equal(deadline) {
		t.Fatal("process and client did not share the caller's deadline")
	}
	if f.d.client != c || raw.closed != 0 || natCalls != 0 {
		t.Fatal("pending operation lost or cleanup continued past its budget")
	}
	close(pending)
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if f.d.client != nil || raw.closed != 1 || natCalls != 1 {
		t.Fatal("subsequent cleanup did not complete retained resources")
	}
}

func TestPeerEndpointMatchesIPv4MappedAddress(t *testing.T) {
	peer := wgtypes.Peer{Endpoint: &net.UDPAddr{IP: net.ParseIP("::ffff:192.0.2.1"), Port: 4500}}
	cfg := wgtypes.PeerConfig{Endpoint: &net.UDPAddr{IP: net.IP{192, 0, 2, 1}, Port: 4500}}
	if !peerConfigMatches(peer, cfg) {
		t.Fatal("equivalent IPv4 endpoints treated as changed")
	}
}

func TestPeerUpdatesKeepKernelBehavior(t *testing.T) {
	for _, backend := range []string{backendKernel, backendUserspace} {
		for _, relay := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/relay=%v", backend, relay), func(t *testing.T) {
				control := &fakeControl{}
				w := &wireguard{wgClient: control, device: &deviceManager{selected: backend},
					listenPort: 4500, keepaliveInterval: 20, psk: wgtypes.Key{2}}
				key := wgtypes.Key{1}
				conn := &vpndriver.Connection{RemoteEndpoint: &types.Endpoint{
					PublicIP: "192.0.2.1", PublicPort: 4500, Subnets: []string{"10.1.0.0/16"},
					Config: map[string]string{PublicKey: key.String()},
				}}
				desired := map[string]*vpndriver.Connection{key.String(): conn}
				apply := func(current map[string]wgtypes.Peer) error {
					if relay {
						return w.ensureRelayPeers(desired, nil, current)
					}
					return w.ensureEdgePeers(desired, current)
				}
				if err := apply(nil); err != nil {
					t.Fatal(err)
				}
				cfg := control.configs[0]
				if cfg.ReplacePeers != (backend == backendKernel && !relay) {
					t.Fatal("kernel peer replacement behavior changed")
				}
				peer := cfg.Peers[0]
				wantKeepalive := time.Duration(20)
				if relay {
					wantKeepalive = 5 * time.Second
					if backend == backendUserspace {
						wantKeepalive = 6 * time.Second
					}
				}
				if *peer.PersistentKeepaliveInterval != wantKeepalive {
					t.Fatal("keepalive policy changed")
				}
				current := map[string]wgtypes.Peer{key.String(): {
					PublicKey: key, PresharedKey: w.psk, Endpoint: peer.Endpoint,
					AllowedIPs: peer.AllowedIPs, PersistentKeepaliveInterval: wantKeepalive,
				}}
				if err := apply(current); err != nil {
					t.Fatal(err)
				}
				wantCalls := 2
				if backend == backendUserspace {
					wantCalls = 1
				}
				if len(control.configs) != wantCalls {
					t.Fatal("incremental peer updates were not confined to userspace")
				}
			})
		}
	}
}

func TestChangedPeerFieldsAreApplied(t *testing.T) {
	for _, field := range []string{"psk", "endpoint", "missing endpoint", "keepalive", "allowed IP contents"} {
		t.Run(field, func(t *testing.T) {
			key, psk, ka := wgtypes.Key{1}, wgtypes.Key{2}, 6*time.Second
			cfg := wgtypes.PeerConfig{PublicKey: key, PresharedKey: &psk,
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: 4500},
				PersistentKeepaliveInterval: &ka, ReplaceAllowedIPs: true,
				AllowedIPs: parseSubnets([]string{"10.1.0.0/16"})}
			peer := wgtypes.Peer{PublicKey: key, PresharedKey: psk, Endpoint: cfg.Endpoint,
				PersistentKeepaliveInterval: ka, AllowedIPs: cfg.AllowedIPs}
			switch field {
			case "psk":
				peer.PresharedKey = wgtypes.Key{3}
			case "endpoint":
				peer.Endpoint = &net.UDPAddr{IP: net.ParseIP("192.0.2.2"), Port: 4501}
			case "missing endpoint":
				peer.Endpoint = nil
			case "keepalive":
				peer.PersistentKeepaliveInterval = time.Second
			case "allowed IP contents":
				peer.AllowedIPs = parseSubnets([]string{"10.2.0.0/16"})
			}
			control := &fakeControl{}
			w := &wireguard{wgClient: control}
			if err := w.configureChangedPeers([]wgtypes.PeerConfig{cfg}, map[string]wgtypes.Peer{key.String(): peer}); err != nil {
				t.Fatal(err)
			}
			if len(control.configs) != 1 || control.configs[0].ReplacePeers || len(control.configs[0].Peers) != 1 {
				t.Fatal("changed peer was skipped or unrelated peers were replaced")
			}
			got := control.configs[0].Peers[0]
			if got.PublicKey != key || *got.PresharedKey != psk || got.Endpoint.String() != cfg.Endpoint.String() ||
				*got.PersistentKeepaliveInterval != ka || !got.ReplaceAllowedIPs || got.AllowedIPs[0].String() != cfg.AllowedIPs[0].String() {
				t.Fatal("desired peer configuration was not preserved")
			}
		})
	}
}

func TestKernelDeviceAdoptionAndRecreation(t *testing.T) {
	f := newDeviceFixture()
	f.link = &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: DeviceName, Index: 10}, LinkType: wgLinkType}
	f.control.dev.Type = wgtypes.LinuxKernel
	ensure := func() error { _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); return err }
	if err := ensure(); err != nil {
		t.Fatal(err)
	}
	if f.adds != 0 || !f.d.owned {
		t.Fatal("existing kernel device was not adopted")
	}
	f.link = nil
	f.addErr = syscall.EOPNOTSUPP
	if err := ensure(); !errors.Is(err, syscall.EOPNOTSUPP) {
		t.Fatalf("recreate error = %v", err)
	}
	if f.process.starts != 0 || f.d.selected != backendKernel {
		t.Fatal("kernel recreation changed backend")
	}
	f.addErr = nil
	if err := ensure(); err != nil {
		t.Fatal(err)
	}
	if f.clients != 2 || f.control.closed != 1 || f.process.starts != 0 || f.link.Attrs().MTU != 1400 {
		t.Fatal("kernel recreation did not replace client and restore configuration")
	}
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if f.d.owned || f.link != nil {
		t.Fatal("adopted/recreated link leaked")
	}
}

func TestUserspaceRestartWaitsForCleanup(t *testing.T) {
	for _, stage := range []string{"process", "client", "occupied link", "lookup"} {
		t.Run(stage, func(t *testing.T) {
			f := newDeviceFixture()
			f.d.selected, f.d.client = backendUserspace, f.control
			failure := errors.New("old resource unavailable")
			switch stage {
			case "process":
				f.process.stopErr = failure
			case "client":
				f.control.closeErr = failure
			case "occupied link":
				f.link = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}}
			case "lookup":
				f.getErr = failure
			}
			if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err == nil {
				t.Fatal("restart unexpectedly succeeded")
			}
			if f.process.starts != 0 || f.deletes != 0 {
				t.Fatal("started replacement or deleted occupied device")
			}
			if (stage == "process" || stage == "client") && f.d.client != f.control {
				t.Fatal("lost unclosed client")
			}
			f.process.stopErr, f.control.closeErr, f.link, f.getErr = nil, nil, nil, nil
			if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err != nil {
				t.Fatal(err)
			}
			if f.process.starts != 1 {
				t.Fatal("retry failed to start exactly one replacement")
			}
			if err := f.d.close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestDeviceConfigurationFailuresKeepOwnership(t *testing.T) {
	for _, stage := range []string{"client", "type", "configure", "mtu", "up", "early exit"} {
		t.Run(stage, func(t *testing.T) {
			f := newDeviceFixture()
			f.addErr = syscall.EOPNOTSUPP
			failure := errors.New("injected configuration failure")
			switch stage {
			case "client":
				f.d.newClient = func() (controlClient, error) { return nil, failure }
			case "type":
				start := f.process.start
				f.process.start = func() error { err := start(); f.control.dev.Type = wgtypes.LinuxKernel; return err }
			case "configure":
				f.d.newClient = func() (controlClient, error) {
					return &rejectingConfigureControl{fakeControl: f.control, err: failure}, nil
				}
			case "mtu":
				f.d.links.setMTU = func(netlink.Link, int) error { return failure }
			case "up":
				f.d.links.setUp = func(netlink.Link) error { return failure }
			case "early exit":
				f.d.newClient = func() (controlClient, error) {
					f.process.running = false
					f.control.err = syscall.ENOENT
					return f.control, nil
				}
			}
			if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err == nil {
				t.Fatal("configuration failure hidden")
			}
			if !f.d.owned || f.process.starts != 1 || f.d.selected != backendUserspace {
				t.Fatal("partial resources lost or backend changed")
			}
			if err := f.d.close(); err != nil {
				t.Fatal(err)
			}
			if f.process.running || f.link != nil || f.d.owned {
				t.Fatal("partial startup leaked resources")
			}
		})
	}
}

type rejectingConfigureControl struct {
	*fakeControl
	err error
}

func (c *rejectingConfigureControl) ConfigureDevice(string, wgtypes.Config) error { return c.err }

func TestDeviceCleanupProtectsForeignLinkAndRetriesDelete(t *testing.T) {
	f := newDeviceFixture()
	if _, err := f.d.ensure(context.Background(), 1400, wgtypes.Key{1}, 4500); err != nil {
		t.Fatal(err)
	}
	original := f.link
	f.link = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}}
	if err := f.d.close(); err == nil || f.deletes != 0 || !f.d.owned {
		t.Fatal("foreign link deleted or ownership lost")
	}
	f.link = original
	del := f.d.links.del
	f.d.links.del = func(netlink.Link) error { return syscall.EPERM }
	if err := f.d.close(); !errors.Is(err, syscall.EPERM) || !f.d.owned {
		t.Fatalf("delete failure not retained: %v", err)
	}
	f.d.links.del = del
	if err := f.d.close(); err != nil {
		t.Fatal(err)
	}
	if f.d.owned || f.link != nil || f.control.closed != 1 {
		t.Fatal("retry did not finish cleanup exactly once")
	}
}
