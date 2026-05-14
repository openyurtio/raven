package engine

import (
	"context"
	"fmt"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
)

// mockVPNDriver implements vpndriver.Driver
type mockVPNDriver struct {
	initCalled    int
	applyCalled   int
	cleanupCalled int
	initErr       error
	cleanupErr    error
}

func (m *mockVPNDriver) Init() error {
	m.initCalled++
	return m.initErr
}
func (m *mockVPNDriver) Apply(_ *types.Network, _ func(*types.Network) (int, error)) error {
	m.applyCalled++
	return nil
}
func (m *mockVPNDriver) MTU() (int, error) { return 1400, nil }
func (m *mockVPNDriver) Cleanup() error {
	m.cleanupCalled++
	return m.cleanupErr
}

// mockRouteDriver implements routedriver.Driver
type mockRouteDriver struct {
	initCalled    int
	applyCalled   int
	cleanupCalled int
	initErr       error
	cleanupErr    error
}

func (m *mockRouteDriver) Init() error {
	m.initCalled++
	return m.initErr
}
func (m *mockRouteDriver) Apply(_ *types.Network, _ func() (int, error)) error {
	m.applyCalled++
	return nil
}
func (m *mockRouteDriver) MTU(_ *types.Network) (int, error) { return 1400, nil }
func (m *mockRouteDriver) Cleanup() error {
	m.cleanupCalled++
	return m.cleanupErr
}

func newTestGateway(name string, tunnelReplicas, proxyReplicas int) *v1beta1.Gateway {
	return &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1beta1.GatewaySpec{
			TunnelConfig: v1beta1.TunnelConfiguration{Replicas: tunnelReplicas},
			ProxyConfig:  v1beta1.ProxyConfiguration{Replicas: proxyReplicas},
			ExposeType:   v1beta1.ExposeTypePublicIP,
		},
		Status: v1beta1.GatewayStatus{
			Nodes: []v1beta1.NodeInfo{
				{NodeName: "node-1", PrivateIP: "10.0.0.1", Subnets: []string{"10.244.0.0/24"}},
			},
			ActiveEndpoints: []*v1beta1.Endpoint{
				{NodeName: "node-1", Type: v1beta1.Tunnel, PublicIP: "1.2.3.4", Port: 4500},
				{NodeName: "node-1", Type: v1beta1.Proxy, PublicIP: "1.2.3.4", Port: 10262},
			},
		},
	}
}

// --- TunnelEngine.Status() tests ---

func TestTunnelStatus_NilGateway(t *testing.T) {
	te := &TunnelEngine{localGateway: nil}
	if te.Status() {
		t.Error("Status() should return false when localGateway is nil")
	}
}

func TestTunnelStatus_ReplicasZero(t *testing.T) {
	te := &TunnelEngine{localGateway: newTestGateway("gw", 0, 0)}
	if te.Status() {
		t.Error("Status() should return false when TunnelConfig.Replicas is 0")
	}
}

func TestTunnelStatus_ReplicasPositive(t *testing.T) {
	te := &TunnelEngine{localGateway: newTestGateway("gw", 1, 0)}
	if !te.Status() {
		t.Error("Status() should return true when TunnelConfig.Replicas > 0")
	}
}

// --- ProxyEngine.Status() tests ---

func TestProxyStatus_NilGateway(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	pe := &ProxyEngine{localGateway: nil, client: fakeClient}
	if pe.Status() {
		t.Error("Status() should return false when localGateway is nil and no centre gateway")
	}
}

func TestProxyStatus_ReplicasZero(t *testing.T) {
	pe := &ProxyEngine{localGateway: newTestGateway("gw", 0, 0)}
	if pe.Status() {
		t.Error("Status() should return false when ProxyConfig.Replicas is 0")
	}
}

func TestProxyStatus_ReplicasPositive(t *testing.T) {
	pe := &ProxyEngine{localGateway: newTestGateway("gw", 0, 1)}
	if !pe.Status() {
		t.Error("Status() should return true when ProxyConfig.Replicas > 0")
	}
}

// --- TunnelEngine.Handler() lazy init / cleanup tests ---

func newTestTunnelEngine(gw *v1beta1.Gateway) (*TunnelEngine, *mockVPNDriver, *mockRouteDriver) {
	vpn := &mockVPNDriver{}
	route := &mockRouteDriver{}
	return &TunnelEngine{
		nodeName:     "node-1",
		localGateway: gw,
		vpnDriver:    vpn,
		routeDriver:  route,
		config: &config.Config{
			Tunnel: &config.TunnelConfig{
				VPNDriver:   "mock",
				RouteDriver: "mock",
			},
		},
	}, vpn, route
}

func TestHandler_NoGateway_NoInit(t *testing.T) {
	te, vpn, route := newTestTunnelEngine(nil)
	err := te.Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}
	if te.driverInitialized {
		t.Error("driverInitialized should be false")
	}
	if vpn.initCalled > 0 || route.initCalled > 0 {
		t.Error("drivers should not be initialized when no gateway")
	}
}

func TestHandler_ReplicasZero_NoInit(t *testing.T) {
	te, vpn, route := newTestTunnelEngine(newTestGateway("gw", 0, 0))
	err := te.Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}
	if te.driverInitialized {
		t.Error("driverInitialized should be false when Replicas=0")
	}
	if vpn.initCalled > 0 || route.initCalled > 0 {
		t.Error("drivers should not be initialized when Replicas=0")
	}
}

func TestHandler_ReplicasZero_TriggersCleanup(t *testing.T) {
	te, vpn, route := newTestTunnelEngine(newTestGateway("gw", 0, 0))
	te.driverInitialized = true // pretend it was initialized

	err := te.Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}
	if te.driverInitialized {
		t.Error("driverInitialized should be false after cleanup")
	}
	if vpn.cleanupCalled != 1 {
		t.Errorf("vpnDriver.Cleanup() should be called once, got %d", vpn.cleanupCalled)
	}
	if route.cleanupCalled != 1 {
		t.Errorf("routeDriver.Cleanup() should be called once, got %d", route.cleanupCalled)
	}
}

func TestHandler_CleanupFails_KeepsInitialized(t *testing.T) {
	te, vpn, _ := newTestTunnelEngine(newTestGateway("gw", 0, 0))
	te.driverInitialized = true
	vpn.cleanupErr = fmt.Errorf("cleanup failed")

	err := te.Handler()
	if err != nil {
		t.Fatalf("Handler() returned error: %v", err)
	}
	if !te.driverInitialized {
		t.Error("driverInitialized should remain true when cleanup fails")
	}
}

// --- findLocalGateway tests ---

func TestFindLocalGateway_ListFails_KeepsPreviousState(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)
	// Use a client that has no objects — but we'll test with a pre-set gateway
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	previousGw := newTestGateway("gw-cloud", 1, 1)
	tunnel := &TunnelEngine{localGateway: previousGw}
	proxy := &ProxyEngine{localGateway: previousGw}

	e := &Engine{
		nodeName: "node-1",
		tunnel:   tunnel,
		proxy:    proxy,
		client:   fakeClient,
	}

	// List succeeds but finds no matching node → should clear
	e.findLocalGateway()
	if e.tunnel.localGateway != nil {
		t.Error("localGateway should be nil when node not found in any gateway")
	}
}

func TestFindLocalGateway_MatchesNode(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	gw := newTestGateway("gw-cloud", 1, 1)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()

	tunnel := &TunnelEngine{}
	proxy := &ProxyEngine{}

	e := &Engine{
		nodeName: "node-1",
		tunnel:   tunnel,
		proxy:    proxy,
		client:   fakeClient,
	}

	e.findLocalGateway()
	if e.tunnel.localGateway == nil {
		t.Fatal("tunnel.localGateway should not be nil")
	}
	if e.tunnel.localGateway.Name != "gw-cloud" {
		t.Errorf("expected gateway name gw-cloud, got %s", e.tunnel.localGateway.Name)
	}
	if e.proxy.localGateway == nil {
		t.Fatal("proxy.localGateway should not be nil")
	}
}

func TestFindLocalGateway_NodeNotInGateway(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	gw := newTestGateway("gw-cloud", 1, 1)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()

	tunnel := &TunnelEngine{}
	proxy := &ProxyEngine{}

	e := &Engine{
		nodeName: "node-not-exist",
		tunnel:   tunnel,
		proxy:    proxy,
		client:   fakeClient,
	}

	e.findLocalGateway()
	if e.tunnel.localGateway != nil {
		t.Error("tunnel.localGateway should be nil when node not in gateway")
	}
	if e.proxy.localGateway != nil {
		t.Error("proxy.localGateway should be nil when node not in gateway")
	}
}

// --- getDestAddressForProxyClient tests ---

// gwBuilder mints a Gateway pre-shaped to mirror the gw-cloud topology in production:
// `Replicas` proxy ActiveEndpoints sharing one publicIP on incrementing ports, and the
// matching node entries in Status.Nodes. Tests then choose which one is the "self" node.
func gwBuilder(name, publicIP string, basePort int, nodeNames []string) *v1beta1.Gateway {
	gw := &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: v1beta1.GatewaySpec{
			ExposeType:  v1beta1.ExposeTypePublicIP,
			ProxyConfig: v1beta1.ProxyConfiguration{Replicas: len(nodeNames)},
		},
	}
	for i, n := range nodeNames {
		gw.Status.Nodes = append(gw.Status.Nodes, v1beta1.NodeInfo{NodeName: n})
		gw.Status.ActiveEndpoints = append(gw.Status.ActiveEndpoints, &v1beta1.Endpoint{
			NodeName: n, Type: v1beta1.Proxy, PublicIP: publicIP, Port: basePort + i,
		})
	}
	return gw
}

// TestGetDestAddressForProxyClient covers the regression where a proxy client on a
// gateway-member node started dialing its own gateway's public VIP because the
// localGateway==nil filter short-circuited.
func TestGetDestAddressForProxyClient(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	cloud := gwBuilder("gw-cloud", "1.2.3.4", 10280,
		[]string{"node-cloud-a", "node-cloud-b"})
	edge := gwBuilder("gw-edge", "5.6.7.8", 10280,
		[]string{"node-edge-a"})
	// non-exposed gateway must always be skipped regardless of node membership
	silent := gwBuilder("gw-silent", "9.9.9.9", 10280, []string{"node-silent"})
	silent.Spec.ExposeType = ""

	cases := []struct {
		name         string
		objects      []*v1beta1.Gateway
		localGateway *v1beta1.Gateway
		nodeName     string
		want         []string
	}{
		{
			name:         "self gateway resolved → filtered out by name",
			objects:      []*v1beta1.Gateway{cloud, edge},
			localGateway: cloud,
			nodeName:     "node-cloud-a",
			want:         []string{"5.6.7.8:10280"},
		},
		{
			name:         "localGateway nil but Status.Nodes has self → filtered out by node",
			objects:      []*v1beta1.Gateway{cloud, edge},
			localGateway: nil,
			nodeName:     "node-cloud-a",
			want:         []string{"5.6.7.8:10280"},
		},
		{
			name:         "localGateway nil and node not in any gateway → all kept",
			objects:      []*v1beta1.Gateway{cloud, edge},
			localGateway: nil,
			nodeName:     "node-floating",
			want:         []string{"1.2.3.4:10280", "1.2.3.4:10281", "5.6.7.8:10280"},
		},
		{
			name:         "non-exposed gateway is always skipped",
			objects:      []*v1beta1.Gateway{cloud, silent},
			localGateway: nil,
			nodeName:     "node-silent",
			want:         []string{"1.2.3.4:10280", "1.2.3.4:10281"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(scheme)
			for _, gw := range tc.objects {
				builder = builder.WithObjects(gw)
			}
			c := builder.Build()

			got := getDestAddressForProxyClient(c, tc.localGateway, tc.nodeName)

			if len(got) != len(tc.want) {
				t.Fatalf("dstAddr length mismatch: got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("dstAddr[%d]: got %s, want %s", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestProxyClientHandler_RestartType_EmptyDstStopsClient pins the fix for the leaked
// stale client: when a node was previously dialing its own gateway during the
// localGateway==nil window, the next sync (now with localGateway resolved) sees an
// empty destination set and MUST stop the existing client instead of returning early.
func TestProxyClientHandler_RestartType_EmptyDstStopsClient(t *testing.T) {
	scheme := runtime.NewScheme()
	_ = v1beta1.AddToScheme(scheme)

	cloud := gwBuilder("gw-cloud", "1.2.3.4", 10280,
		[]string{"node-cloud-a", "node-cloud-b"})
	c := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cloud).Build()

	pe := &ProxyEngine{
		nodeName:              "node-cloud-a",
		localGateway:          cloud,
		client:                c,
		ctx:                   context.Background(),
		clientRemoteEndpoints: []string{"1.2.3.4:10280", "1.2.3.4:10281"}, // leaked from earlier nil-window
		proxyOption:           newProxyOption(),
		proxyCtx:              newProxyContext(context.Background()),
	}
	// Simulate: a client was started during the bootstrap window.
	pe.proxyOption.SetClientStatus(true)

	if err := pe.proxyClientHandler(true); err != nil {
		t.Fatalf("proxyClientHandler returned error: %v", err)
	}

	if pe.proxyOption.GetClientStatus() {
		t.Error("client status should be false after empty dstAddr in RestartType")
	}
	if pe.clientRemoteEndpoints != nil {
		t.Errorf("clientRemoteEndpoints should be cleared, got %v", pe.clientRemoteEndpoints)
	}
}

// --- CleanupDriver returns bool tests ---

func TestCleanupDriver_Success(t *testing.T) {
	vpn := &mockVPNDriver{}
	route := &mockRouteDriver{}
	te := &TunnelEngine{vpnDriver: vpn, routeDriver: route}

	result := te.CleanupDriver()
	if !result {
		t.Error("CleanupDriver should return true on success")
	}
	if vpn.cleanupCalled != 1 {
		t.Errorf("vpnDriver.Cleanup() called %d times, expected 1", vpn.cleanupCalled)
	}
	if route.cleanupCalled != 1 {
		t.Errorf("routeDriver.Cleanup() called %d times, expected 1", route.cleanupCalled)
	}
}

func TestCleanupDriver_Failure(t *testing.T) {
	vpn := &mockVPNDriver{cleanupErr: fmt.Errorf("fail")}
	route := &mockRouteDriver{}
	te := &TunnelEngine{vpnDriver: vpn, routeDriver: route}

	result := te.CleanupDriver()
	if result {
		t.Error("CleanupDriver should return false on failure")
	}
}

// --- Engine.Cleanup() tests ---

func TestEngineCleanup_DriverNotInitialized(t *testing.T) {
	vpn := &mockVPNDriver{}
	route := &mockRouteDriver{}
	te := &TunnelEngine{vpnDriver: vpn, routeDriver: route, driverInitialized: false}

	e := &Engine{
		tunnel: te,
		option: NewEngineOption(),
		proxy: &ProxyEngine{
			proxyOption: newProxyOption(),
			proxyCtx:    newProxyContext(context.Background()),
		},
	}

	e.Cleanup()
	if vpn.cleanupCalled > 0 {
		t.Error("should not call CleanupDriver when driver not initialized")
	}
}

func TestEngineCleanup_DriverInitialized(t *testing.T) {
	vpn := &mockVPNDriver{}
	route := &mockRouteDriver{}
	te := &TunnelEngine{vpnDriver: vpn, routeDriver: route, driverInitialized: true}

	e := &Engine{
		tunnel: te,
		option: NewEngineOption(),
		proxy: &ProxyEngine{
			proxyOption: newProxyOption(),
			proxyCtx:    newProxyContext(context.Background()),
		},
	}

	e.Cleanup()
	if vpn.cleanupCalled != 1 {
		t.Errorf("vpnDriver.Cleanup() called %d times, expected 1", vpn.cleanupCalled)
	}
}
