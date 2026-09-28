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

package engine

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func newTestWireGuardTunnel(gw *v1beta1.Gateway) (*TunnelEngine, *mockVPNDriver, *mockRouteDriver) {
	te, vpn, route := newTestTunnelEngine(gw)
	te.config.Tunnel.VPNDriver = "wireguard"
	te.ctx = context.Background()
	return te, vpn, route
}

type lifecycleVPNDriver struct {
	mockVPNDriver
	ctx            context.Context
	onChange       func()
	lifecycleCalls int
}

func (d *lifecycleVPNDriver) SetLifecycle(ctx context.Context, onChange func()) {
	d.ctx, d.onChange = ctx, onChange
	d.lifecycleCalls++
}

func (d *lifecycleVPNDriver) Init() error {
	if d.ctx == nil || d.onChange == nil {
		return errors.New("lifecycle was not supplied before initialization")
	}
	return d.mockVPNDriver.Init()
}

func TestLifecycleInjectedIntoNewDriversOnRetryAndReenable(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw := newTestGateway("gw", 1, 0)
	e := recoveryEngine(t, gw)
	e.context = ctx
	te := e.tunnel
	te.driverInitialized = false
	te.ctx, te.onChange = ctx, e.requestTunnelRecovery
	var routes []*mockRouteDriver
	var vpns []*lifecycleVPNDriver
	name := fmt.Sprintf("%s-%p", t.Name(), te)
	te.config.Tunnel.RouteDriver, te.config.Tunnel.VPNDriver = name, name
	routedriver.RegisterRouteDriver(name, func(*config.Config) (routedriver.Driver, error) {
		d := &mockRouteDriver{}
		routes = append(routes, d)
		return d, nil
	})
	vpndriver.RegisterDriver(name, func(*config.Config) (vpndriver.Driver, error) {
		if routes[len(routes)-1].initCalled != 1 {
			t.Fatal("VPN created before route initialization")
		}
		d := &lifecycleVPNDriver{}
		if len(vpns) == 0 {
			d.initErr = errors.New("initialization failed")
		}
		vpns = append(vpns, d)
		return d, nil
	})
	if err := te.InitDriver(); err == nil {
		t.Fatal("initialization failure lost")
	}
	if routes[0].cleanupCalled != 1 || vpns[0].cleanupCalled != 0 || te.cleanupPending {
		t.Fatal("initialization failure did not use the original route-only rollback")
	}
	if err := te.Handler(ctx); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || len(vpns) != 2 || te.vpnDriver == vpns[0] || te.routeDriver == routes[0] {
		t.Fatal("initialization retry reused old driver instances")
	}
	gw.Spec.TunnelConfig.Replicas = 0
	if err := te.Handler(ctx); err != nil {
		t.Fatal(err)
	}
	if te.driverInitialized || routes[1].cleanupCalled != 1 || vpns[1].cleanupCalled != 1 {
		t.Fatal("L3 disable did not clean both drivers")
	}
	gw.Spec.TunnelConfig.Replicas = 1
	if err := te.Handler(ctx); err != nil {
		t.Fatal(err)
	}
	if len(routes) != 3 || len(vpns) != 3 || te.routeDriver == routes[1] || te.vpnDriver == vpns[1] {
		t.Fatal("L3 re-enable reused driver instances")
	}
	for _, vpn := range vpns {
		if vpn.lifecycleCalls != 1 || vpn.initCalled != 1 || vpn.ctx != ctx {
			t.Fatal("lifecycle was not injected once before Init for each instance")
		}
	}
	vpns[2].onChange()
	if e.queue.Len() != 1 {
		t.Fatal("driver notification did not enqueue recovery")
	}
	request, quit := e.queue.Get()
	e.queue.Done(request)
	if quit || request != e.recoveryRequest {
		t.Fatal("driver notification did not use the existing recovery queue")
	}
	cancel()
	if !errors.Is(vpns[2].ctx.Err(), context.Canceled) {
		t.Fatal("runtime cancellation did not reach the replacement driver")
	}
	vpns[2].onChange()
	if e.queue.Len() != 0 {
		t.Fatal("driver notification was queued after cancellation")
	}
}

func TestUserspacePendingCleanupBlocksNewInstances(t *testing.T) {
	for _, stage := range []string{"vpn", "route"} {
		t.Run(stage, func(t *testing.T) {
			gw := newTestGateway("gw", 0, 0)
			e := recoveryEngine(t, gw)
			te := e.tunnel
			oldVPN := &runtimeVPN{}
			oldRoute := te.routeDriver.(*mockRouteDriver)
			te.vpnDriver = oldVPN
			if stage == "vpn" {
				oldVPN.cleanupErr = errors.New("child still stopping")
			} else {
				oldRoute.cleanupErr = errors.New("route cleanup failed")
			}
			name := fmt.Sprintf("%s-%p", t.Name(), te)
			te.config.Tunnel.RouteDriver, te.config.Tunnel.VPNDriver = name, name
			newRoute, newVPN := &mockRouteDriver{}, &mockVPNDriver{}
			creates := 0
			routedriver.RegisterRouteDriver(name, func(*config.Config) (routedriver.Driver, error) {
				creates++
				return newRoute, nil
			})
			vpndriver.RegisterDriver(name, func(*config.Config) (vpndriver.Driver, error) {
				creates++
				return newVPN, nil
			})
			if err := te.Handler(e.context); err == nil || !te.cleanupPending {
				t.Fatal("userspace cleanup failure was not retained for retry")
			}
			if stage == "vpn" && oldRoute.cleanupCalled != 0 {
				t.Fatal("route cleanup ran before VPN cleanup succeeded")
			}
			if err := te.InitDriver(); err == nil || creates != 0 {
				t.Fatal("InitDriver replaced instances while cleanup was pending")
			}
			gw.Spec.TunnelConfig.Replicas = 1
			te.driverInitialized = false // The pending guard must suffice on its own.
			if err := te.Handler(e.context); err == nil || creates != 0 || te.vpnDriver != oldVPN || te.routeDriver != oldRoute {
				t.Fatal("L3 re-enable replaced drivers before old resources were cleaned")
			}
			oldVPN.cleanupErr, oldRoute.cleanupErr = nil, nil
			if err := te.Handler(e.context); err != nil {
				t.Fatal(err)
			}
			if te.cleanupPending || !te.driverInitialized || creates != 2 || te.vpnDriver != newVPN || te.routeDriver != newRoute {
				t.Fatal("completed cleanup did not allow fresh driver initialization")
			}
			if newVPN.applyCalled != 1 || newRoute.applyCalled != 1 {
				t.Fatal("new drivers did not receive the current network configuration")
			}
		})
	}
}

type unavailableVPN struct{ mockVPNDriver }

func (*unavailableVPN) Apply(*types.Network, func(*types.Network) (int, error)) error {
	return errors.New("userspace process unavailable")
}

type runtimeVPN struct {
	unavailableVPN
	delay time.Duration
}

func (v *runtimeVPN) NextReconcile() time.Duration { return v.delay }
func (v *runtimeVPN) UsesUserspace() bool          { return true }

type cleanupBudgetVPN struct {
	mockVPNDriver
	userspace    bool
	budget       time.Duration
	contextCalls int
}

func (v *cleanupBudgetVPN) UsesUserspace() bool { return v.userspace }
func (v *cleanupBudgetVPN) CleanupContext(ctx context.Context) error {
	v.contextCalls++
	if deadline, ok := ctx.Deadline(); ok {
		v.budget = time.Until(deadline)
	}
	return nil
}

func TestCleanupBudgetIsPassedOnlyToUserspace(t *testing.T) {
	for _, userspace := range []bool{false, true} {
		te, _, route := newTestWireGuardTunnel(nil)
		vpn := &cleanupBudgetVPN{userspace: userspace}
		te.vpnDriver = vpn
		if !te.CleanupDriver() || route.cleanupCalled != 1 {
			t.Fatal("cleanup ordering failed")
		}
		if userspace {
			if vpn.contextCalls != 1 || vpn.cleanupCalled != 0 || vpn.budget <= 0 || vpn.budget > 5*time.Second {
				t.Fatal("userspace did not receive the outer polling deadline")
			}
		} else if vpn.contextCalls != 0 || vpn.cleanupCalled != 1 {
			t.Fatal("kernel cleanup path changed")
		}
	}
}

func TestConfigurationEventsKeepOriginalLimiter(t *testing.T) {
	for _, name := range []string{"libreswan", "wireguard"} {
		t.Run(name, func(t *testing.T) {
			gw := newTestGateway("gw", 1, 0)
			e := recoveryEngine(t, gw)
			e.tunnel.config.Tunnel.VPNDriver = name
			e.tunnel.vpnDriver = &unavailableVPN{}
			e.queue.Add(gw)
			if !e.processNextWorkItem() || e.queue.NumRequeues(gw) != 1 || e.queue.NumRequeues(e.recoveryRequest) != 0 {
				t.Fatal("driver name changed configuration-event retries")
			}
		})
	}
}

func TestRuntimeNotificationUsesSameWorkerAndDriverDeadline(t *testing.T) {
	gw := newTestGateway("gw", 1, 0)
	e := recoveryEngine(t, gw)
	vpn := &runtimeVPN{delay: 50 * time.Millisecond}
	e.tunnel.vpnDriver = vpn
	// Runtime recovery does not invoke Proxy's configuration path.
	e.proxy = &ProxyEngine{}
	e.requestTunnelRecovery()
	if !e.processNextWorkItem() || e.queue.NumRequeues(e.recoveryRequest) != 0 {
		t.Fatal("runtime fault used the configuration-event limiter")
	}
	if e.queue.Len() != 0 {
		t.Fatal("runtime retry did not respect the driver's delay")
	}
	deadline := time.Now().Add(time.Second)
	for e.queue.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("runtime retry was not queued")
		}
		time.Sleep(time.Millisecond)
	}
	// Turning off L3 is handled by that worker even with recovery pending.
	gw.Spec.TunnelConfig.Replicas = 0
	if err := e.client.Update(e.context, gw); err != nil {
		t.Fatal(err)
	}
	vpn.delay = 0
	if !e.processNextWorkItem() || vpn.cleanupCalled == 0 || e.tunnel.driverInitialized {
		t.Fatal("runtime event did not reconcile the latest L3 configuration")
	}
}

func recoveryEngine(t *testing.T, gw *v1beta1.Gateway) *Engine {
	t.Helper()
	scheme := runtime.NewScheme()
	if err := v1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()
	te, _, _ := newTestWireGuardTunnel(gw)
	te.ravenClient, te.driverInitialized = cl, true
	ctx := context.Background()
	q := workqueue.NewTypedRateLimitingQueue[*v1beta1.Gateway](workqueue.DefaultTypedControllerRateLimiter[*v1beta1.Gateway]())
	t.Cleanup(q.ShutDown)
	option := NewEngineOption()
	proxy := &ProxyEngine{nodeName: "node-1", client: cl, ctx: ctx, option: option,
		proxyOption: newProxyOption(), proxyCtx: newProxyContext(ctx)}
	return &Engine{context: ctx, nodeName: "node-1", client: cl, tunnel: te, proxy: proxy,
		option: option, queue: q, recoveryRequest: &v1beta1.Gateway{}}
}

type blockingRuntimeVPN struct {
	mockVPNDriver
	entered    chan struct{}
	release    chan struct{}
	active     atomic.Bool
	overlapped atomic.Bool
}

func (v *blockingRuntimeVPN) Apply(*types.Network, func(*types.Network) (int, error)) error {
	v.active.Store(true)
	close(v.entered)
	<-v.release
	v.active.Store(false)
	return context.Canceled
}

func (v *blockingRuntimeVPN) Cleanup() error {
	if v.active.Load() {
		v.overlapped.Store(true)
	}
	return v.mockVPNDriver.Cleanup()
}

func TestRuntimeCleanupWaitsForReconciliation(t *testing.T) {
	e := recoveryEngine(t, newTestGateway("gw", 1, 0))
	vpn := &blockingRuntimeVPN{entered: make(chan struct{}), release: make(chan struct{})}
	e.tunnel.vpnDriver = vpn
	e.cancelRuntime = func() { close(vpn.release) }
	e.requestTunnelRecovery()
	done := make(chan struct{})
	go func() { defer close(done); e.processNextWorkItem() }()
	select {
	case <-vpn.entered:
	case <-time.After(time.Second):
		t.Fatal("worker did not start reconciliation")
	}
	e.Cleanup()
	<-done
	if vpn.overlapped.Load() || vpn.cleanupCalled != 1 {
		t.Fatal("cleanup overlapped the worker or skipped the driver")
	}
}

func TestRuntimeRouteCleanupFailureUsesConfigurationRetry(t *testing.T) {
	e := recoveryEngine(t, newTestGateway("gw", 0, 0))
	e.tunnel.vpnDriver = &runtimeVPN{}
	route := e.tunnel.routeDriver.(*mockRouteDriver)
	route.cleanupErr = errors.New("route cleanup failed")
	e.requestTunnelRecovery()
	if !e.processNextWorkItem() || !e.tunnel.cleanupPending || e.queue.NumRequeues(e.recoveryRequest) != 1 {
		t.Fatal("route cleanup failure was lost after userspace recovery ended")
	}
	route.cleanupErr = nil
	e.requestTunnelRecovery()
	if !e.processNextWorkItem() || e.tunnel.cleanupPending || e.tunnel.driverInitialized {
		t.Fatal("configuration retry did not finish route cleanup")
	}
}

func TestVPNFailureAndDisableKeepProxyRunning(t *testing.T) {
	gw := newTestGateway("gw", 1, 1)
	scheme := runtime.NewScheme()
	if err := v1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()
	te, _, route := newTestWireGuardTunnel(gw)
	vpn := &unavailableVPN{}
	te.vpnDriver, te.ravenClient, te.driverInitialized = vpn, cl, true
	te.config.Tunnel.VPNDriver = "wireguard"
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	q := workqueue.NewTypedRateLimitingQueue[*v1beta1.Gateway](workqueue.DefaultTypedControllerRateLimiter[*v1beta1.Gateway]())
	defer q.ShutDown()
	option := NewEngineOption()
	p := &ProxyEngine{nodeName: "node-1", client: cl, ctx: ctx, option: option,
		proxyOption: newProxyOption(), proxyCtx: newProxyContext(ctx), serverPublicIPs: collectGatewayProxyPublicIPs(gw)}
	p.proxyOption.SetServerStatus(true)
	serverContext := p.proxyCtx.GetServerContext()
	e := &Engine{context: ctx, nodeName: "node-1", client: cl, tunnel: te, proxy: p,
		option: option, queue: q, recoveryRequest: &v1beta1.Gateway{}}
	if err := e.sync(); err == nil {
		t.Fatal("VPN failure lost")
	}
	if !p.proxyOption.GetServerStatus() || serverContext.Err() != nil || route.cleanupCalled != 0 {
		t.Fatal("VPN failure stopped Proxy or destroyed VXLAN")
	}
	gw.Spec.TunnelConfig.Replicas = 0
	if err := cl.Update(ctx, gw); err != nil {
		t.Fatal(err)
	}
	if err := e.sync(); err != nil {
		t.Fatal(err)
	}
	if vpn.cleanupCalled == 0 || route.cleanupCalled == 0 || te.driverInitialized {
		t.Fatal("disable failed to clean L3 or cancel recovery")
	}
	if !p.proxyOption.GetServerStatus() || serverContext.Err() != nil {
		t.Fatal("L3 disable stopped Proxy")
	}
}

// These interfaces must be exercised through Handler, not just called directly
// on a driver: readiness also depends on VXLAN and discovery succeeding.
type reportingVPN struct {
	mockVPNDriver
	healthErr, applyErr error
	healthCalls         int
	reports             []bool
}

func (v *reportingVPN) CheckHealth() error         { v.healthCalls++; return v.healthErr }
func (v *reportingVPN) SetNetworkReady(ready bool) { v.reports = append(v.reports, ready) }
func (v *reportingVPN) Apply(*types.Network, func(*types.Network) (int, error)) error {
	v.applyCalled++
	return v.applyErr
}

type failingRoute struct {
	mockRouteDriver
	applyErr error
}

func (r *failingRoute) Apply(*types.Network, func() (int, error)) error {
	r.applyCalled++
	return r.applyErr
}

func TestHandlerHealthAndNetworkReadiness(t *testing.T) {
	failure := errors.New("injected failure")
	for _, stage := range []string{"success", "health", "discovery", "vpn", "route", "disabled"} {
		t.Run(stage, func(t *testing.T) {
			e := recoveryEngine(t, newTestGateway("gw", 1, 0))
			vpn, route := &reportingVPN{}, &failingRoute{}
			e.tunnel.vpnDriver, e.tunnel.routeDriver = vpn, route
			wantErr := failure
			switch stage {
			case "success":
				wantErr = nil
			case "health":
				vpn.healthErr = failure
				// Health failure must short-circuit even before discovery.
				e.tunnel.ravenClient = nil
			case "discovery":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				e.tunnel.ctx = ctx
				e.tunnel.ravenClient = cancellationAwareClient{e.tunnel.ravenClient}
				wantErr = context.Canceled
			case "vpn":
				vpn.applyErr = failure
			case "route":
				route.applyErr = failure
			case "disabled":
				e.tunnel.localGateway.Spec.TunnelConfig.Replicas = 0
				wantErr = nil
			}
			err := e.tunnel.Handler(e.context)
			if !errors.Is(err, wantErr) {
				t.Fatalf("Handler error = %v, want %v", err, wantErr)
			}
			if len(vpn.reports) != 1 || vpn.reports[0] != (stage == "success") {
				t.Fatalf("readiness reports = %v", vpn.reports)
			}
			wantHealth, wantVPN, wantRoute := 1, 0, 0
			switch stage {
			case "disabled":
				wantHealth = 0
			case "vpn":
				wantVPN = 1
			case "route", "success":
				wantVPN, wantRoute = 1, 1
			}
			if vpn.healthCalls != wantHealth || vpn.applyCalled != wantVPN || route.applyCalled != wantRoute {
				t.Fatalf("health/vpn/route calls = %d/%d/%d", vpn.healthCalls, vpn.applyCalled, route.applyCalled)
			}
		})
	}
}

func TestRuntimeSchedulingStopsWithEngine(t *testing.T) {
	e := recoveryEngine(t, newTestGateway("gw", 1, 0))
	e.tunnel.vpnDriver = &runtimeVPN{delay: time.Millisecond}
	ctx, cancel := context.WithCancel(e.context)
	e.context = ctx
	cancel()
	e.scheduleDriver()
	e.requestTunnelRecovery()
	if e.queue.Len() != 0 {
		t.Fatal("scheduled work after cancellation")
	}
	e.context, e.queue = context.Background(), nil
	e.scheduleDriver() // An uninitialized queue cannot accept runtime work.
}
