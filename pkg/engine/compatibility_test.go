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
	"reflect"
	"testing"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/util/workqueue"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type lifecycleProbeVPN struct {
	mockVPNDriver
	lifecycleCalls int
}

func (d *lifecycleProbeVPN) SetLifecycle(context.Context, func()) { d.lifecycleCalls++ }

func TestDriverInitializationKeepsOriginalRollback(t *testing.T) {
	for _, stage := range []string{"success", "route", "vpn-create", "vpn-init"} {
		t.Run(stage, func(t *testing.T) {
			route := &mockRouteDriver{}
			vpn := &lifecycleProbeVPN{}
			name := fmt.Sprintf("%s-%p", t.Name(), vpn)
			routeCreates, vpnCreates := 0, 0
			routedriver.RegisterRouteDriver(name, func(*config.Config) (routedriver.Driver, error) {
				routeCreates++
				return route, nil
			})
			vpndriver.RegisterDriver(name, func(*config.Config) (vpndriver.Driver, error) {
				vpnCreates++
				if stage == "vpn-create" {
					return nil, errors.New("VPN creation failed")
				}
				return vpn, nil
			})
			if stage == "route" {
				route.initErr = errors.New("route init failed")
			}
			if stage == "vpn-init" {
				vpn.initErr = errors.New("VPN init failed")
			}
			te := &TunnelEngine{config: &config.Config{Tunnel: &config.TunnelConfig{VPNDriver: name, RouteDriver: name}}}
			for i := 0; i < 2; i++ {
				if err := te.InitDriver(); (err == nil) != (stage == "success") {
					t.Fatalf("stage %s: %v", stage, err)
				}
			}
			if routeCreates != 2 || (stage != "route" && vpnCreates != 2) {
				t.Fatal("initialization did not recreate drivers")
			}
			wantCleanup := 0
			if stage == "vpn-create" || stage == "vpn-init" {
				wantCleanup = 2
			}
			wantLifecycle := 0
			if stage == "success" || stage == "vpn-init" {
				wantLifecycle = 2
			}
			if route.cleanupCalled != wantCleanup || vpn.cleanupCalled != 0 || te.cleanupPending || vpn.lifecycleCalls != wantLifecycle {
				t.Fatal("optional lifecycle injection or original initialization rollback changed")
			}
		})
	}
}

type orderedCleanupVPN struct {
	mockVPNDriver
	calls *[]string
}

func (d *orderedCleanupVPN) Cleanup() error {
	*d.calls = append(*d.calls, "vpn")
	d.cleanupCalled++
	if d.cleanupCalled == 1 {
		return errors.New("transient VPN cleanup error")
	}
	return nil
}

type orderedCleanupRoute struct {
	mockRouteDriver
	calls *[]string
}

func (d *orderedCleanupRoute) Cleanup() error {
	*d.calls = append(*d.calls, "route")
	return nil
}

func TestLibreswanCleanupRetainsVPNFirstOrdering(t *testing.T) {
	te, _, _ := newTestTunnelEngine(nil)
	te.config.Tunnel.VPNDriver = "libreswan"
	te.driverInitialized = true
	var calls []string
	te.vpnDriver = &orderedCleanupVPN{calls: &calls}
	te.routeDriver = &orderedCleanupRoute{calls: &calls}
	if !te.CleanupDriver() {
		t.Fatal("cleanup did not recover from a transient error")
	}
	if !reflect.DeepEqual(calls, []string{"vpn", "vpn", "route"}) || !te.driverInitialized || te.cleanupPending {
		t.Fatalf("non-WireGuard cleanup semantics changed: %v", calls)
	}
}

func TestLibreswanShutdownKeepsExistingBehavior(t *testing.T) {
	te, vpn, route := newTestTunnelEngine(nil)
	te.config.Tunnel.VPNDriver = "libreswan"
	te.driverInitialized = true
	q := workqueue.NewTypedRateLimitingQueue[*v1beta1.Gateway](workqueue.DefaultTypedControllerRateLimiter[*v1beta1.Gateway]())
	defer q.ShutDown()
	e := &Engine{tunnel: te, option: NewEngineOption(), queue: q}
	e.Cleanup()
	e.Cleanup()
	if q.ShuttingDown() || vpn.cleanupCalled != 2 || route.cleanupCalled != 2 {
		t.Fatal("WireGuard shutdown handling affected Libreswan")
	}
}

func TestKernelWireGuardCleanupKeepsOriginalFailureHandling(t *testing.T) {
	te, vpn, route := newTestWireGuardTunnel(newTestGateway("gw", 0, 0))
	te.driverInitialized = true
	vpn.cleanupErr = errors.New("kernel cleanup failed")
	if err := te.Handler(context.Background()); err != nil {
		t.Fatalf("kernel cleanup no longer follows the original Handler behavior: %v", err)
	}
	if te.cleanupPending || !te.driverInitialized || route.cleanupCalled != 0 {
		t.Fatal("userspace pending state or changed cleanup ordering affected the kernel backend")
	}
}

func TestLibreswanSyncFailureKeepsStatusAndEventRetry(t *testing.T) {
	gw := newTestGateway("gw", 1, 0)
	scheme := runtime.NewScheme()
	if err := v1beta1.AddToScheme(scheme); err != nil {
		t.Fatal(err)
	}
	cl := fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()
	te, _, _ := newTestTunnelEngine(gw)
	te.config.Tunnel.VPNDriver = "libreswan"
	te.vpnDriver, te.ravenClient, te.driverInitialized = &unavailableVPN{}, cl, true
	q := workqueue.NewTypedRateLimitingQueue[*v1beta1.Gateway](workqueue.DefaultTypedControllerRateLimiter[*v1beta1.Gateway]())
	defer q.ShutDown()
	option := NewEngineOption()
	option.SetTunnelStatus(true)
	ctx := context.Background()
	proxy := &ProxyEngine{nodeName: "node-1", client: cl, ctx: ctx, option: option,
		proxyOption: newProxyOption(), proxyCtx: newProxyContext(ctx)}
	e := &Engine{context: ctx, nodeName: "node-1", client: cl, tunnel: te, proxy: proxy,
		option: option, queue: q}
	err := e.sync()
	if err == nil || !option.GetTunnelStatus() || q.Len() != 0 {
		t.Fatal("WireGuard backoff or readiness changed Libreswan sync")
	}
	e.handleEventErr(err, gw)
	if q.NumRequeues(gw) != 1 {
		t.Fatal("Libreswan event was redirected to WireGuard retry handling")
	}
}

type cancellationAwareClient struct {
	client.Client
}

func (c cancellationAwareClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return c.Client.List(ctx, list, opts...)
}

func TestTunnelAPICancellationIsWireGuardOnly(t *testing.T) {
	for _, driver := range []string{"libreswan", "wireguard"} {
		t.Run(driver, func(t *testing.T) {
			gw := newTestGateway("gw", 1, 0)
			scheme := runtime.NewScheme()
			if err := v1beta1.AddToScheme(scheme); err != nil {
				t.Fatal(err)
			}
			te, vpn, _ := newTestTunnelEngine(gw)
			te.config.Tunnel.VPNDriver = driver
			te.driverInitialized = true
			te.ravenClient = cancellationAwareClient{fake.NewClientBuilder().WithScheme(scheme).WithObjects(gw).Build()}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			err := te.Handler(ctx)
			if driver == "wireguard" {
				if !errors.Is(err, context.Canceled) || vpn.applyCalled != 0 {
					t.Fatalf("WireGuard ignored cancellation: %v", err)
				}
			} else if err != nil || vpn.applyCalled != 1 {
				t.Fatalf("Libreswan no longer uses its existing background API context: %v", err)
			}
		})
	}
}
