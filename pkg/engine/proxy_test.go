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
	"os"
	"path/filepath"
	"reflect"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/utils"
)

// --- collectGatewayProxyPublicIPs ---

func TestCollectGatewayProxyPublicIPs(t *testing.T) {
	cases := []struct {
		name string
		gw   *v1beta1.Gateway
		want []string
	}{
		{
			name: "nil gateway",
			gw:   nil,
			want: nil,
		},
		{
			name: "no active endpoints",
			gw:   &v1beta1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw"}},
			want: nil,
		},
		{
			name: "mixes Tunnel and Proxy types — only Proxy kept",
			gw: &v1beta1.Gateway{
				ObjectMeta: metav1.ObjectMeta{Name: "gw"},
				Status: v1beta1.GatewayStatus{
					ActiveEndpoints: []*v1beta1.Endpoint{
						{NodeName: "n1", Type: v1beta1.Tunnel, PublicIP: "1.1.1.1"},
						{NodeName: "n1", Type: v1beta1.Proxy, PublicIP: "2.2.2.2"},
					},
				},
			},
			want: []string{"2.2.2.2"},
		},
		{
			name: "empty PublicIP skipped",
			gw: &v1beta1.Gateway{
				Status: v1beta1.GatewayStatus{
					ActiveEndpoints: []*v1beta1.Endpoint{
						{NodeName: "n1", Type: v1beta1.Proxy, PublicIP: ""},
						{NodeName: "n2", Type: v1beta1.Proxy, PublicIP: "3.3.3.3"},
					},
				},
			},
			want: []string{"3.3.3.3"},
		},
		{
			name: "deduplicated and sorted",
			gw: &v1beta1.Gateway{
				Status: v1beta1.GatewayStatus{
					ActiveEndpoints: []*v1beta1.Endpoint{
						{NodeName: "n1", Type: v1beta1.Proxy, PublicIP: "9.9.9.9"},
						{NodeName: "n2", Type: v1beta1.Proxy, PublicIP: "1.1.1.1"},
						{NodeName: "n3", Type: v1beta1.Proxy, PublicIP: "9.9.9.9"},
					},
				},
			},
			want: []string{"1.1.1.1", "9.9.9.9"},
		},
		{
			name: "nil endpoint entry tolerated",
			gw: &v1beta1.Gateway{
				Status: v1beta1.GatewayStatus{
					ActiveEndpoints: []*v1beta1.Endpoint{
						nil,
						{NodeName: "n1", Type: v1beta1.Proxy, PublicIP: "1.1.1.1"},
					},
				},
			},
			want: []string{"1.1.1.1"},
		},
		{
			name: "non-local-node PublicIPs are included (this is the coverage gap fix)",
			gw: &v1beta1.Gateway{
				Status: v1beta1.GatewayStatus{
					ActiveEndpoints: []*v1beta1.Endpoint{
						{NodeName: "self", Type: v1beta1.Proxy, PublicIP: "1.1.1.1"},
						{NodeName: "peer", Type: v1beta1.Proxy, PublicIP: "2.2.2.2"},
					},
				},
			},
			want: []string{"1.1.1.1", "2.2.2.2"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := collectGatewayProxyPublicIPs(tc.gw)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("collectGatewayProxyPublicIPs got %v, want %v", got, tc.want)
			}
		})
	}
}

// --- proxyServerHandler RestartType: PublicIP set unchanged → no-op ---

// minimalProxyEngine builds a ProxyEngine wired enough for handler unit-tests.
// It pins ProxyServerCertDir to a tempdir so purgeServerCert is observable.
func minimalProxyEngine(t *testing.T, gw *v1beta1.Gateway, prevPublicIPs []string) (*ProxyEngine, string) {
	t.Helper()
	dir := t.TempDir()
	pe := &ProxyEngine{
		nodeName:        "node-1",
		localGateway:    gw,
		ctx:             context.Background(),
		proxyOption:     newProxyOption(),
		proxyCtx:        newProxyContext(context.Background()),
		serverPublicIPs: prevPublicIPs,
		config: &config.Config{
			Proxy: &config.ProxyConfig{ProxyServerCertDir: dir},
		},
	}
	return pe, dir
}

func writeServerCertFile(t *testing.T, dir, qualifier string) string {
	t.Helper()
	path := filepath.Join(dir, utils.RavenProxyServerName+"-"+qualifier+".pem")
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatalf("write cert file: %v", err)
	}
	return path
}

func TestProxyServerHandler_RestartType_SamePublicIPs_NoPurgeNoStop(t *testing.T) {
	gw := &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-cloud"},
		Status: v1beta1.GatewayStatus{
			ActiveEndpoints: []*v1beta1.Endpoint{
				{NodeName: "node-1", Type: v1beta1.Proxy, PublicIP: "1.1.1.1"},
			},
		},
	}
	pe, dir := minimalProxyEngine(t, gw, []string{"1.1.1.1"})

	// Pretend the proxy server is already running so JudgeAction → RestartType.
	pe.proxyOption.SetServerStatus(true)

	// Place a cert file; if no-restart logic is correct, it must remain.
	certFile := writeServerCertFile(t, dir, "current")

	if err := pe.proxyServerHandler(true); err != nil {
		t.Fatalf("proxyServerHandler returned error: %v", err)
	}

	// Same publicIP set → no-op: server status preserved, cert file untouched.
	if !pe.proxyOption.GetServerStatus() {
		t.Error("server status should remain true when publicIPs unchanged")
	}
	if _, err := os.Stat(certFile); err != nil {
		t.Errorf("cert file should not be removed when publicIPs unchanged: %v", err)
	}
}

// --- proxyServerHandler StopType: purges server cert ---

func TestProxyServerHandler_StopType_PurgesServerCert(t *testing.T) {
	pe, dir := minimalProxyEngine(t, nil, []string{"1.1.1.1"})

	// Pretend the proxy server is running and the desired enableServer is false
	// (e.g., node no longer participates) → JudgeAction returns StopType.
	pe.proxyOption.SetServerStatus(true)

	serverCert := writeServerCertFile(t, dir, "current")
	// Other component's cert in the same dir must be left intact.
	otherCert := filepath.Join(dir, utils.RavenProxyUserName+"-current.pem")
	if err := os.WriteFile(otherCert, []byte("dummy"), 0600); err != nil {
		t.Fatalf("write other cert: %v", err)
	}

	if err := pe.proxyServerHandler(false); err != nil {
		t.Fatalf("proxyServerHandler returned error: %v", err)
	}

	if pe.proxyOption.GetServerStatus() {
		t.Error("server status should be false after StopType")
	}
	if _, err := os.Stat(serverCert); !os.IsNotExist(err) {
		t.Errorf("server cert should be purged, got err=%v", err)
	}
	if _, err := os.Stat(otherCert); err != nil {
		t.Errorf("non-server cert should be left intact, got err=%v", err)
	}
	if pe.serverPublicIPs != nil {
		t.Errorf("serverPublicIPs should be cleared, got %v", pe.serverPublicIPs)
	}
}

// --- proxyServerHandler RestartType: PublicIP set changed → purges ---

// We can't drive the full restart through proxyServerHandler in a unit test
// (startProxyServer needs a fully-wired manager.Manager, etc.), so we assert
// the trigger boundary: when publicIPs differ, stop+purge happens before the
// start attempt. We accept that startProxyServer will fail in the test env;
// the relevant pre-start observable side-effects are what we assert.
func TestProxyServerHandler_RestartType_DifferentPublicIPs_StopsAndPurges(t *testing.T) {
	gw := &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "gw-cloud"},
		Status: v1beta1.GatewayStatus{
			ActiveEndpoints: []*v1beta1.Endpoint{
				// Gateway now reports a NEW PublicIP set.
				{NodeName: "peer", Type: v1beta1.Proxy, PublicIP: "2.2.2.2"},
			},
		},
	}
	pe, dir := minimalProxyEngine(t, gw, []string{"1.1.1.1"})
	pe.proxyOption.SetServerStatus(true)
	serverCert := writeServerCertFile(t, dir, "current")

	// Drive the handler. We expect it to attempt restart: stop, purge, then try
	// to start. start panics because config.Manager is nil in the unit-test
	// fixture; that's OK — we only need to verify the pre-start side-effects
	// (purge runs before the start attempt).
	func() {
		defer func() { _ = recover() }()
		_ = pe.proxyServerHandler(true)
	}()

	if _, err := os.Stat(serverCert); !os.IsNotExist(err) {
		t.Errorf("server cert should be purged on publicIP change, got err=%v", err)
	}
}
