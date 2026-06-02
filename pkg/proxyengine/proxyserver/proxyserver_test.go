/*
Copyright 2023 The OpenYurt Authors.

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

package proxyserver

import (
	"net"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/openyurtio/api/raven/v1beta1"
)

// containsIP checks whether the given list contains an IP equal to want.
func containsIP(list []net.IP, want string) bool {
	w := net.ParseIP(want)
	if w == nil {
		return false
	}
	for _, ip := range list {
		if ip != nil && ip.Equal(w) {
			return true
		}
	}
	return false
}

// containsDNS checks whether the given list contains an exact DNS name match.
func containsDNS(list []string, want string) bool {
	for _, d := range list {
		if d == want {
			return true
		}
	}
	return false
}

func newGatewayWithEndpoints(name string, eps []*v1beta1.Endpoint) *v1beta1.Gateway {
	return &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec:       v1beta1.GatewaySpec{ExposeType: v1beta1.ExposeTypePublicIP},
		Status:     v1beta1.GatewayStatus{ActiveEndpoints: eps},
	}
}

// TestGetProxyServerIPs_GatewayProxyPublicIPsIncluded pins the contract: the
// publicIP on every Proxy-typed ActiveEndpoint of the local Gateway must be
// present in the cert SAN list, because that is the address remote proxy
// clients dial (see pkg/engine/proxy.go::getDestAddressFromRemoteGateway).
func TestGetProxyServerIPs_GatewayProxyPublicIPsIncluded(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "1.2.3.4", Port: 10262},
		{NodeName: "node-b", Type: v1beta1.Proxy, PublicIP: "1.2.3.5", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	_, ips := ps.getProxyServerIPsAndDNSName()

	if !containsIP(ips, "1.2.3.4") {
		t.Errorf("expected gateway proxy publicIP 1.2.3.4 in SAN list, got %v", ips)
	}
	if !containsIP(ips, "1.2.3.5") {
		t.Errorf("expected gateway proxy publicIP 1.2.3.5 in SAN list, got %v", ips)
	}
}

// TestGetProxyServerIPs_TunnelEndpointSkipped ensures we do not pollute the
// proxy server cert with VPN tunnel endpoint IPs — those serve a different
// protocol and are not used as proxy server addresses.
func TestGetProxyServerIPs_TunnelEndpointSkipped(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Tunnel, PublicIP: "9.9.9.9", Port: 4500},
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "1.2.3.4", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	_, ips := ps.getProxyServerIPsAndDNSName()

	if containsIP(ips, "9.9.9.9") {
		t.Errorf("tunnel endpoint publicIP must not appear in proxy server cert SAN, got %v", ips)
	}
	if !containsIP(ips, "1.2.3.4") {
		t.Errorf("proxy endpoint publicIP must appear in cert SAN, got %v", ips)
	}
}

// TestGetProxyServerIPs_NilGatewaySafe guards against a nil-deref regression.
// Defensive: real construction always passes a non-nil gateway, but the helper
// must not panic if the field is unset (e.g. in tests or partial init).
func TestGetProxyServerIPs_NilGatewaySafe(t *testing.T) {
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  nil,
		client:   NewFakeClient(),
	}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("getProxyServerIPsAndDNSName panicked with nil gateway: %v", r)
		}
	}()

	_, ips := ps.getProxyServerIPsAndDNSName()
	if !containsIP(ips, "10.0.0.1") {
		t.Errorf("expected nodeIP 10.0.0.1 still present even with nil gateway, got %v", ips)
	}
}

// TestGetProxyServerIPs_GatewayProxyPublicIPDomainIncluded pins the contract:
// when Gateway publicIP is configured as a domain (the field accepts either
// IP or hostname), the domain must appear in the cert SAN dnsName list, not
// in ipAddr. Remote proxy clients dial whatever PublicIP holds, so the cert
// must validate against that same hostname.
func TestGetProxyServerIPs_GatewayProxyPublicIPDomainIncluded(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "raven.example.com", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	dns, ips := ps.getProxyServerIPsAndDNSName()

	if !containsDNS(dns, "raven.example.com") {
		t.Errorf("expected domain publicIP raven.example.com in SAN dnsName list, got %v", dns)
	}
	for _, ip := range ips {
		if ip == nil {
			t.Error("nil net.IP entry leaked into SAN ipAddr list (domain misrouted)")
		}
	}
}

// TestGetProxyServerIPs_MixedIPAndDomainPublicIPs covers a real-world setup
// where one Gateway endpoint is reachable by IP and another by domain. Both
// must land in the cert SAN — IP in ipAddr, domain in dnsName.
func TestGetProxyServerIPs_MixedIPAndDomainPublicIPs(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "1.2.3.4", Port: 10262},
		{NodeName: "node-b", Type: v1beta1.Proxy, PublicIP: "raven.example.com", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	dns, ips := ps.getProxyServerIPsAndDNSName()

	if !containsIP(ips, "1.2.3.4") {
		t.Errorf("expected IP publicIP 1.2.3.4 in SAN ipAddr list, got %v", ips)
	}
	if !containsDNS(dns, "raven.example.com") {
		t.Errorf("expected domain publicIP raven.example.com in SAN dnsName list, got %v", dns)
	}
}

// TestGetProxyServerIPs_TunnelEndpointDomainSkipped: the existing IP test
// covers tunnel-IP exclusion; extend the contract so a tunnel-typed *domain*
// PublicIP is likewise not added to the proxy server cert dnsName.
func TestGetProxyServerIPs_TunnelEndpointDomainSkipped(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Tunnel, PublicIP: "tunnel.example.com", Port: 4500},
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "proxy.example.com", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	dns, _ := ps.getProxyServerIPsAndDNSName()

	if containsDNS(dns, "tunnel.example.com") {
		t.Errorf("tunnel endpoint domain must not appear in proxy server cert dnsName, got %v", dns)
	}
	if !containsDNS(dns, "proxy.example.com") {
		t.Errorf("proxy endpoint domain must appear in cert dnsName, got %v", dns)
	}
}

// TestGetProxyServerIPs_InvalidPublicIPSkipped ensures malformed publicIP
// strings (controller-manager edge cases) do not become nil entries that
// later trip cert generation.
func TestGetProxyServerIPs_InvalidPublicIPSkipped(t *testing.T) {
	gw := newGatewayWithEndpoints("gw-cloud", []*v1beta1.Endpoint{
		{NodeName: "node-a", Type: v1beta1.Proxy, PublicIP: "not-an-ip", Port: 10262},
		{NodeName: "node-b", Type: v1beta1.Proxy, PublicIP: "", Port: 10262},
		{NodeName: "node-c", Type: v1beta1.Proxy, PublicIP: "1.2.3.4", Port: 10262},
	})
	ps := &ProxyServer{
		nodeName: "node-a",
		nodeIP:   "10.0.0.1",
		gateway:  gw,
		client:   NewFakeClient(),
	}

	_, ips := ps.getProxyServerIPsAndDNSName()

	for _, ip := range ips {
		if ip == nil {
			t.Error("nil net.IP entry leaked into SAN list (invalid publicIP not skipped)")
		}
	}
	if !containsIP(ips, "1.2.3.4") {
		t.Errorf("valid publicIP 1.2.3.4 missing from SAN list, got %v", ips)
	}
}
