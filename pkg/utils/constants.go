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

package utils

const (
	MaxRetries           = 15
	RavenProxyClientName = "raven-proxy-client"
	RavenProxyServerName = "raven-proxy-server"
	RavenProxyUserName   = "raven-proxy-user"

	RavenProxyClientCSRCN = "tunnel-agent-client"
	RavenProxyServerCSRCN = "tunnel-proxy-server"
	RavenProxyUserCSRCN   = "tunnel-proxy-client"
	RavenCSROrg           = "openyurt:yurttunnel"

	RavenCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	RavenTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"

	RavenProxyServerCertDir = "/var/lib/raven/proxy.server/pki"
	RavenProxyClientCertDir = "/var/lib/raven/proxy.client/pki"
	RavenProxyServerUDSFile = "/tmp/interceptor-proxier.sock"

	DefaultLoopBackIP4                   = "127.0.0.1"
	DefaultLoopBackIP6                   = "::1"
	RavenProxyHostHeaderKey              = "X-Tunnel-Proxy-Host"
	RavenProxyDestHeaderKey              = "X-Tunnel-Proxy-Dest"
	RavenProxyUserHeaderKey              = "User-Agent"
	RavenProxyServerForwardModeHeaderKey = "Forward-Mode"
	RavenProxyServerForwardLocalMode     = "Local"
	RavenProxyServerForwardRemoteMode    = "Remote"

	WorkingNamespace  = "kube-system"
	RavenConfigName   = "raven-cfg"
	RavenEnableProxy  = "enable-l7-proxy"
	RavenEnableTunnel = "enable-l3-tunnel"

	GatewayProxyInternalService  = "x-raven-proxy-internal-svc"
	LabelCurrentGatewayEndpoints = "raven.openyurt.io/endpoints-name"
	LabelCurrentGatewayType      = "raven.openyurt.io/gateway-type"

	NATSymmetric      = "Symmetric NAT"
	NATPortRestricted = "Port Restricted cone NAT"
	NATUndefined      = "Undefined"
)
