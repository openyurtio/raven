/*
 * Copyright 2022 The OpenYurt Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package config

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

// Config is the main context object for raven agent
type Config struct {
	NodeName   string
	NodeIP     string
	SyncRules  bool
	SyncPeriod metav1.Duration

	MetricsBindAddress string
	HealthProbeAddr    string

	KubeConfig *rest.Config
	Manager    manager.Manager
	Tunnel     *TunnelConfig
	Proxy      *ProxyConfig
}

type TunnelConfig struct {
	VPNDriver         string
	VPNPort           string
	RouteDriver       string
	MACPrefix         string
	ForwardNodeIP     bool
	NATTraversal      bool
	KeepAliveInterval int
	KeepAliveTimeout  int
}

type ProxyConfig struct {
	ProxyMetricsAddress string
	ProxyClientCertDir  string

	InternalInsecureAddress  string
	InternalSecureAddress    string
	ExternalAddress          string
	ProxyServerCertDNSNames  string
	ProxyServerCertIPs       string
	ProxyServerCertDir       string
	InterceptorServerUDSFile string
}

type completedConfig struct {
	*Config
}

// CompletedConfig same as Config, just to swap private object.
type CompletedConfig struct {
	// Embed a private pointer that cannot be instantiated outside this package.
	*completedConfig
}

// Complete fills in any fields not set that are required to have valid data. It's mutating the receiver.
func (c *Config) Complete() *CompletedConfig {
	cc := completedConfig{c}
	return &CompletedConfig{&cc}
}
