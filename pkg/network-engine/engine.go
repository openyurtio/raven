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

package network_engine

import (
	"net"

	"github.com/openyurtio/raven/pkg/types"
)

type NetworkEngine interface {
	// Start network engine
	Start()
	// Update local network
	Update(localIP net.IP, localPublicIP net.IP, localSubnets []string)
	// MTU Minimal MTU in NodePool
	// NormalNode = InterfaceMTU - VxlanEncapHeader
	// GatewayNode = min(IntrafaceMTU - IPSecEncapHeader, SamePoolNormalNodesMTU...)
	MTU() (int, error)
	// ConnectToGateway Connect NormalNode to Endpoint Node
	ConnectToGateway(gateway *types.Gateway) error
	// ConnectToEndpoint Connect to others Endpoint
	ConnectToEndpoint(gateway *types.Endpoint) error
	// EnsureEndpoints Ensure Endpoints configuration
	// on local/remote config/subnet changed
	EnsureEndpoints(gateway []*types.Endpoint) error
	// Cleanup all for new setup
	Cleanup()
}

func NewNetworkEngine() NetworkEngine {
	return &Engine{
		vxlanAgent:       vxlanAgent{},
		libreswanGateway: libreswanGateway{},
	}
}

type Engine struct {
	vxlanAgent
	libreswanGateway
}

func (ne *Engine) Update(localIP net.IP, localPublicIP net.IP, localSubnets []string) {
	ne.vxlanAgent.Update(localIP, localPublicIP, localSubnets)
	ne.libreswanGateway.Update(localIP, localPublicIP, localSubnets)
}

func (ne *Engine) Cleanup() {
	ne.vxlanAgent.Cleanup()
	ne.libreswanGateway.Cleanup()
}
