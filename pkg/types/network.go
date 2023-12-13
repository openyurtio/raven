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

package types

import (
	"github.com/openyurtio/api/raven/v1beta1"
)

// GatewayName is the type representing the name of Gateway.
type GatewayName string

// NodeName is the type representing the name of Node.
type NodeName string

type Endpoint struct {
	// GatewayName is the name of the Gateway holding this the Endpoint.
	GatewayName GatewayName
	// NodeName is the name of the Node holding this Endpoint.
	NodeName NodeName
	// Subnets stores subnets of the nodes managed by the gateway.
	Subnets    []string
	PrivateIP  string
	PublicIP   string
	PublicPort int
	UnderNAT   bool
	NATType    string
	Config     map[string]string
}

func (e *Endpoint) String() string {
	return e.PrivateIP
}

func (e *Endpoint) Copy() *Endpoint {
	if e == nil {
		return nil
	}
	copied := *e
	copied.Subnets = make([]string, len(e.Subnets))
	copy(copied.Subnets, e.Subnets)
	copied.Config = make(map[string]string)
	for k, v := range e.Config {
		copied.Config[k] = v
	}
	return &copied
}

// Network describes the network topology in the cluster and
// provides enough information for route driver and vpn driver to set up routing rules and vpn connections.
type Network struct {
	// LocalEndpoint is the Endpoint of local gateway node.
	// Equals to nil if there is no local gateway node.
	LocalEndpoint *Endpoint
	// LocalNodeInfo stores NodeInfo of all nodes in local gateway.
	LocalNodeInfo map[NodeName]*v1beta1.NodeInfo
	// RemoteEndpoints is the Endpoint of all remote gateway nodes, indexed by their gateway name.
	// Equals to nil if there is no remote gateway node.
	RemoteEndpoints map[GatewayName]*Endpoint
	// RemoteNodeInfo stores NodeInfo of all nodes in remote gateways
	RemoteNodeInfo map[NodeName]*v1beta1.NodeInfo
}

func (n *Network) Copy() *Network {
	if n == nil {
		return nil
	}
	nw := &Network{
		LocalEndpoint:   n.LocalEndpoint.Copy(),
		LocalNodeInfo:   make(map[NodeName]*v1beta1.NodeInfo),
		RemoteEndpoints: make(map[GatewayName]*Endpoint),
		RemoteNodeInfo:  make(map[NodeName]*v1beta1.NodeInfo),
	}
	for k, v := range n.RemoteEndpoints {
		nw.RemoteEndpoints[k] = v.Copy()
	}
	for k, v := range n.LocalNodeInfo {
		nw.LocalNodeInfo[k] = v.DeepCopy()
	}
	for k, v := range n.RemoteNodeInfo {
		nw.RemoteNodeInfo[k] = v.DeepCopy()
	}
	return nw
}
