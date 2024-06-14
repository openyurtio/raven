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

package libreswan

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	iptablesutil "github.com/openyurtio/raven/pkg/networkengine/util/iptables"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
	"github.com/openyurtio/raven/pkg/types"
)

type whackMock struct {
	connections map[string]string
	cmdHistory  []string
}

func (w *whackMock) whackCmd(args ...string) error {
	str := strings.Join(args, " ")
	w.cmdHistory = append(w.cmdHistory, str)
	if w.connections == nil {
		w.connections = make(map[string]string)
	}
	var connName string
	var op string // "add" or "del"
	for k, v := range args {
		if v == "--name" && len(args) > k+1 {
			connName = args[k+1]
		}
		if v == "--to" {
			op = "add"
		}
		if v == "--delete" {
			op = "del"
		}
	}
	if connName == "" {
		return errors.New("connection name is empty")
	}
	switch op {
	case "add":
		w.connections[connName] = str
	case "del":
		delete(w.connections, connName)
	}
	return nil
}

func TestLibreswan_Apply(t *testing.T) {
	localGwIP := "192.168.0.1"
	remoteGw1IP := "192.168.0.2"
	remoteGw2IP := "192.168.0.3"
	localSubnet := []string{"10.244.0.0/24", "10.244.1.0/24"}
	remoteGw1Subnets := []string{"10.244.2.0/24", "10.244.3.0/24"}
	remoteGw2Subnets := []string{"10.244.4.0/24", "10.244.5.0/24"}

	testcases := []struct {
		name             string
		nodeName         string
		network          *types.Network
		expectedConnName map[string]struct{}
		shouldCleanup    bool
		findCentralGw    func(network *types.Network) *types.Endpoint
	}{
		{
			name:     "no-NATed-gateway",
			nodeName: "localGwNode",
			expectedConnName: map[string]struct{}{
				// localGw to remoteGw1
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[1]): {},
				// localGw to remoteGw2
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[0]): {},
			},
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "localGw",
					NodeName:    "localGwNode",
					Subnets:     localSubnet,
					PrivateIP:   localGwIP,
					PublicIP:    "1.1.1.1",
					UnderNAT:    false,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"remoteGw1": {
						GatewayName: "remoteGw1",
						NodeName:    "remoteNode1",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    false,
					},
					"remoteGw2": {
						GatewayName: "remoteGw2",
						NodeName:    "remoteNode2",
						Subnets:     remoteGw2Subnets[:1],
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    false,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return network.LocalEndpoint
			},
		}, {
			name:     "all-NATed-gateway",
			nodeName: "localGwNode",
			// It is unable to set up any vpn connections in such case and should clean up vpn connections
			expectedConnName: map[string]struct{}{},
			shouldCleanup:    false,
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "localGw",
					NodeName:    "localGwNode",
					Subnets:     []string{"10.244.0.0/24", "10.244.1.0/24"},
					PrivateIP:   "192.168.0.1",
					PublicIP:    "1.1.1.1",
					UnderNAT:    true,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"remoteGw1": {
						GatewayName: "remoteGw1",
						NodeName:    "remoteNode1",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    true,
					},
					"remoteGw2": {
						GatewayName: "remoteGw2",
						NodeName:    "remoteNode2",
						Subnets:     remoteGw2Subnets,
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    true,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return nil
			},
		}, {
			name:     "NATed-gateway-connect-to-central-gateway",
			nodeName: "localGwNode",
			expectedConnName: map[string]struct{}{
				// Direct connection to the central gateway
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[1]): {},
				// Connection that forwards traffic of other NATed gateway
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw2Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw2Subnets[1]): {},
			},
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "localGw",
					NodeName:    "localGwNode",
					Subnets:     localSubnet,
					PrivateIP:   localGwIP,
					PublicIP:    "1.1.1.1",
					UnderNAT:    true,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"centralGw": {
						GatewayName: "centralGw",
						NodeName:    "centralGwNode",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    false,
					},
					"remoteGw": {
						GatewayName: "remoteGw",
						NodeName:    "remoteNode",
						Subnets:     remoteGw2Subnets,
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    true,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return network.RemoteEndpoints["centralGw"]
			},
		},
		{
			name:     "NATed-gateway-connect-to-central-gateway-and-not-NATed-gateway",
			nodeName: "localGwNode",
			expectedConnName: map[string]struct{}{
				// Direct connection to remoteGw1 (central gateway)
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[1]): {},
				// Direct connection to remoteGw2
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[1]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[1]): {},
				// No need to add subnets of the not NATed gateway into left subnets
			},
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "localGw",
					NodeName:    "localGwNode",
					Subnets:     localSubnet,
					PrivateIP:   localGwIP,
					PublicIP:    "1.1.1.1",
					UnderNAT:    true,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"remoteGw1": {
						GatewayName: "remoteGw1",
						NodeName:    "remoteGwNode1",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    false,
					},
					"remoteGw2": {
						GatewayName: "remoteGw2",
						NodeName:    "remoteGwNode2",
						Subnets:     remoteGw2Subnets,
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    false,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return network.RemoteEndpoints["remoteGw1"]
			},
		},
		{
			name:     "central-gateway-connect-to-NATed-gateways",
			nodeName: "centralGwNode",
			expectedConnName: map[string]struct{}{
				// Direct connection to remoteGw1
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[1]): {},
				// Direct connection to remoteGw2
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[1]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[1]): {},
				// Connections that forward traffic between remoteGw1 and remoteGw2
				connectionName(localGwIP, remoteGw1IP, remoteGw2Subnets[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, remoteGw2Subnets[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, remoteGw2Subnets[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, remoteGw2Subnets[1], remoteGw1Subnets[1]): {},

				connectionName(localGwIP, remoteGw2IP, remoteGw1Subnets[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, remoteGw1Subnets[0], remoteGw2Subnets[1]): {},
				connectionName(localGwIP, remoteGw2IP, remoteGw1Subnets[1], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, remoteGw1Subnets[1], remoteGw2Subnets[1]): {},
			},
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "centralGw",
					NodeName:    "centralGwNode",
					Subnets:     localSubnet,
					PrivateIP:   localGwIP,
					PublicIP:    "1.1.1.1",
					UnderNAT:    false,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"remoteGw1": {
						GatewayName: "remoteGw1",
						NodeName:    "remoteGwNode1",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    true,
					},
					"remoteGw2": {
						GatewayName: "remoteGw2",
						NodeName:    "remoteGwNode12",
						Subnets:     remoteGw2Subnets,
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    true,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return network.LocalEndpoint
			},
		}, {
			name:     "central-gateway-connect-to-NATed-gateways-and-not-NATed-gateway",
			nodeName: "centralGwNode",
			expectedConnName: map[string]struct{}{
				// Direct connection to remoteGw1
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[0], remoteGw1Subnets[1]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[0]): {},
				connectionName(localGwIP, remoteGw1IP, localSubnet[1], remoteGw1Subnets[1]): {},
				// Direct connection to remoteGw2
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[0]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[0], remoteGw2Subnets[1]): {},
				connectionName(localGwIP, remoteGw2IP, localSubnet[1], remoteGw2Subnets[1]): {},
			},
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{
					GatewayName: "centralGw",
					NodeName:    "centralGwNode",
					Subnets:     localSubnet,
					PrivateIP:   localGwIP,
					PublicIP:    "1.1.1.1",
					UnderNAT:    false,
				},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
					"remoteGw1": {
						GatewayName: "remoteGw1",
						NodeName:    "remoteGwNode1",
						Subnets:     remoteGw1Subnets,
						PrivateIP:   remoteGw1IP,
						PublicIP:    "1.1.1.2",
						UnderNAT:    true,
					},
					"remoteGw2": {
						GatewayName: "remoteGw2",
						NodeName:    "remoteGwNode12",
						Subnets:     remoteGw2Subnets,
						PrivateIP:   remoteGw2IP,
						PublicIP:    "1.1.1.3",
						UnderNAT:    false,
					},
				},
			},
			findCentralGw: func(network *types.Network) *types.Endpoint {
				return network.LocalEndpoint
			},
		},
	}
	for _, v := range testcases {
		t.Run(v.name, func(t *testing.T) {
			var cleanup bool
			netlinkutil.XfrmPolicyFlush = func() error {
				cleanup = true
				return nil
			}
			w := &whackMock{}
			whackCmd = w.whackCmd
			a := assert.New(t)
			l := &libreswan{
				connections: make(map[string]bool),
				nodeName:    types.NodeName(v.nodeName),
			}
			var err error
			l.iptables, err = iptablesutil.New()
			a.NoError(err)
			a.NoError(l.Apply(v.network, nil)) // libreswan will not use route driver mtu fn
			connName := make(map[string]struct{})
			for name := range w.connections {
				connName[name] = struct{}{}
			}
			a.Equal(v.expectedConnName, connName)
			a.Equal(v.shouldCleanup, cleanup)
		})
	}
}
