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

package vxlan

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/openyurtio/api/raven/v1beta1"
	networkutil "github.com/openyurtio/raven/pkg/networkengine/util"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
	"github.com/openyurtio/raven/pkg/types"
)

func Test_applyRoutes(t *testing.T) {
	tt := []struct {
		name     string
		current  map[string]*netlink.Route
		desired  map[string]*netlink.Route
		expected map[string]*netlink.Route
	}{
		{
			name: "cleanup",
			current: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			expected: map[string]*netlink.Route{},
		}, {
			name: "add-routes",
			current: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			desired: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			expected: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
		}, {
			name: "replace-routes",
			current: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 2, 0),
				},
			},
			desired: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 0, 3),
				},
			},
			expected: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 0, 3),
				},
			},
		}, {
			name: "remove-unwanted-routes",
			current: map[string]*netlink.Route{
				"192.168.1.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 2, 0),
				},
			},
			desired: map[string]*netlink.Route{
				"192.168.2.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 0, 3),
				},
			},
			expected: map[string]*netlink.Route{
				"192.168.2.0/24-9027": {
					Table: 9027,
					Dst: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
					Gw: net.IPv4(192, 168, 0, 3),
				},
			},
		},
	}
	for _, v := range tt {
		t.Run(v.name, func(t *testing.T) {
			current := make(map[string]*netlink.Route)
			for _, r := range v.current {
				current[networkutil.RouteKey(r)] = r
			}
			v.current = current

			desired := make(map[string]*netlink.Route)
			for _, r := range v.desired {
				desired[networkutil.RouteKey(r)] = r
			}
			v.desired = desired

			expected := make(map[string]*netlink.Route)
			for _, r := range v.expected {
				expected[networkutil.RouteKey(r)] = r
			}
			v.expected = expected

			actual := make(map[string]*netlink.Route)
			for k := range v.current {
				actual[k] = v.current[k]
			}
			netlinkutil.RouteAdd = func(route *netlink.Route) (err error) {
				actual[networkutil.RouteKey(route)] = route
				return nil
			}
			netlinkutil.RouteReplace = func(route *netlink.Route) error {
				actual[networkutil.RouteKey(route)] = route
				return nil
			}
			netlinkutil.RouteDel = func(route *netlink.Route) (err error) {
				delete(actual, networkutil.RouteKey(route))
				return nil
			}
			a := assert.New(t)

			err := networkutil.ApplyRoutes(v.current, v.desired)
			a.NoError(err)
			if len(v.expected) == 0 {
				a.Len(actual, 0)
			} else {
				a.Equal(v.expected, actual)
			}
		})
	}
}

func Test_applyRule(t *testing.T) {
	tt := []struct {
		name     string
		current  map[string]*netlink.Rule
		desired  map[string]*netlink.Rule
		expected map[string]*netlink.Rule
	}{
		{
			name: "cleanup",
			current: map[string]*netlink.Rule{
				"192.168.1.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			expected: map[string]*netlink.Rule{},
		}, {
			name: "add-rules",
			current: map[string]*netlink.Rule{
				"192.168.1.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			desired: map[string]*netlink.Rule{
				"192.168.1.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			expected: map[string]*netlink.Rule{
				"192.168.1.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
				"192.168.2.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
		}, {
			name: "remove-unwanted-rules",
			current: map[string]*netlink.Rule{
				"192.168.1.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 1, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			desired: map[string]*netlink.Rule{
				"192.168.2.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
			expected: map[string]*netlink.Rule{
				"192.168.2.0/24": {
					Table: 9027,
					Src: &net.IPNet{
						IP:   net.IPv4(192, 168, 2, 0),
						Mask: net.IPMask{0xff, 0xff, 0xff, 00},
					},
				},
			},
		},
	}
	for _, v := range tt {
		t.Run(v.name, func(t *testing.T) {
			current := make(map[string]*netlink.Rule)
			for _, r := range v.current {
				current[networkutil.RuleKey(r)] = r
			}
			v.current = current

			desired := make(map[string]*netlink.Rule)
			for _, r := range v.desired {
				desired[networkutil.RuleKey(r)] = r
			}
			v.desired = desired

			expected := make(map[string]*netlink.Rule)
			for _, r := range v.expected {
				expected[networkutil.RuleKey(r)] = r
			}
			v.expected = expected

			actual := make(map[string]*netlink.Rule)
			for k := range v.current {
				actual[k] = v.current[k]
			}
			netlinkutil.RuleAdd = func(route *netlink.Rule) (err error) {
				actual[networkutil.RuleKey(route)] = route
				return nil
			}
			netlinkutil.RuleDel = func(route *netlink.Rule) error {
				delete(actual, networkutil.RuleKey(route))
				return nil
			}
			a := assert.New(t)

			err := networkutil.ApplyRules(v.current, v.desired)
			a.NoError(err)
			if len(v.expected) == 0 {
				a.Len(actual, 0)
			} else {
				a.Equal(v.expected, actual)
			}
		})
	}
}

func TestVxlan_Apply(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			GatewayName: "gw-1",
			NodeName:    "node-1",
			Subnets: []string{
				"10.10.1.0/24",
			},
			PrivateIP: "192.168.1.1",
		},
		LocalNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-1": {
				NodeName:  "node-1",
				PrivateIP: "192.168.1.1",
				Subnets: []string{
					"10.10.1.0/24",
				},
			},
			"node-4": {
				NodeName:  "node-4",
				PrivateIP: "192.168.1.4",
				Subnets: []string{
					"10.10.4.0/24",
				},
			},
		},
		RemoteEndpoints: map[types.GatewayName]*types.Endpoint{
			"gw-2": {
				GatewayName: "gw-2",
				NodeName:    "node-2",
				Subnets: []string{
					"10.10.2.0/24",
				},
				PrivateIP: "192.168.1.2",
			},
			"gw-3": {
				GatewayName: "gw-3",
				NodeName:    "remoteGwNode12",
				Subnets: []string{
					"10.10.3.0/24",
				},
				PrivateIP: "192.168.1.3",
			},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-2": {
				NodeName:  "node-2",
				PrivateIP: "192.168.1.2",
				Subnets: []string{
					"10.10.2.0/24",
				},
			},
			"node-3": {
				NodeName:  "node-3",
				PrivateIP: "192.168.1.3",
				Subnets: []string{
					"10.10.3.0/24",
				},
			},
		},
	}

	testcases := []struct {
		name     string
		nodeName types.NodeName
		network  *types.Network
	}{
		{
			name:     "test-gateway-vxlan-apply",
			nodeName: "node-1",
			network:  network,
		},
		{
			name:     "test-non-gateway-vxlan-apply",
			nodeName: "node-4",
			network:  network,
		},
	}

	for _, v := range testcases {
		t.Run(v.name, func(t *testing.T) {
			vx := vxlan{
				nodeName:  v.nodeName,
				macPrefix: "aa:0f",
			}
			a := assert.New(t)
			a.NoError(vx.Init())
			a.NoError(vx.Apply(v.network, func() (int, error) {
				return 1500, nil
			}))
			a.NoError(vx.Cleanup())
		})
	}
}
