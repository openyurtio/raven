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

	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
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
			actual := make(map[string]*netlink.Route)
			for k := range v.current {
				actual[k] = v.current[k]
			}
			netlinkutil.RouteAdd = func(route *netlink.Route) (err error) {
				actual[routeKey(route)] = route
				return nil
			}
			netlinkutil.RouteReplace = func(route *netlink.Route) error {
				actual[routeKey(route)] = route
				return nil
			}
			netlinkutil.RouteDel = func(route *netlink.Route) (err error) {
				delete(actual, routeKey(route))
				return nil
			}
			a := assert.New(t)

			err := applyRoutes(v.current, v.desired)
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
			actual := make(map[string]*netlink.Rule)
			for k := range v.current {
				actual[k] = v.current[k]
			}
			netlinkutil.RuleAdd = func(route *netlink.Rule) (err error) {
				actual[ruleKey(route)] = route
				return nil
			}
			netlinkutil.RuleDel = func(route *netlink.Rule) error {
				delete(actual, ruleKey(route))
				return nil
			}
			a := assert.New(t)

			err := applyRules(v.current, v.desired)
			a.NoError(err)
			if len(v.expected) == 0 {
				a.Len(actual, 0)
			} else {
				a.Equal(v.expected, actual)
			}
		})
	}
}
