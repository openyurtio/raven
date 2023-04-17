//go:build linux
// +build linux

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

package networkutil

import (
	"reflect"
	"testing"

	"github.com/vishvananda/netlink"
)

const (
	failed  = "\u2717"
	succeed = "\u2713"
)

func TestNewRavenRule(t *testing.T) {
	tests := []struct {
		name         string
		rulePriority int
		routeTableID int
		expect       netlink.Rule
	}{
		{
			"normal",
			1,
			1,
			netlink.Rule{
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Priority:          1,
				Mark:              -1,
				Mask:              -1,
				Goto:              -1,
				Flow:              -1,
				Table:             1,
				Family:            netlink.FAMILY_V4,
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)

			get := NewRavenRule(1, 1)

			if !reflect.DeepEqual(*get, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but get %v", failed, tt.expect, get)
			}
			t.Logf("\t%s\texpect %v, get %v", succeed, tt.expect, get)
		})
	}
}

func TestRouteKey(t *testing.T) {
	route1 := &netlink.Route{
		Dst:   netlink.NewIPNet([]byte{0xC0, 0xA8, 0x00, 0x01}),
		Table: 1,
	}
	tests := []struct {
		name   string
		route  *netlink.Route
		expect string
	}{
		{
			name:  "normal",
			route: route1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)

			tt.expect = tt.route.String()
			get := RouteKey(tt.route)

			if !reflect.DeepEqual(get, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but get %v", failed, tt.expect, get)
			}
			t.Logf("\t%s\texpect %v, get %v", succeed, tt.expect, get)
		})
	}
}

func TestRuleKey(t *testing.T) {
	tests := []struct {
		name   string
		rule   *netlink.Rule
		expect string
	}{
		{
			name: "nil",
			rule: &netlink.Rule{
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Priority:          -1,
				Mark:              -1,
				Mask:              -1,
				Goto:              -1,
				Flow:              -1,
			},
		},
		{
			name: "normal",
			rule: &netlink.Rule{
				SuppressIfgroup:   -1,
				SuppressPrefixlen: -1,
				Priority:          -1,
				Mark:              -1,
				Mask:              -1,
				Goto:              -1,
				Flow:              -1,
				Src:               netlink.NewIPNet([]byte{0xC0, 0xA8, 0x00, 0x01}),
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)
			tt.expect = tt.rule.String()
			get := RuleKey(tt.rule)

			if !reflect.DeepEqual(get, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but get %v", failed, tt.expect, get)
			}
			t.Logf("\t%s\texpect %v, get %v", succeed, tt.expect, get)
		})
	}
}
