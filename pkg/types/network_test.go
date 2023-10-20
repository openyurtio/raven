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
	"reflect"
	"testing"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1beta1"
)

const (
	failed  = "\u2717"
	succeed = "\u2713"
)

func TestString(t *testing.T) {
	var e = &Endpoint{
		PrivateIP: "192.168.1.1",
	}

	tests := []struct {
		name   string
		expect string
	}{
		{
			name:   "normal",
			expect: "192.168.1.1",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)

			get := e.String()

			if !reflect.DeepEqual(get, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but get %v", failed, tt.expect, get)
			}
			t.Logf("\t%s\texpect %v, get %v", succeed, tt.expect, get)
		})
	}
}

func TestCopy(t *testing.T) {
	var e = &Endpoint{
		PrivateIP: "192.168.1.1",
	}

	tests := []struct {
		name   string
		pe     *Endpoint
		expect *Endpoint
	}{
		{
			name:   "normal",
			pe:     e,
			expect: e,
		},
		{
			name:   "nil",
			pe:     nil,
			expect: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)

			pe := tt.pe

			if !reflect.DeepEqual(pe, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but get %v", failed, tt.expect, pe)
			}
			t.Logf("\t%s\texpect %v, get %v", succeed, tt.expect, pe)
		})
	}
}

func TestNCopy(t *testing.T) {
	var n = &Network{
		LocalEndpoint: &Endpoint{
			PrivateIP: "192.168.1.1",
		},
		LocalNodeInfo:   make(map[NodeName]*v1beta1.NodeInfo),
		RemoteEndpoints: make(map[GatewayName]*Endpoint),
		RemoteNodeInfo:  make(map[NodeName]*v1beta1.NodeInfo),
	}

	tests := []struct {
		name   string
		pn     *Network
		expect *Network
	}{
		{
			name:   "normal",
			pn:     n,
			expect: n,
		},
		{
			name:   "nil",
			pn:     nil,
			expect: nil,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			t.Logf("\tTestCase: %s", tt.name)

			pn := tt.pn

			if !reflect.DeepEqual(pn, tt.expect) {
				t.Fatalf("\t%s\texpect %v, but pn %v", failed, tt.expect, pn)
			}
			t.Logf("\t%s\texpect %v, pn %v", succeed, tt.expect, pn)
		})
	}
}
