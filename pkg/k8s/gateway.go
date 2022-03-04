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

package k8s

import (
	"net"
	"strings"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"

	"github.com/openyurtio/raven/pkg/types"
)

func EnsureEndpoint(gateway *v1alpha1.Gateway) *types.Endpoint {
	endpoint := &types.Endpoint{}
	endpoint.ID = gateway.Status.ActiveEndpoint.PrivateIP
	endpoint.Vtep = net.ParseIP(gateway.Status.ActiveEndpoint.PublicIP)
	endpoint.Subnets = make([]string, 0)
	for _, subnet := range gateway.Status.Subnets {
		endpoint.Subnets = append(endpoint.Subnets, subnet)
	}
	endpoint.Subnets, _ = cidrman.MergeCIDRs(endpoint.Subnets)
	endpoint.Topologies = make(map[string]bool)
	for l := range gateway.Labels {
		if strings.HasPrefix(l, v1alpha1.LabelTopologyKeyPrefix) {
			endpoint.Topologies[l] = true
		}
	}
	endpoint.Config = make(map[string]string)
	for k, v := range gateway.Status.ActiveEndpoint.Config {
		endpoint.Config[k] = v
	}
	return endpoint
}

func EnsureSubnets(src *types.Endpoint, dst *types.Endpoint, others map[string]*types.Endpoint) []string {
	subnets := make([]string, 0)
	subnets = append(subnets, src.Subnets...)
	for _, o := range others {
		if o.ID != dst.ID {
			subnets = append(subnets, o.Subnets...)
		}
	}
	return subnets
}

func EnsureCloudEndpoint(others map[string]*types.Endpoint) *types.Endpoint {
	var cloud *types.Endpoint
	subnets := make([]string, 0)
	for _, ep := range others {
		if value, _ := types.GetBoolConfig(ep.Config, types.IsCloudEndpoint); value {
			cloud = ep
		}
		subnets = append(subnets, ep.Subnets...)
	}
	if cloud != nil {
		return &types.Endpoint{
			Subnets:    subnets,
			ID:         cloud.ID,
			Vtep:       cloud.Vtep,
			Topologies: cloud.Topologies,
			Config:     cloud.Config,
		}
	}
	return nil
}
