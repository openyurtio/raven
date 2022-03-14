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
	"sort"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"

	"github.com/openyurtio/raven/pkg/types"
)

func EnsureEndpoint(gateway *v1alpha1.Gateway) *types.Endpoint {
	endpoint := &types.Endpoint{}
	endpoint.NodeName = gateway.Status.ActiveEndpoint.NodeName
	endpoint.ID = gateway.Status.ActiveEndpoint.PrivateIP
	endpoint.Vtep = net.ParseIP(gateway.Status.ActiveEndpoint.PublicIP)
	endpoint.Subnets = make([]string, 0)
	for _, subnet := range gateway.Status.Subnets {
		endpoint.Subnets = append(endpoint.Subnets, subnet)
	}
	endpoint.Subnets, _ = cidrman.MergeCIDRs(endpoint.Subnets)
	endpoint.NATEnabled = gateway.Status.ActiveEndpoint.NATEnabled
	endpoint.Config = make(map[string]string)
	for k, v := range gateway.Status.ActiveEndpoint.Config {
		endpoint.Config[k] = v
	}
	endpoint.Central = false
	return endpoint
}

func UpdateCentralEndpoint(local *types.Endpoint, remote *types.Endpoint, others map[string]*types.Endpoint) *types.Endpoint {
	subnets := make([]string, 0)
	subnets = append(subnets, local.Subnets...)
	for _, o := range others {
		if o.NodeName != remote.NodeName {
			subnets = append(subnets, o.Subnets...)
		}
	}
	return &types.Endpoint{
		NodeName:   local.NodeName,
		Subnets:    subnets,
		ID:         local.ID,
		Vtep:       local.Vtep,
		NATEnabled: local.NATEnabled,
		Config:     local.Config,
		Central:    true,
	}
}

func EnsureCentralEndpoint(local *types.Endpoint, others map[string]*types.Endpoint) *types.Endpoint {
	candidates := make([]*types.Endpoint, 0)
	candidates = append(candidates, local)
	for _, v := range others {
		candidates = append(candidates, v)
	}
	// TODO: Maybe cause central ep switch when add or delete a candidate gateway because of sorting
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].NodeName < candidates[j].NodeName
	})

	var central *types.Endpoint
	subnets := make([]string, 0)
	for i := range candidates {
		if !candidates[i].NATEnabled {
			central = candidates[i]
		}
		if local.NodeName != candidates[i].NodeName {
			subnets = append(subnets, candidates[i].Subnets...)
		}
	}
	if central != nil {
		return &types.Endpoint{
			NodeName:   central.NodeName,
			Subnets:    subnets,
			ID:         central.ID,
			Vtep:       central.Vtep,
			NATEnabled: central.NATEnabled,
			Config:     central.Config,
			Central:    true,
		}
	}
	return nil
}
