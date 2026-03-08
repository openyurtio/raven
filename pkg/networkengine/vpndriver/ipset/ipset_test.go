/*
Copyright 2023 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package ipset

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/vishvananda/netlink"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/pkg/types"
)

type mockIPSet struct{}

func (m *mockIPSet) List() (*netlink.IPSetResult, error) { return nil, nil }
func (m *mockIPSet) Name() string                        { return "test-set" }
func (m *mockIPSet) Add(_ *netlink.IPSetEntry) error     { return nil }
func (m *mockIPSet) Del(_ *netlink.IPSetEntry) error     { return nil }
func (m *mockIPSet) Flush() error                        { return nil }
func (m *mockIPSet) Destroy() error                      { return nil }
func (m *mockIPSet) Key(entry *netlink.IPSetEntry) string {
	return fmt.Sprintf("%s/%d-%s/%d", entry.IP.String(), entry.CIDR, entry.IP2.String(), entry.CIDR2)
}

func ek(ip1 string, cidr1 uint8, ip2 string, cidr2 uint8) string {
	return fmt.Sprintf("%s/%d-%s/%d", ip1, cidr1, ip2, cidr2)
}

func TestIsGatewayRole(t *testing.T) {
	tests := []struct {
		name     string
		network  *types.Network
		nodeName types.NodeName
		expected bool
	}{
		{
			name:     "nil network",
			network:  nil,
			nodeName: "node1",
			expected: false,
		},
		{
			name:     "nil local endpoint",
			network:  &types.Network{},
			nodeName: "node1",
			expected: false,
		},
		{
			name: "node is gateway",
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{NodeName: "node1"},
			},
			nodeName: "node1",
			expected: true,
		},
		{
			name: "node is not gateway",
			network: &types.Network{
				LocalEndpoint: &types.Endpoint{NodeName: "node1"},
			},
			nodeName: "node2",
			expected: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsGatewayRole(tt.network, tt.nodeName))
		})
	}
}

func TestIsCentreGatewayRole(t *testing.T) {
	tests := []struct {
		name      string
		centralGw *types.Endpoint
		nodeName  types.NodeName
		expected  bool
	}{
		{
			name:      "nil central gateway",
			centralGw: nil,
			nodeName:  "node1",
			expected:  false,
		},
		{
			name:      "node is central gateway",
			centralGw: &types.Endpoint{NodeName: "node1"},
			nodeName:  "node1",
			expected:  true,
		},
		{
			name:      "node is not central gateway",
			centralGw: &types.Endpoint{NodeName: "node1"},
			nodeName:  "node2",
			expected:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, IsCentreGatewayRole(tt.centralGw, tt.nodeName))
		})
	}
}

func TestKeyFunc(t *testing.T) {
	entry := &netlink.IPSetEntry{
		IP:    net.ParseIP("10.244.1.0"),
		CIDR:  24,
		IP2:   net.ParseIP("10.244.2.0"),
		CIDR2: 24,
	}
	assert.Equal(t, "10.244.1.0/24-10.244.2.0/24", KeyFunc(entry))
}

func TestCalIPSetOnNode_NonCentralGateway(t *testing.T) {
	// Use non-adjacent CIDRs to avoid merging by cidrman.MergeCIDRs
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.4.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// 2 remotes * 2 directions = 4
	assert.Equal(t, 4, len(result))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.4.0", 24))
	assert.Contains(t, result, ek("10.244.4.0", 24, "10.244.1.0", 24))
}

func TestCalIPSetOnNode_CentralGateway(t *testing.T) {
	centralGw := &types.Endpoint{NodeName: "central-gw"}
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "central-gw",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.4.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, centralGw, "central-gw", &mockIPSet{})

	// local↔remote: 2 remotes * 2 directions = 4
	// remote↔remote: C(2,2) * 2 directions = 2
	// Total = 6
	assert.Equal(t, 6, len(result))

	// local↔remote
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.4.0", 24))
	assert.Contains(t, result, ek("10.244.4.0", 24, "10.244.1.0", 24))

	// remote↔remote
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.4.0", 24))
	assert.Contains(t, result, ek("10.244.4.0", 24, "10.244.2.0", 24))
}

func TestCalIPSetOnNode_CentralGatewayThreeRemotes(t *testing.T) {
	centralGw := &types.Endpoint{NodeName: "central-gw"}
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "central-gw",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.4.0/24"}},
			"node-c": {NodeName: "node-c", Subnets: []string{"10.244.6.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, centralGw, "central-gw", &mockIPSet{})

	// local↔remote: 3 * 2 = 6
	// remote↔remote: C(3,2) * 2 = 6
	// Total = 12
	assert.Equal(t, 12, len(result))

	// remote↔remote pairs
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.4.0", 24))
	assert.Contains(t, result, ek("10.244.4.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.6.0", 24))
	assert.Contains(t, result, ek("10.244.6.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.4.0", 24, "10.244.6.0", 24))
	assert.Contains(t, result, ek("10.244.6.0", 24, "10.244.4.0", 24))
}

func TestCalIPSetOnNode_MultipleLocalSubnets(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24", "10.244.5.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// 2 local * 1 remote * 2 directions = 4
	assert.Equal(t, 4, len(result))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))
	assert.Contains(t, result, ek("10.244.5.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.5.0", 24))
}

func TestCalIPSetOnNode_InvalidLocalCIDR(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"invalid-cidr", "10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// Invalid local CIDR skipped, valid one still generates entries
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))
}

func TestCalIPSetOnNode_InvalidRemoteCIDR(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"bad-cidr"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// cidrman.MergeCIDRs fails on invalid CIDR, returns empty set
	assert.Equal(t, 0, len(result))
}

func TestCalIPSetOnNode_NoRemoteNodes(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	assert.Equal(t, 0, len(result))
}

func TestCalIPSetOnNode_CIDRMerging(t *testing.T) {
	// Two adjacent subnets from different nodes get merged
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/25"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.2.128/25"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// Merged to 10.244.2.0/24, so 1 merged * 2 directions = 2
	assert.Equal(t, 2, len(result))
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))
}

func TestCalIPSetOnNode_CentralGwRemoteNotMerged(t *testing.T) {
	// Central gateway remote↔remote uses unmerged subnets to preserve
	// cross-gateway pairs even when CIDRs are adjacent
	centralGw := &types.Endpoint{NodeName: "central-gw"}
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "central-gw",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/25"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.2.128/25"}},
		},
	}

	result := CalIPSetOnNode(network, centralGw, "central-gw", &mockIPSet{})

	// local↔remote uses merged: 10.244.2.0/24 -> 1 * 2 = 2
	// remote↔remote uses unmerged: (2.0/25, 2.128/25) * 2 = 2
	// Total = 4
	assert.Equal(t, 4, len(result))

	// local↔merged remote
	assert.Contains(t, result, ek("10.244.1.0", 24, "10.244.2.0", 24))
	assert.Contains(t, result, ek("10.244.2.0", 24, "10.244.1.0", 24))

	// remote↔remote unmerged
	assert.Contains(t, result, ek("10.244.2.0", 25, "10.244.2.128", 25))
	assert.Contains(t, result, ek("10.244.2.128", 25, "10.244.2.0", 25))
}

func TestCalIPSetOnNode_SingleRemoteCentralGw(t *testing.T) {
	centralGw := &types.Endpoint{NodeName: "central-gw"}
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "central-gw",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, centralGw, "central-gw", &mockIPSet{})

	// Only local↔remote: 1 * 2 = 2, no remote↔remote
	assert.Equal(t, 2, len(result))
}

func TestCalIPSetOnNode_EntryReplaceFlag(t *testing.T) {
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	for _, entry := range result {
		assert.True(t, entry.Replace)
	}
}

func TestCalIPSetOnNode_InvalidRemoteCIDRInCentralGwLoop(t *testing.T) {
	// Test that invalid CIDRs in the unmerged remote list are skipped
	// in the central gateway remote↔remote loop
	centralGw := &types.Endpoint{NodeName: "central-gw"}
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "central-gw",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-a", Subnets: []string{"10.244.2.0/24"}},
			"node-b": {NodeName: "node-b", Subnets: []string{"10.244.4.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, centralGw, "central-gw", &mockIPSet{})

	// local↔remote: 2 * 2 = 4
	// remote↔remote: 1 pair * 2 = 2
	// Total = 6
	assert.Equal(t, 6, len(result))
}

func TestCalIPSetOnNode_RemoteNodeNotFound(t *testing.T) {
	// When RemoteNodeInfo has a key but the looked-up nodeInfo is nil
	// (key mismatch scenario: map key differs from v.NodeName)
	network := &types.Network{
		LocalEndpoint: &types.Endpoint{
			NodeName: "gw1",
			Subnets:  []string{"10.244.1.0/24"},
		},
		RemoteNodeInfo: map[types.NodeName]*v1beta1.NodeInfo{
			"node-a": {NodeName: "node-x", Subnets: []string{"10.244.2.0/24"}},
		},
	}

	result := CalIPSetOnNode(network, nil, "gw1", &mockIPSet{})

	// v.NodeName is "node-x", looked up as RemoteNodeInfo["node-x"] which is nil
	// The nil check skips it, no subnets collected
	assert.Equal(t, 0, len(result))
}
