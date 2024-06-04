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

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/vdobler/ht/errorlist"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	ipsetutil "github.com/openyurtio/raven/pkg/networkengine/util/ipset"
	"github.com/openyurtio/raven/pkg/types"
)

const (
	RavenSkipNatSet     = "raven-skip-nat-set"
	RavenSkipNatSetType = "hash:net,net"
)

var KeyFunc = func(entry *netlink.IPSetEntry) string {
	return fmt.Sprintf("%s/%d-%s/%d", entry.IP.String(), entry.CIDR, entry.IP2.String(), entry.CIDR2)
}

func IsGatewayRole(network *types.Network, nodeName types.NodeName) bool {
	return network != nil &&
		network.LocalEndpoint != nil &&
		network.LocalEndpoint.NodeName == nodeName
}

func IsCentreGatewayRole(centralGw *types.Endpoint, localNodeName types.NodeName) bool {
	return centralGw != nil && centralGw.NodeName == localNodeName
}

func CalIPSetOnNode(network *types.Network, centralGw *types.Endpoint, nodeName types.NodeName, ipset ipsetutil.IPSetInterface) map[string]*netlink.IPSetEntry {
	set := make(map[string]*netlink.IPSetEntry)
	subnets := make([]string, 0)
	for _, v := range network.RemoteNodeInfo {
		nodeInfo := network.RemoteNodeInfo[types.NodeName(v.NodeName)]
		if nodeInfo == nil {
			klog.Errorf("node %s not found in RemoteNodeInfo", v.NodeName)
			continue
		}
		subnets = append(subnets, nodeInfo.Subnets...)
	}
	var err error
	subnets, err = cidrman.MergeCIDRs(subnets)
	if err != nil {
		return set
	}
	if IsCentreGatewayRole(centralGw, nodeName) {
		subnets = append(subnets, network.LocalEndpoint.Subnets...)
		for _, srcCIDR := range subnets {
			_, ipNet, err := net.ParseCIDR(srcCIDR)
			if err != nil {
				klog.Errorf("parse node subnet %s error %s", srcCIDR, err.Error())
				continue
			}
			ones, _ := ipNet.Mask.Size()
			entry := &netlink.IPSetEntry{
				IP:      ipNet.IP,
				CIDR:    uint8(ones),
				IP2:     ipNet.IP,
				CIDR2:   uint8(ones),
				Replace: true,
			}
			set[ipset.Key(entry)] = entry
		}
	} else {
		for _, localCIDR := range network.LocalEndpoint.Subnets {
			_, localIPNet, err := net.ParseCIDR(localCIDR)
			if err != nil {
				klog.Errorf("parse node subnet %s error %s", localCIDR, err.Error())
				continue
			}
			localOnes, _ := localIPNet.Mask.Size()
			for _, remoteCIDR := range subnets {
				_, remoteIPNet, err := net.ParseCIDR(remoteCIDR)
				if err != nil {
					klog.Errorf("parse node subnet %s error %s", remoteCIDR, err.Error())
					continue
				}
				remoteOnes, _ := remoteIPNet.Mask.Size()
				entry := &netlink.IPSetEntry{
					IP:      localIPNet.IP,
					CIDR:    uint8(localOnes),
					IP2:     remoteIPNet.IP,
					CIDR2:   uint8(remoteOnes),
					Replace: true,
				}
				set[ipset.Key(entry)] = entry
			}
		}
	}
	return set
}

func CleanupRavenSkipNATIPSet() error {
	errList := errorlist.List{}
	ipset, err := ipsetutil.New(RavenSkipNatSet, RavenSkipNatSetType, ipsetutil.IpsetWrapperOption{})
	if err != nil {
		errList = errList.Append(fmt.Errorf("error ensure ip set %s: %s", RavenSkipNatSet, err))
	}
	err = ipset.Flush()
	if err != nil {
		errList = errList.Append(fmt.Errorf("error flushing ipset: %s", err))
	}
	err = ipset.Destroy()
	if err != nil {
		errList = errList.Append(fmt.Errorf("error destroying ipset: %s", err))
	}
	return errList.AsError()
}
