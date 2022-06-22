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

package vxlan

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
)

func ensureVxlanLink(vxlan netlink.Vxlan, vtepIP net.IP) (netlink.Link, error) {
	linkExist := func() netlink.Link {
		link, err := netlink.LinkByName(vxlanLinkName)
		if err == nil {
			return link
		}
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			klog.Errorf("error get vxlan link: %v", err)
		}
		return nil
	}
	vxLink := linkExist()
	// add link
	if vxLink == nil {
		err := netlink.LinkAdd(&vxlan)
		if err != nil {
			return nil, fmt.Errorf("error add vxlan link: %v", err)
		}
		vxLink = linkExist()
	} else {
		if isVxlanConfigChanged(&vxlan, vxLink) {
			if err := netlink.LinkDel(vxLink); err != nil {
				return nil, fmt.Errorf("error del existing vxlan: %v", err)
			}
			if err := netlink.LinkAdd(&vxlan); err != nil {
				return nil, fmt.Errorf("error add vxlan link: %v", err)
			}
		}
	}
	err := netlink.LinkSetUp(vxLink)
	if err != nil {
		return nil, fmt.Errorf("error set up vxlan link: %v", err)
	}
	// add address
	err = netlink.AddrReplace(vxLink, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   vtepIP,
			Mask: net.IPv4Mask(0xff, 0, 0, 0),
		},
		Scope: int(netlink.SCOPE_LINK),
	})
	if err != nil {
		return nil, fmt.Errorf("error add vxlan addr: %v", err)
	}

	return vxLink, nil
}

func isVxlanConfigChanged(newLink, currentLink netlink.Link) bool {
	required := newLink.(*netlink.Vxlan)
	existing := currentLink.(*netlink.Vxlan)

	if required.VxlanId != existing.VxlanId {
		return true
	}
	if !required.Group.Equal(existing.Group) {
		return true
	}
	if !required.SrcAddr.Equal(existing.SrcAddr) {
		return true
	}
	if required.Port != existing.Port {
		return true
	}
	if required.MTU != existing.MTU {
		return true
	}
	return false
}

func defaultLinkTo(ip net.IP) (netlink.Link, error) {
	route, err := netlinkutil.RouteGet(ip)
	if err != nil || len(route) == 0 {
		return nil, fmt.Errorf("error get route to ip: %v", err)
	}
	link, err := netlinkutil.LinkByIndex(route[0].LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("error get route to gateway link: %v", err)
	}
	if vxLink, ok := link.(*netlink.Vxlan); ok {
		link, err = netlinkutil.LinkByIndex(vxLink.ParentIndex)
		if err != nil {
			return nil, fmt.Errorf("error get vxlan parent: %v", err)
		}
	}
	return link, nil
}
