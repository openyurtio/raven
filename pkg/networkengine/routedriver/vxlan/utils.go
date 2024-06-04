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
	"golang.org/x/sys/unix"
	"k8s.io/klog/v2"

	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
)

const (
	resetMark = 0x0
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

	// tc qdisc add dev raven0 clsact
	err = ensureClsActQdsic(vxLink)
	if err != nil {
		return nil, fmt.Errorf("error ensure qdisc: %v", err)
	}

	// tc filter add dev raven0 egress protocol ip prio 1 matchall action skbedit mark 0x0
	err = ensureSkbEditFilter(vxLink)
	if err != nil {
		return nil, fmt.Errorf("error ensure filter: %v", err)
	}
	return vxLink, nil
}

func ensureClsActQdsic(link netlink.Link) error {
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	for _, q := range qds {
		if q.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_CLSACT,
			Handle:    netlink.HANDLE_CLSACT & 0xffff0000,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscReplace(qdisc); err != nil {
		return fmt.Errorf("replace clsact qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	return nil
}

func deleteClsActQdsic(link netlink.Link) error {
	qds, err := netlink.QdiscList(link)
	if err != nil {
		return fmt.Errorf("list qdisc for dev %s error, %w", link.Attrs().Name, err)
	}
	var qdisc netlink.Qdisc
	for _, q := range qds {
		if q.Type() == "clsact" {
			qdisc = q
			break
		}
	}
	if qdisc != nil {
		err = netlink.QdiscDel(qdisc)
		if err != nil {
			return fmt.Errorf("error delete qdisc: %s", err)
		}
	}
	return nil
}

func ensureSkbEditFilter(link netlink.Link) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("list egress filter for %s error, %w", link.Attrs().Name, err)
	}

	for _, f := range filters {
		if isMatch(f) {
			return nil
		}
	}

	skbedit := netlink.NewSkbEditAction()
	mark := uint32(resetMark)
	skbedit.Mark = &mark
	match := &netlink.MatchAll{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    netlink.HANDLE_MIN_EGRESS,
			Priority:  20000,
			Protocol:  unix.ETH_P_IP,
		},
		Actions: []netlink.Action{
			skbedit,
		},
	}

	return netlink.FilterReplace(match)
}

func deleteSkbEditFilter(link netlink.Link) error {
	filters, err := netlink.FilterList(link, netlink.HANDLE_MIN_EGRESS)
	if err != nil {
		return fmt.Errorf("list egress filter for %s error, %w", link.Attrs().Name, err)
	}
	for _, f := range filters {
		_ = netlink.FilterDel(f)
	}
	return nil
}

func isMatch(filter netlink.Filter) bool {
	match, ok := filter.(*netlink.MatchAll)
	if !ok {
		return false
	}
	if match.Parent != netlink.HANDLE_MIN_EGRESS || match.Protocol != unix.ETH_P_IP {
		return false
	}
	if len(match.Actions) != 1 {
		return false
	}
	action, ok := match.Actions[0].(*netlink.SkbEditAction)
	if !ok {
		return false
	}
	if *action.Mark != resetMark {
		return false
	}
	return true
}

func deleteVxlanLink(linkName string) error {
	vxLink, err := netlink.LinkByName(linkName)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			return nil
		}
		return fmt.Errorf("error finding vxlan link: %s", err)
	}

	err = deleteSkbEditFilter(vxLink)
	if err != nil {
		return fmt.Errorf("error deleting skbedit filter: %s", err)
	}
	err = deleteClsActQdsic(vxLink)
	if err != nil {
		return fmt.Errorf("error deleting clsact qdsic: %s", err)
	}
	err = netlink.LinkDel(vxLink)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); !ok {
			return fmt.Errorf("error deleting vxlan link: %s", err)
		}
	}
	return nil
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
