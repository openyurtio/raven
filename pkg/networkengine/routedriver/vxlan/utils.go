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
	"syscall"

	"github.com/vdobler/ht/errorlist"
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
	if len(required.Group) > 0 && len(existing.Group) > 0 && !required.Group.Equal(existing.Group) {
		return true
	}
	if len(required.SrcAddr) > 0 && len(existing.SrcAddr) > 0 && !required.SrcAddr.Equal(existing.SrcAddr) {
		return true
	}
	if required.Port > 0 && existing.Port > 0 && required.Port != existing.Port {
		return true
	}
	return false
}

func listRulesOnNode() (map[string]*netlink.Rule, error) {
	rulesOnNode := make(map[string]*netlink.Rule)

	rules, err := netlinkutil.RuleListFiltered(netlink.FAMILY_V4,
		&netlink.Rule{Table: routeTableID},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	for k, v := range rules {
		rulesOnNode[ruleKey(&v)] = &rules[k]
	}

	return rulesOnNode, nil
}

func listRoutesOnNode() (map[string]*netlink.Route, error) {
	routes, err := netlinkutil.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Table: routeTableID},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	ro := make(map[string]*netlink.Route)
	for k, v := range routes {
		ro[routeKey(&v)] = &routes[k]
	}
	return ro, nil
}

func listFDBsOnNode(link netlink.Link) (map[string]*netlink.Neigh, error) {
	fdbsOnNode := make(map[string]*netlink.Neigh)
	neighs, err := netlinkutil.NeighList(link.Attrs().Index, syscall.AF_BRIDGE)
	if err != nil {
		return nil, err
	}
	for k, v := range neighs {
		if v.HardwareAddr.String() == allZeroMAC.String() {
			fdbsOnNode[v.IP.String()] = &neighs[k]
		}
	}
	return fdbsOnNode, nil
}

func applyRules(current, desired map[string]*netlink.Rule) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying rules", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range desired {
		_, ok := current[k]
		if !ok {
			klog.InfoS("adding rule", "src", v.Src, "lookup", v.Table)
			err = netlinkutil.RuleAdd(v)
			errList = errList.Append(err)
			continue
		}
		delete(current, k)
	}
	// remove unwanted rules
	for _, v := range current {
		klog.InfoS("deleting rule", "src", v.Src, "lookup", v.Table)
		err = netlinkutil.RuleDel(v)
		errList = errList.Append(err)
	}
	return errList.AsError()
}

func applyRoutes(current, desired map[string]*netlink.Route) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying routes", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range desired {
		ro, ok := current[k]
		if !ok {
			klog.InfoS("adding route", "dst", v.Dst, "via", v.Gw, "src", v.Src, "table", v.Table)
			err = netlinkutil.RouteAdd(v)
			errList = errList.Append(err)
			continue
		}
		delete(current, k)
		if !routeEqual(*ro, *v) {
			klog.InfoS("replacing route", "dst", v.Dst, "via", v.Gw, "src", v.Src, "table", v.Table)
			err = netlinkutil.RouteReplace(v)
			errList = errList.Append(err)
		}
	}
	// remove unwanted routes
	for _, v := range current {
		klog.InfoS("deleting route", "dst", v.Dst.String(), "via", v.Gw.String())
		err = netlinkutil.RouteDel(v)
		errList = errList.Append(err)
	}
	return errList.AsError()
}

func applyFDBs(current, desired map[string]*netlink.Neigh) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying FDBs", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range desired {
		_, ok := current[k]
		if !ok {
			klog.InfoS("adding FDB", "dst", v.IP, "mac", v.HardwareAddr)
			err = netlinkutil.NeighAppend(v)
			errList = errList.Append(err)
			continue
		}
		delete(current, k)
	}
	// remove unwanted fdb entries
	for _, v := range current {
		klog.InfoS("deleting FDB", "dst", v.IP, "mac", v.HardwareAddr)
		err = netlinkutil.NeighDel(v)
		errList = errList.Append(err)
	}
	return errList.AsError()
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
