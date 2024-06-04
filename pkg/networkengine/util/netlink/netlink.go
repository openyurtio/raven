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

package netlinkutil

import (
	"net"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

// The following private methods wrap corresponding netlink methods and add logging.
// These variables are exposed for testing only.
var (
	RouteDel          = routeDel
	RouteReplace      = routeReplace
	RouteAdd          = routeAdd
	RouteListFiltered = routeListFiltered
	RouteList         = routeList
	RouteGet          = routeGet

	RuleListFiltered = ruleListFiltered
	RuleAdd          = ruleAdd
	RuleDel          = ruleDel

	XfrmPolicyFlush = xfrmPolicyFlush
	XfrmStateFlush  = xfrmStateFlush

	NeighAdd     = neighAdd
	NeighReplace = neighReplace
	NeighList    = neighList
	NeighDel     = neighDel

	LinkByName  = linkByName
	LinkByIndex = linkByIndex
)

func routeDel(route *netlink.Route) (err error) {
	err = netlink.RouteDel(route)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RouteDel")
		return
	}
	klog.V(5).InfoS("netlink.RouteDel succeeded")
	return
}

func routeReplace(route *netlink.Route) (err error) {
	err = netlink.RouteReplace(route)
	if err != nil {
		klog.ErrorS(err, "error on netlink.routeReplace")
		return
	}
	klog.V(5).InfoS("netlink.routeReplace succeeded")
	return
}

func routeAdd(route *netlink.Route) (err error) {
	err = netlink.RouteAdd(route)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RouteAdd")
		return
	}
	klog.V(5).InfoS("netlink.RouteAdd succeeded")
	return
}

func routeListFiltered(family int, filter *netlink.Route, filterMask uint64) (nr []netlink.Route, err error) {
	nr, err = netlink.RouteListFiltered(family, filter, filterMask)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RouteListFiltered")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.RouteListFiltered succeeded", "result", nr)
	}
	return
}

func routeList(link netlink.Link, family int) (nr []netlink.Route, err error) {
	nr, err = netlink.RouteList(link, family)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RouteList")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.RouteList succeeded", "result", nr)
	}
	return
}

func routeGet(ip net.IP) (nr []netlink.Route, err error) {
	nr, err = netlink.RouteGet(ip)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RouteGet")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.RouteGet succeeded", "result", nr)
	}
	return
}

func xfrmPolicyFlush() (err error) {
	err = netlink.XfrmPolicyFlush()
	if err != nil {
		klog.ErrorS(err, "error on netlink.XfrmPolicyFlush")
		return
	}
	klog.V(5).InfoS("netlink.XfrmPolicyFlush succeeded")
	return nil
}

func xfrmStateFlush() (err error) {
	err = netlink.XfrmStateFlush(0)
	if err != nil {
		klog.ErrorS(err, "error on netlink.XfrmStateFlush")
		return
	}
	klog.V(5).InfoS("netlink.XfrmStateFlush succeeded")
	return nil
}

func ruleListFiltered(family int, filter *netlink.Rule, filterMask uint64) (rules []netlink.Rule, err error) {
	rules, err = netlink.RuleListFiltered(family, filter, filterMask)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RuleListFiltered")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.RuleListFiltered succeeded", "result", rules)
	}
	return
}

func ruleAdd(rule *netlink.Rule) (err error) {
	err = netlink.RuleAdd(rule)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RuleAdd")
		return
	}
	klog.V(5).InfoS("netlink.RuleAdd succeeded")
	return
}

func ruleDel(rule *netlink.Rule) (err error) {
	err = netlink.RuleDel(rule)
	if err != nil {
		klog.ErrorS(err, "error on netlink.RuleDel")
		return
	}
	klog.V(5).InfoS("netlink.RuleDel succeeded")
	return
}

func neighAdd(neigh *netlink.Neigh) (err error) {
	err = netlink.NeighAdd(neigh)
	if err != nil {
		klog.ErrorS(err, "error on netlink.NeighSet")
		return
	}
	klog.V(5).InfoS("netlink.NeighAdd succeeded")
	return
}

func neighReplace(neigh *netlink.Neigh) (err error) {
	err = netlink.NeighSet(neigh)
	if err != nil {
		klog.ErrorS(err, "error on netlink.NeighSet")
		return
	}
	klog.V(5).InfoS("netlink.NeighSet succeeded")
	return
}

func neighList(linkIndex int, family int) (neighsList []netlink.Neigh, err error) {
	neighsList, err = netlink.NeighList(linkIndex, family)
	if err != nil {
		klog.ErrorS(err, "error on netlink.NeighList")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.NeighList succeeded", "result", neighsList)
	}
	return
}

func neighDel(neigh *netlink.Neigh) (err error) {
	err = netlink.NeighDel(neigh)
	if err != nil {
		klog.ErrorS(err, "error on netlink.NeighDel")
		return
	}
	klog.V(5).InfoS("netlink.NeighDel succeeded")
	return
}

func linkByIndex(index int) (l netlink.Link, err error) {
	l, err = netlink.LinkByIndex(index)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return
	}
	if err != nil {
		klog.ErrorS(err, "error on netlink.LinkByIndex")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.LinkByIndex succeeded", "result", l)
	}
	return
}

func linkByName(name string) (l netlink.Link, err error) {
	l, err = netlink.LinkByName(name)
	if _, ok := err.(netlink.LinkNotFoundError); ok {
		return
	}
	if err != nil {
		klog.ErrorS(err, "error on netlink.linkByName")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.LinkByName succeeded", "result", l)
	}
	return
}
