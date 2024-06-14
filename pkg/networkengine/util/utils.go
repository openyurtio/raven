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
	"fmt"
	"syscall"

	"github.com/vdobler/ht/errorlist"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	ipsetutil "github.com/openyurtio/raven/pkg/networkengine/util/ipset"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
)

func NewRavenRule(rulePriority int, routeTableID int) *netlink.Rule {
	rule := netlink.NewRule()
	rule.Priority = rulePriority
	rule.Table = routeTableID
	rule.Family = netlink.FAMILY_V4
	return rule
}

func RouteKey(route *netlink.Route) string {
	return route.String()
}

func NeighKey(neigh *netlink.Neigh) string { return neigh.String() }

func RuleKey(rule *netlink.Rule) string {
	return rule.String()
}

func ListRulesOnNode(routeTableID int) (map[string]*netlink.Rule, error) {
	rulesOnNode := make(map[string]*netlink.Rule)

	rules, err := netlinkutil.RuleListFiltered(netlink.FAMILY_V4,
		&netlink.Rule{Table: routeTableID},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	for k, v := range rules {
		rulesOnNode[RuleKey(&v)] = &rules[k]
	}

	return rulesOnNode, nil
}

func ListRoutesOnNode(routeTableID int) (map[string]*netlink.Route, error) {
	routes, err := netlinkutil.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Table: routeTableID},
		netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}
	ro := make(map[string]*netlink.Route)
	for k, v := range routes {
		ro[RouteKey(&v)] = &routes[k]
	}
	return ro, nil
}

func ListIPSetOnNode(set ipsetutil.IPSetInterface) (map[string]*netlink.IPSetEntry, error) {
	info, err := set.List()
	if err != nil {
		return nil, err
	}
	ro := make(map[string]*netlink.IPSetEntry)
	for i := range info.Entries {
		ro[set.Key(&info.Entries[i])] = &info.Entries[i]
	}
	return ro, nil
}

func ApplyRules(current, desired map[string]*netlink.Rule) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying rules", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	// deleted unwanted ip rules
	for k, v := range current {
		_, ok := desired[k]
		if !ok {
			klog.InfoS("deleting rule", "src", v.Src, "lookup", v.Table)
			err = netlinkutil.RuleDel(v)
			errList = errList.Append(err)
		}
	}
	// add expect ip rules
	for k, v := range desired {
		_, ok := current[k]
		if ok {
			continue
		}
		klog.InfoS("adding rule", "src", v.Src, "lookup", v.Table)
		err = netlinkutil.RuleAdd(v)
		errList = errList.Append(err)
	}

	return errList.AsError()
}

func ApplyRoutes(current, desired map[string]*netlink.Route) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying routes", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range current {
		ro, ok := desired[k]
		if !ok {
			// remove unwanted routes
			klog.InfoS("deleting route", "dst", v.Dst.String(), "via", v.Gw.String())
			err = netlinkutil.RouteDel(v)
			errList = errList.Append(err)
		} else {
			// replace unequal routes
			if !ro.Equal(*v) {
				klog.InfoS("replacing route", "dst", v.Dst, "via", v.Gw, "src", v.Src, "table", v.Table)
				err = netlinkutil.RouteReplace(v)
				errList = errList.Append(err)
			}
			delete(desired, k)
		}
	}
	// add new routes
	for _, v := range desired {
		klog.InfoS("adding route", "dst", v.Dst, "via", v.Gw, "src", v.Src, "table", v.Table)
		err = netlinkutil.RouteAdd(v)
		errList = errList.Append(err)
	}
	return errList.AsError()
}

func ApplyIPSet(set ipsetutil.IPSetInterface, current, desired map[string]*netlink.IPSetEntry) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying ipset entry", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	// delete unwanted ipset entries
	for k, v := range current {
		_, ok := desired[k]
		if !ok {
			klog.InfoS("deleting ipset entry", "entry", k)
			err = set.Del(v)
			errList = errList.Append(err)
		}
	}
	// add wanted ipset entries
	for k, v := range desired {
		klog.InfoS("adding entry", "entry", k)
		err = set.Add(v)
		errList = errList.Append(err)
	}
	return errList.AsError()
}

func ListFDBsOnNode(link netlink.Link) (map[string]*netlink.Neigh, error) {
	fdbsOnNode := make(map[string]*netlink.Neigh)
	neighs, err := netlinkutil.NeighList(link.Attrs().Index, syscall.AF_BRIDGE)
	if err != nil {
		return nil, err
	}
	for k, v := range neighs {
		fdbsOnNode[v.String()] = &neighs[k]
	}
	return fdbsOnNode, nil
}

func ListARPsOnNode(link netlink.Link) (map[string]*netlink.Neigh, error) {
	arpsOnNode := make(map[string]*netlink.Neigh)
	neighs, err := netlinkutil.NeighList(link.Attrs().Index, syscall.AF_INET)
	if err != nil {
		return nil, err
	}
	for k, v := range neighs {
		arpsOnNode[v.String()] = &neighs[k]
	}
	return arpsOnNode, nil
}

func ApplyFDBs(current, desired map[string]*netlink.Neigh) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying FDBs", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range current {
		ipNeigh, ok := desired[k]
		if !ok {
			klog.InfoS("deleting FDB", "dst", v.IP, "mac", v.HardwareAddr)
			err = netlinkutil.NeighDel(v)
			errList = errList.Append(err)
		} else {
			klog.InfoS("replace FDB", "dst", v.IP, "mac", v.HardwareAddr)
			err = netlinkutil.NeighReplace(ipNeigh)
			errList = errList.Append(err)
		}
		delete(desired, k)
	}

	for _, v := range desired {
		klog.InfoS("adding FDB", "dst", v.IP, "mac", v.HardwareAddr)
		err = netlinkutil.NeighAdd(v)
		errList = errList.Append(err)
	}

	return errList.AsError()
}

func ApplyARPs(current, desired map[string]*netlink.Neigh) (err error) {
	if klog.V(5).Enabled() {
		klog.InfoS("applying ARPs", "current", current, "desired", desired)
	}
	errList := errorlist.List{}
	for k, v := range current {
		ipNeigh, ok := desired[k]
		if !ok {
			klog.InfoS("deleting ARP", "dst", v.IP, "mac", v.HardwareAddr)
			err = netlinkutil.NeighDel(v)
			errList = errList.Append(err)
		} else {
			klog.InfoS("replace ARP", "dst", v.IP, "mac", v.HardwareAddr)
			err = netlinkutil.NeighReplace(ipNeigh)
			errList = errList.Append(err)
		}
		delete(desired, k)
	}

	for _, v := range desired {
		klog.InfoS("adding ARP", "dst", v.IP, "mac", v.HardwareAddr)
		err = netlinkutil.NeighAdd(v)
		errList = errList.Append(err)
	}

	return errList.AsError()
}

func CleanRoutesOnNode(routeTableID int) error {
	errList := errorlist.List{}
	routes, err := ListRoutesOnNode(routeTableID)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error listing routes: %s", err))
	}
	for _, v := range routes {
		err = netlinkutil.RouteDel(v)
		if err != nil {
			errList = errList.Append(fmt.Errorf("error deleting routes: %s", err))
		}
	}
	return errList.AsError()
}

func CleanRulesOnNode(routeTableID int) error {
	errList := errorlist.List{}
	rules, err := ListRulesOnNode(routeTableID)
	if err != nil {
		errList = errList.Append(fmt.Errorf("error listing rules: %s", err))
	}
	for _, v := range rules {
		err = netlinkutil.RuleDel(v)
		if err != nil {
			errList = errList.Append(fmt.Errorf("error deleting rules: %s", err))
		}
	}
	return errList.AsError()
}
