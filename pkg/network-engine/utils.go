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

package network_engine

import (
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/vdobler/ht/errorlist"
	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/types"
)

const (
	routeTableId = 9027 // yurt
	rulePriority = 100

	vxlanLinkName = "cross-edge"
	vxlanEncapLen = 50
	vxlanID       = 200
	vxlanPort     = 8472
	vxlanGwPrefix = 240
)

func ensureVxlanLink(vxlan netlink.Vxlan, cniIP net.IP) (netlink.Link, error) {
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
				return nil, fmt.Errorf("err del existing vxlan: %v", err)
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
	vxAddr, err := vxlanGwIP(cniIP)
	if err != nil {
		return nil, err
	}
	// add address
	err = netlink.AddrReplace(vxLink, &netlink.Addr{
		IPNet: vxAddr,
		Scope: int(netlink.SCOPE_LINK),
	})
	if err != nil {
		return nil, fmt.Errorf("error add vxlan addr: %v", err)
	}

	return vxLink, nil
}

func addFDB(link netlink.Link, ip net.IP, hwAddr string) error {
	mac, err := net.ParseMAC(hwAddr)
	if err != nil {
		return fmt.Errorf("error parse mac addr: %v", err)
	}
	err = netlink.NeighAppend(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT | netlink.NUD_NOARP,
		Type:         netlink.NDA_DST,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           ip,
		HardwareAddr: mac,
	})
	if err != nil {
		return fmt.Errorf("error add fdb entry: %v", err)
	}
	return nil
}

func deleteFDB(link netlink.Link, ip net.IP, hwAddr string) error {
	mac, err := net.ParseMAC(hwAddr)
	if err != nil {
		return fmt.Errorf("error parse mac addr: %v", err)
	}
	err = netlink.NeighDel(&netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		State:        netlink.NUD_PERMANENT | netlink.NUD_NOARP,
		Type:         netlink.NDA_DST,
		Family:       syscall.AF_BRIDGE,
		Flags:        netlink.NTF_SELF,
		IP:           ip,
		HardwareAddr: mac,
	})
	if err != nil {
		return fmt.Errorf("error del fdb entry: %v", err)
	}
	return nil
}

func ensureFDB(link netlink.Link, requiredIPs map[string]net.IP, existingIPs map[string]net.IP) (map[string]net.IP, error) {

	remoteIPs := make(map[string]net.IP)
	errList := errorlist.List{}
del:
	for key, existing := range existingIPs {
		if required, ok := requiredIPs[key]; ok && required.Equal(existing) {
			remoteIPs[key] = existing
			continue del
		}
		if err := deleteFDB(link, existing, "00:00:00:00:00:00"); err != nil {
			remoteIPs[key] = existing
			errList = errList.Append(fmt.Errorf("fail to delete fdb entry: %v", err))
		}
	}
add:
	for key, required := range requiredIPs {
		if existing, ok := existingIPs[key]; ok && existing.Equal(required) {
			continue add
		}
		if err := addFDB(link, required, "00:00:00:00:00:00"); err != nil {
			errList = errList.Append(fmt.Errorf("fail to add fdb entry: %v", err))
		} else {
			remoteIPs[key] = required
		}
	}
	return remoteIPs, errList.AsError()
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

func vxlanGwIP(cniIP net.IP) (*net.IPNet, error) {
	if cniIP == nil || cniIP.To4() == nil {
		return nil, fmt.Errorf("invalid cniIP %v", cniIP)
	}
	gwIP := make(net.IP, len(cniIP))
	copy(gwIP, cniIP)
	gwIP[0] = vxlanGwPrefix
	return &net.IPNet{
		IP:   gwIP,
		Mask: net.IPv4Mask(0xff, 0, 0, 0),
	}, nil
}

func defaultLinkTo(ip net.IP) (netlink.Link, error) {
	route, err := netlink.RouteGet(ip)
	if err != nil || len(route) == 0 {
		return nil, fmt.Errorf("error get route to gateway ip: %v", err)
	}
	link, err := netlink.LinkByIndex(route[0].LinkIndex)
	if err != nil {
		return nil, fmt.Errorf("error get route to gateway link: %v", err)
	}
	if vxLink, ok := link.(*netlink.Vxlan); ok {
		link, err = netlink.LinkByIndex(vxLink.ParentIndex)
		if err != nil {
			return nil, fmt.Errorf("error get vxlan parent: %v", err)
		}
	}
	return link, nil
}

func ensurePolicyTable() error {
	ruleList, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		return fmt.Errorf("error list exist rule, err: %v", err)
	}
	for _, rule := range ruleList {
		if rule.Table == routeTableId {
			if rulePriority == rule.Priority {
				return nil
			} else {
				err = netlink.RuleDel(&rule)
				if err != nil {
					return fmt.Errorf("error delete conflict rule, err: %v", err)
				}
			}
		}
	}
	crossEdgeRule := netlink.NewRule()
	crossEdgeRule.Table = routeTableId
	crossEdgeRule.Priority = rulePriority
	crossEdgeRule.Family = netlink.FAMILY_V4
	if err = netlink.RuleAdd(crossEdgeRule); err != nil {
		return fmt.Errorf("error add rule, err: %v", err)
	}
	return nil
}

func deletePolicyTable() error {
	crossEdgeRule := netlink.NewRule()
	crossEdgeRule.Table = routeTableId
	crossEdgeRule.Priority = rulePriority
	crossEdgeRule.Family = netlink.FAMILY_V4
	if err := netlink.RuleDel(crossEdgeRule); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("error remote policy rule: %v", err)
	}
	return nil
}

func ensureRoutes(routes map[string]types.Route, tableID int, link netlink.Link) error {
	existRoutes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("error get exist routes for table %d, err: %v", tableID, err)
	}

	errList := errorlist.List{}

	existing := make(map[string]netlink.Route)
	for _, r := range existRoutes {
		existing[r.Dst.String()] = r
	}

del:
	for key, routeInTable := range existing {
		if _, ok := routes[key]; ok {
			continue del
		}
		err = netlink.RouteDel(&routeInTable)
		if err != nil {
			errList = errList.Append(fmt.Errorf("error delete route %+v in table: %v", routeInTable, err))
		}
	}
add:
	for key, routeExpect := range routes {
		if _, ok := existing[key]; ok {
			continue add
		}
		err = netlink.RouteAdd(&netlink.Route{
			LinkIndex: link.Attrs().Index,
			Scope:     netlink.SCOPE_UNIVERSE,
			Dst:       routeExpect.Dst,
			Gw:        routeExpect.Gateway,
			Table:     tableID,
			Flags:     int(netlink.FLAG_ONLINK),
		})
		if err != nil {
			errList = errList.Append(fmt.Errorf("error add route %+v in table: %v", routeExpect, err))
		}
	}
	return errList.AsError()
}
