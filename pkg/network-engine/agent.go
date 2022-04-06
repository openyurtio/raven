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
	"reflect"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/pkg/types"
)

type vxlanAgent struct {
	gatewayIPs   []net.IP
	localCniIP   net.IP
	remoteCniIPs map[string]net.IP
}

func (agent *vxlanAgent) Init(localCniIP net.IP, localGatewayPublicIP net.IP) {
	agent.gatewayIPs = make([]net.IP, 0)
	agent.localCniIP = localCniIP
	agent.remoteCniIPs = make(map[string]net.IP)
}

func (agent *vxlanAgent) ConnectToGateway(gateway *types.Gateway) error {
	var vxlan netlink.Vxlan
	if agent.localCniIP.Equal(gateway.GatewayIP) {
		keySet := reflect.ValueOf(gateway.RemoteIPs).MapKeys()
		if len(keySet) == 0 {
			agent.Cleanup()
			return nil
		}

		link, err := defaultLinkTo(gateway.RemoteIPs[keySet[0].String()])
		if err != nil {
			return err
		}
		vxlan = netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:  vxlanLinkName,
				MTU:   link.Attrs().MTU - vxlanEncapLen,
				Flags: net.FlagUp,
			},
			VxlanId:      vxlanID,
			VtepDevIndex: 0,
			Age:          300,
			Port:         vxlanPort,
		}

	} else {
		link, err := defaultLinkTo(gateway.GatewayIP)
		if err != nil {
			return err
		}

		vxlan = netlink.Vxlan{
			LinkAttrs: netlink.LinkAttrs{
				Name:  vxlanLinkName,
				MTU:   link.Attrs().MTU - vxlanEncapLen,
				Flags: net.FlagUp,
			},
			VxlanId:      vxlanID,
			Group:        gateway.GatewayIP,
			VtepDevIndex: 0,
			Age:          300,
			Port:         vxlanPort,
		}

	}
	vxLink, err := ensureVxlanLink(vxlan, agent.localCniIP)
	if err != nil {
		return err
	}

	agent.remoteCniIPs, err = ensureFDB(vxLink, gateway.RemoteIPs, agent.remoteCniIPs)
	if err != nil {
		return err
	}

	err = ensurePolicyTable()
	if err != nil {
		return err
	}

	err = ensureRoutes(gateway.Routes, routeTableId, vxLink)
	if err != nil {
		return err
	}
	agent.gatewayIPs = []net.IP{gateway.GatewayIP}
	return nil
}

func (agent *vxlanAgent) MTU() (int, error) {
	if len(agent.gatewayIPs) < 1 {
		return 0, fmt.Errorf("not connected to gateway")
	}
	link, err := netlink.LinkByName(vxlanLinkName)
	if err != nil {
		return 0, err
	}
	return link.Attrs().MTU, nil
}

func (agent *vxlanAgent) Cleanup() {
	vxLink, err := netlink.LinkByName(vxlanLinkName)
	if err == nil {
		for _, remote := range agent.remoteCniIPs {
			err = deleteFDB(vxLink, remote, "00:00:00:00:00:00")
			if err != nil {
				klog.Errorf("error delete fdb for vxlan link: %v", err)
			}
		}
		agent.remoteCniIPs = make(map[string]net.IP)
		// delete vxlan link
		if err := netlink.LinkDel(vxLink); err != nil {
			klog.Errorf("error delete vxlan link: %v", err)
		}
	} else if _, ok := err.(netlink.LinkNotFoundError); !ok {
		klog.Errorf("error get vxlan link: %v", err)
	}
	// delete ip rule
	if err := deletePolicyTable(); err != nil {
		klog.Errorf("error delete policy route table: %v", err)
	}
	agent.gatewayIPs = make([]net.IP, 0)
}
