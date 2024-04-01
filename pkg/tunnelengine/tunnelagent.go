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

package tunnelengine

import (
	"context"
	"fmt"
	"net"
	"reflect"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

type TunnelHandler struct {
	nodeName      string
	forwardNodeIP bool
	natTraversal  bool
	ownGateway    *v1beta1.Gateway

	ravenClient client.Client
	routeDriver routedriver.Driver
	vpnDriver   vpndriver.Driver

	nodeInfos       map[types.NodeName]*v1beta1.NodeInfo
	network         *types.Network
	lastSeenNetwork *types.Network
}

func NewTunnelHandler(nodeName string, forwardNodeIP bool, natTraversal bool, client client.Client, routeDriver routedriver.Driver, vpnDriver vpndriver.Driver) *TunnelHandler {
	return &TunnelHandler{
		nodeName:      nodeName,
		forwardNodeIP: forwardNodeIP,
		natTraversal:  natTraversal,
		ravenClient:   client,
		routeDriver:   routeDriver,
		vpnDriver:     vpnDriver,
	}
}

// sync syncs full state according to the gateway list.
func (c *TunnelHandler) Handler() error {
	var gws v1beta1.GatewayList
	err := c.ravenClient.List(context.Background(), &gws)
	if err != nil {
		return err
	}
	// As we are going to rebuild a full state, so cleanup before proceeding.
	c.network = &types.Network{
		LocalEndpoint:   nil,
		RemoteEndpoints: make(map[types.GatewayName]*types.Endpoint),
		LocalNodeInfo:   make(map[types.NodeName]*v1beta1.NodeInfo),
		RemoteNodeInfo:  make(map[types.NodeName]*v1beta1.NodeInfo),
	}
	c.nodeInfos = make(map[types.NodeName]*v1beta1.NodeInfo)

	c.ownGateway, err = utils.GetOwnGateway(c.ravenClient, c.nodeName)
	if err != nil {
		return fmt.Errorf("failed to get own gateway, error %s", err.Error())
	}

	for i := range gws.Items {
		// try to update public IP if empty.
		gw := &gws.Items[i]
		if ep := getTunnelActiveEndpoints(gw); ep != nil {
			if ep.PublicIP == "" {
				if err := c.configGatewayPublicIP(gw); err != nil {
					// output only error messages, without skipping
					klog.ErrorS(err, "error config gateway public ip", "gateway", klog.KObj(gw))
				}
			}
			if c.natTraversal && (ep.NATType == "" || ep.PublicPort == 0 && ep.NATType != utils.NATSymmetric) {
				if err := c.configGatewayStunInfo(gw); err != nil {
					klog.ErrorS(err, "error config gateway stun info", "gateway", klog.KObj(gw))
				}
			}
		}
		if !c.shouldHandleGateway(gw) {
			continue
		}
		c.syncNodeInfo(gw.Status.Nodes)
	}
	for i := range gws.Items {
		gw := &gws.Items[i]
		if !c.shouldHandleGateway(gw) {
			continue
		}
		c.syncGateway(gw)
	}
	if reflect.DeepEqual(c.network, c.lastSeenNetwork) {
		klog.Info("network not changed, skip to process")
		return nil
	}
	nw := c.network.Copy()
	klog.InfoS("applying network", "localEndpoint", nw.LocalEndpoint, "remoteEndpoint", nw.RemoteEndpoints)
	err = c.vpnDriver.Apply(nw, c.routeDriver.MTU)
	if err != nil {
		return err
	}
	err = c.routeDriver.Apply(nw, c.vpnDriver.MTU)
	if err != nil {
		return err
	}

	// Only update lastSeenNetwork when all operations succeeded.
	c.lastSeenNetwork = c.network
	return nil
}

func (c *TunnelHandler) syncNodeInfo(nodes []v1beta1.NodeInfo) {
	for _, v := range nodes {
		c.nodeInfos[types.NodeName(v.NodeName)] = v.DeepCopy()
	}
}

func (c *TunnelHandler) appendNodeIP(gw *v1beta1.Gateway) {
	for i := range gw.Status.Nodes {
		nodeSubnet := net.IPNet{
			IP:   net.ParseIP(gw.Status.Nodes[i].PrivateIP),
			Mask: []byte{0xff, 0xff, 0xff, 0xff},
		}
		gw.Status.Nodes[i].Subnets = append(gw.Status.Nodes[i].Subnets, nodeSubnet.String())
	}
}

func (c *TunnelHandler) getMergedSubnets(nodeInfo []v1beta1.NodeInfo) []string {
	subnets := make([]string, 0)
	for _, n := range nodeInfo {
		subnets = append(subnets, n.Subnets...)
	}
	subnets, _ = cidrman.MergeCIDRs(subnets)
	return subnets
}

func (c *TunnelHandler) syncGateway(gw *v1beta1.Gateway) {
	if c.forwardNodeIP {
		c.appendNodeIP(gw)
	}
	aep := getTunnelActiveEndpoints(gw)
	subnets := c.getMergedSubnets(gw.Status.Nodes)
	cfg := make(map[string]string)
	for k := range aep.Config {
		cfg[k] = aep.Config[k]
	}
	var nodeInfo *v1beta1.NodeInfo
	if nodeInfo = c.nodeInfos[types.NodeName(aep.NodeName)]; nodeInfo == nil {
		klog.Errorf("node %s is found in Endpoint but not existed in NodeInfo", aep.NodeName)
		return
	}
	ep := &types.Endpoint{
		GatewayName: types.GatewayName(gw.Name),
		NodeName:    types.NodeName(aep.NodeName),
		Subnets:     subnets,
		PrivateIP:   nodeInfo.PrivateIP,
		PublicPort:  aep.PublicPort,
		PublicIP:    aep.PublicIP,
		UnderNAT:    aep.UnderNAT,
		NATType:     aep.NATType,
		Config:      cfg,
	}
	var isLocalGateway bool
	defer func() {
		for _, v := range gw.Status.Nodes {
			if isLocalGateway {
				c.network.LocalNodeInfo[types.NodeName(v.NodeName)] = v.DeepCopy()
			} else {
				c.network.RemoteNodeInfo[types.NodeName(v.NodeName)] = v.DeepCopy()
			}
		}
	}()

	if gw.Name == c.ownGateway.Name {
		c.network.LocalEndpoint = ep
		isLocalGateway = true
	} else {
		c.network.RemoteEndpoints[types.GatewayName(gw.Name)] = ep
	}

}

func (c *TunnelHandler) shouldHandleGateway(gateway *v1beta1.Gateway) bool {
	ep := getTunnelActiveEndpoints(gateway)
	if ep == nil {
		klog.InfoS("no active endpoint , waiting for sync", "gateway", klog.KObj(gateway))
		return false
	}
	if c.natTraversal {
		if ep.NATType == "" {
			klog.InfoS("no nat type for gateway, waiting for sync", "gateway", klog.KObj(gateway))
			return false
		}
		if ep.NATType != utils.NATSymmetric && ep.PublicPort == 0 {
			klog.InfoS("no public port for gateway, waiting for sync", "gateway", klog.KObj(gateway))
			return false
		}
	}
	if c.ownGateway == nil {
		klog.InfoS(fmt.Sprintf("no own gateway for node %s, skip it", c.nodeName), "gateway", klog.KObj(gateway))
		return false
	}
	return true
}

func (c *TunnelHandler) configGatewayPublicIP(gateway *v1beta1.Gateway) error {
	if getTunnelActiveEndpoints(gateway).NodeName != c.nodeName {
		return nil
	}
	var publicIP string
	var err error
	if gateway.Spec.ExposeType == v1beta1.ExposeTypeLoadBalancer {
		publicIP, err = c.getLoadBalancerPublicIP(gateway.GetName())
		if err != nil {
			return err
		}
	} else {
		publicIP, err = utils.GetPublicIP()
		if err != nil {
			return err
		}
	}

	// retry to update public ip of localGateway
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get localGateway from api server
		var apiGw v1beta1.Gateway
		err := c.ravenClient.Get(context.Background(), client.ObjectKey{
			Name: gateway.Name,
		}, &apiGw)
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == c.nodeName && v.Type == v1beta1.Tunnel {
				apiGw.Spec.Endpoints[k].PublicIP = publicIP
				err = c.ravenClient.Update(context.Background(), &apiGw)
				return err
			}
		}
		return nil
	})
	return err
}

func (c *TunnelHandler) configGatewayStunInfo(gateway *v1beta1.Gateway) error {
	if getTunnelActiveEndpoints(gateway).NodeName != c.nodeName {
		return nil
	}

	natType, err := utils.GetNATType()
	if err != nil {
		return err
	}

	var publicPort int
	if natType != utils.NATSymmetric {
		publicPort, err = utils.GetPublicPort()
		if err != nil {
			return err
		}
	}

	// retry to update nat type of localGateway
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get localGateway from api server
		var apiGw v1beta1.Gateway
		err := c.ravenClient.Get(context.Background(), client.ObjectKey{
			Name: gateway.Name,
		}, &apiGw)
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == c.nodeName {
				apiGw.Spec.Endpoints[k].NATType = natType
				if natType != utils.NATSymmetric {
					apiGw.Spec.Endpoints[k].PublicPort = publicPort
				}
				err = c.ravenClient.Update(context.Background(), &apiGw)
				return err
			}
		}
		return nil
	})
	return err
}

func (c *TunnelHandler) getLoadBalancerPublicIP(gwName string) (string, error) {
	var svcList v1.ServiceList
	err := c.ravenClient.List(context.TODO(), &svcList, &client.ListOptions{
		LabelSelector: labels.Set{
			raven.LabelCurrentGateway:          gwName,
			utils.LabelCurrentGatewayType:      v1beta1.Tunnel,
			utils.LabelCurrentGatewayEndpoints: c.nodeName,
		}.AsSelector(),
	})
	if err != nil {
		return "", err
	}
	if len(svcList.Items) == 0 {
		return "", apierrors.NewNotFound(v1.Resource("service"), fmt.Sprintf("%s-%s", "x-raven-proxy-svc-%s", gwName))
	}
	svc := svcList.Items[0]
	if svc.Status.LoadBalancer.Ingress == nil && len(svc.Status.LoadBalancer.Ingress) == 0 {
		return "", apierrors.NewNotFound(v1.Resource("service"), svc.GetName())
	}
	publicIP := svc.Status.LoadBalancer.Ingress[0].IP
	if publicIP == "" {
		return "", apierrors.NewServiceUnavailable(fmt.Sprintf("service %s/%s has no public ingress", svc.GetNamespace(), svc.GetName()))
	}
	return publicIP, nil
}

func getTunnelActiveEndpoints(gw *v1beta1.Gateway) *v1beta1.Endpoint {
	for _, aep := range gw.Status.ActiveEndpoints {
		if aep.Type == v1beta1.Tunnel {
			return aep.DeepCopy()
		}
	}
	return nil
}
