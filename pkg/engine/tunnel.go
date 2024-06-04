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

package engine

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/EvilSuperstars/go-cidrman"
	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

type TunnelEngine struct {
	nodeName      string
	forwardNodeIP bool
	natTraversal  bool

	localGateway *v1beta1.Gateway
	config       *config.Config
	ravenClient  client.Client
	routeDriver  routedriver.Driver
	vpnDriver    vpndriver.Driver

	nodeInfos map[types.NodeName]*v1beta1.NodeInfo
	network   *types.Network
}

func (c *TunnelEngine) InitDriver() error {
	var err error
	c.routeDriver, err = routedriver.New(c.config.Tunnel.RouteDriver, c.config)
	if err != nil {
		return fmt.Errorf("fail to create route driver: %s, %s", c.config.Tunnel.RouteDriver, err)
	}
	err = c.routeDriver.Init()
	if err != nil {
		return fmt.Errorf("fail to initialize route driver: %s, %s", c.config.Tunnel.RouteDriver, err)
	}
	c.vpnDriver, err = vpndriver.New(c.config.Tunnel.VPNDriver, c.config)
	if err != nil {
		return fmt.Errorf("fail to create vpn driver: %s, %s", c.config.Tunnel.VPNDriver, err)
	}
	err = c.vpnDriver.Init()
	if err != nil {
		return fmt.Errorf("fail to initialize vpn driver: %s, %s", c.config.Tunnel.VPNDriver, err)
	}
	klog.Infof("route driver %s and vpn driver %s are initialized", c.config.Tunnel.RouteDriver, c.config.Tunnel.VPNDriver)
	return nil
}

func (c *TunnelEngine) CleanupDriver() {
	_ = wait.PollImmediate(time.Second, 5*time.Second, func() (done bool, err error) {
		err = c.vpnDriver.Cleanup()
		if err != nil {
			klog.Errorf("fail to cleanup vpn driver: %s", err.Error())
			return false, nil
		}
		err = c.routeDriver.Cleanup()
		if err != nil {
			klog.Errorf("fail to cleanup route driver: %s", err.Error())
			return false, nil
		}
		return true, nil
	})
}

func (c *TunnelEngine) Status() bool {
	aep := getActiveEndpoints(c.localGateway, v1beta1.Tunnel)
	if aep != nil && aep.Config != nil {
		enable, err := strconv.ParseBool(aep.Config[utils.RavenEnableTunnel])
		if err == nil {
			return enable
		}
	}
	return false
}

// sync syncs full state according to the gateway list.
func (c *TunnelEngine) Handler() error {
	if c.config.Tunnel.NATTraversal {
		if err := c.checkNatCapability(); err != nil {
			klog.Errorf("fail to check the capability of NAT, error %s", err.Error())
			return err
		}
	}

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

	for i := range gws.Items {
		// try to update public IP if empty.
		gw := &gws.Items[i]
		if ep := getActiveEndpoints(gw, v1beta1.Tunnel); ep != nil {
			if ep.PublicIP == "" || c.natTraversal && (ep.NATType == "" || ep.PublicPort == 0 && ep.NATType != utils.NATSymmetric) {
				if ep.PublicIP == "" {
					if err := c.configGatewayPublicIP(gw); err != nil {
						klog.ErrorS(err, "error config gateway public ip", "gateway", klog.KObj(gw))
					}
				}
				if c.natTraversal && (ep.NATType == "" || ep.PublicPort == 0 && ep.NATType != utils.NATSymmetric) {
					if err := c.configGatewayStunInfo(gw); err != nil {
						klog.ErrorS(err, "error config gateway stun info", "gateway", klog.KObj(gw))
					}
				}
				continue
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
	nw := c.network.Copy()
	klog.InfoS("applying network", "localEndpoint", nw.LocalEndpoint, "remoteEndpoint", nw.RemoteEndpoints)
	err = c.vpnDriver.Apply(nw, c.routeDriver.MTU)
	if err != nil {
		klog.Errorf("error apply vpn driver, error %s", err.Error())
		return err
	}
	err = c.routeDriver.Apply(nw, c.vpnDriver.MTU)
	if err != nil {
		klog.Errorf("error apply route driver, error %s", err.Error())
		return err
	}
	return nil
}

func (c *TunnelEngine) syncNodeInfo(nodes []v1beta1.NodeInfo) {
	for _, v := range nodes {
		c.nodeInfos[types.NodeName(v.NodeName)] = v.DeepCopy()
	}
}

func (c *TunnelEngine) appendNodeIP(gw *v1beta1.Gateway) {
	for i := range gw.Status.Nodes {
		nodeSubnet := net.IPNet{
			IP:   net.ParseIP(gw.Status.Nodes[i].PrivateIP),
			Mask: []byte{0xff, 0xff, 0xff, 0xff},
		}
		gw.Status.Nodes[i].Subnets = append(gw.Status.Nodes[i].Subnets, nodeSubnet.String())
	}
}

func (c *TunnelEngine) getMergedSubnets(nodeInfo []v1beta1.NodeInfo) []string {
	subnets := make([]string, 0)
	for _, n := range nodeInfo {
		subnets = append(subnets, n.Subnets...)
	}
	subnets, _ = cidrman.MergeCIDRs(subnets)
	return subnets
}

func (c *TunnelEngine) syncGateway(gw *v1beta1.Gateway) {
	if c.forwardNodeIP {
		c.appendNodeIP(gw)
	}
	aep := getActiveEndpoints(gw, v1beta1.Tunnel)
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

	if gw.Name == c.localGateway.Name {
		c.network.LocalEndpoint = ep
		isLocalGateway = true
	} else {
		c.network.RemoteEndpoints[types.GatewayName(gw.Name)] = ep
	}

}

func (c *TunnelEngine) shouldHandleGateway(gateway *v1beta1.Gateway) bool {
	ep := getActiveEndpoints(gateway, v1beta1.Tunnel)
	if ep == nil {
		klog.InfoS("no active endpoint , waiting for sync", "gateway", klog.KObj(gateway))
		return false
	}
	if ep.PublicIP == "" {
		klog.InfoS("no public IP for gateway, waiting for sync", "gateway", klog.KObj(gateway))
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
	if c.localGateway == nil {
		klog.InfoS(fmt.Sprintf("no own gateway for node %s, skip it", c.nodeName), "gateway", klog.KObj(gateway))
		return false
	}
	return true
}

func (c *TunnelEngine) checkNatCapability() error {
	natType, err := utils.GetNATType()
	if err != nil {
		return err
	}

	if natType == utils.NATSymmetric {
		return nil
	}

	_, err = utils.GetPublicPort()
	if err != nil {
		return err
	}

	return nil
}

func (c *TunnelEngine) configGatewayPublicIP(gateway *v1beta1.Gateway) error {
	if getActiveEndpoints(gateway, v1beta1.Tunnel).NodeName != c.nodeName {
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

func (c *TunnelEngine) configGatewayStunInfo(gateway *v1beta1.Gateway) error {
	if getActiveEndpoints(gateway, v1beta1.Tunnel).NodeName != c.nodeName {
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

func (c *TunnelEngine) getLoadBalancerPublicIP(gwName string) (string, error) {
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
