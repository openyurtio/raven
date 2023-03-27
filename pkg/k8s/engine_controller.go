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

package k8s

import (
	"context"
	"net"
	"reflect"
	"time"

	"github.com/EvilSuperstars/go-cidrman"
	"github.com/openyurtio/openyurt/pkg/apis/raven/v1alpha1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	maxRetries = 30
)

type EngineController struct {
	nodeName      string
	forwardNodeIP bool
	nodeInfos     map[types.NodeName]*v1alpha1.NodeInfo
	network       *types.Network
	// lastSeenNetwork tracks the last seen Network.
	lastSeenNetwork *types.Network

	manager manager.Manager

	ravenClient client.Client
	queue       workqueue.RateLimitingInterface

	routeDriver routedriver.Driver
	vpnDriver   vpndriver.Driver
}

func NewEngineController(nodeName string, forwardNodeIP bool, routeDriver routedriver.Driver, manager manager.Manager,
	vpnDriver vpndriver.Driver) (*EngineController, error) {
	ctr := &EngineController{
		nodeName:      nodeName,
		forwardNodeIP: forwardNodeIP,
		queue:         workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		routeDriver:   routeDriver,
		manager:       manager,
		vpnDriver:     vpnDriver,
	}

	err := ctrl.NewControllerManagedBy(ctr.manager).
		For(&v1alpha1.Gateway{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: ctr.addGateway,
			UpdateFunc: ctr.updateGateway,
			DeleteFunc: ctr.deleteGateway,
		})).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}))
	if err != nil {
		klog.ErrorS(err, "failed to new raven agent controller with manager")
	}
	ctr.ravenClient = ctr.manager.GetClient()

	return ctr, nil
}

func (c *EngineController) Start(ctx context.Context) {
	defer utilruntime.HandleCrash()
	go func() {
		if err := c.manager.Start(ctx); err != nil {
			klog.ErrorS(err, "failed to start engine controller")
		}
	}()
	go wait.Until(c.worker, time.Second, ctx.Done())
	klog.Info("engine controller successfully start")
}

func (c *EngineController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *EngineController) enqueue(obj *v1alpha1.Gateway) {
	c.queue.Add(obj.Name)
}

func (c *EngineController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.sync()
	c.handleEventErr(err, key)

	return true
}

func (c *EngineController) getMergedSubnets(nodeInfo []v1alpha1.NodeInfo) []string {
	subnets := make([]string, 0)
	for _, n := range nodeInfo {
		subnets = append(subnets, n.Subnets...)
	}
	subnets, _ = cidrman.MergeCIDRs(subnets)
	return subnets
}

// sync syncs full state according to the gateway list.
func (c *EngineController) sync() error {
	var gws v1alpha1.GatewayList
	err := c.ravenClient.List(context.Background(), &gws)
	if err != nil {
		return err
	}
	// As we are going to rebuild a full state, so cleanup before proceeding.
	c.network = &types.Network{
		LocalEndpoint:   nil,
		RemoteEndpoints: make(map[types.GatewayName]*types.Endpoint),
		LocalNodeInfo:   make(map[types.NodeName]*v1alpha1.NodeInfo),
		RemoteNodeInfo:  make(map[types.NodeName]*v1alpha1.NodeInfo),
	}
	c.nodeInfos = make(map[types.NodeName]*v1alpha1.NodeInfo)

	for i := range gws.Items {
		// try to update public IP if empty.
		gw := &gws.Items[i]
		if ep := gw.Status.ActiveEndpoint; ep != nil && ep.PublicIP == "" {
			err := c.configGatewayPublicIP(gw)
			if err != nil {
				klog.ErrorS(err, "error config gateway public ip", "gateway", klog.KObj(gw))
			}
			continue
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

func (c *EngineController) syncNodeInfo(nodes []v1alpha1.NodeInfo) {
	for _, v := range nodes {
		c.nodeInfos[types.NodeName(v.NodeName)] = v.DeepCopy()
	}
}

func (c *EngineController) appendNodeIP(gw *v1alpha1.Gateway) {
	for i := range gw.Status.Nodes {
		nodeSubnet := net.IPNet{
			IP:   net.ParseIP(gw.Status.Nodes[i].PrivateIP),
			Mask: []byte{0xff, 0xff, 0xff, 0xff},
		}
		gw.Status.Nodes[i].Subnets = append(gw.Status.Nodes[i].Subnets, nodeSubnet.String())
	}
}

func (c *EngineController) syncGateway(gw *v1alpha1.Gateway) {
	if c.forwardNodeIP {
		c.appendNodeIP(gw)
	}
	aep := gw.Status.ActiveEndpoint
	subnets := c.getMergedSubnets(gw.Status.Nodes)
	cfg := make(map[string]string)
	for k := range aep.Config {
		cfg[k] = aep.Config[k]
	}
	var nodeInfo *v1alpha1.NodeInfo
	if nodeInfo = c.nodeInfos[types.NodeName(aep.NodeName)]; nodeInfo == nil {
		klog.Errorf("node %s is found in Endpoint but not existed in NodeInfo", aep.NodeName)
		return
	}
	ep := &types.Endpoint{
		GatewayName: types.GatewayName(gw.Name),
		NodeName:    types.NodeName(aep.NodeName),
		Subnets:     subnets,
		PrivateIP:   nodeInfo.PrivateIP,
		PublicIP:    aep.PublicIP,
		UnderNAT:    aep.UnderNAT,
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
	for _, v := range gw.Status.Nodes {
		if v.NodeName == c.nodeName {
			c.network.LocalEndpoint = ep
			isLocalGateway = true
			return
		}
	}
	c.network.RemoteEndpoints[types.GatewayName(gw.Name)] = ep
}

func (c *EngineController) handleEventErr(err error, event interface{}) {
	if err == nil {
		c.queue.Forget(event)
		return
	}
	if c.queue.NumRequeues(event) < maxRetries {
		klog.Infof("error syncing event %v: %v", event, err)
		c.queue.AddRateLimited(event)
		return
	}

	utilruntime.HandleError(err)
	klog.Infof("dropping event %q out of the queue: %v", event, err)
	c.queue.Forget(event)
}

func (c *EngineController) shouldHandleGateway(gateway *v1alpha1.Gateway) bool {
	if gateway.Status.ActiveEndpoint == nil {
		klog.InfoS("no active endpoint , waiting for sync", "gateway", klog.KObj(gateway))
		return false
	}
	if gateway.Status.ActiveEndpoint.PublicIP == "" {
		klog.InfoS("no public IP for gateway, waiting for sync", "gateway", klog.KObj(gateway))
		return false
	}
	return true
}

func (c *EngineController) configGatewayPublicIP(gateway *v1alpha1.Gateway) error {
	if gateway.Status.ActiveEndpoint.NodeName != c.nodeName {
		return nil
	}

	publicIP, err := utils.GetPublicIP()
	if err != nil {
		return err
	}

	// retry to update public ip of localGateway
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get localGateway from api server
		var apiGw v1alpha1.Gateway
		err := c.ravenClient.Get(context.Background(), client.ObjectKey{
			Name: gateway.Name,
		}, &apiGw)
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == c.nodeName {
				apiGw.Spec.Endpoints[k].PublicIP = publicIP
				err = c.ravenClient.Update(context.Background(), &apiGw)
				return err
			}
		}
		return nil
	})
	return err
}

func (c *EngineController) addGateway(e event.CreateEvent) bool {
	gw, ok := e.Object.(*v1alpha1.Gateway)
	if ok {
		klog.V(4).InfoS("adding gateway", "gateway", klog.KObj(gw))
		c.enqueue(gw)
	}
	return ok
}

func (c *EngineController) updateGateway(e event.UpdateEvent) bool {
	oldGw, ok1 := e.ObjectOld.(*v1alpha1.Gateway)
	newGw, ok2 := e.ObjectNew.(*v1alpha1.Gateway)
	update := false
	if ok1 && ok2 {
		if oldGw.ResourceVersion != newGw.ResourceVersion {
			update = true
			klog.V(4).InfoS("updating gateway", "gateway", klog.KObj(newGw))
			c.enqueue(newGw)
		}
		klog.InfoS("skip handle update gateway", "gateway", klog.KObj(newGw))
	}
	return update
}

func (c *EngineController) deleteGateway(e event.DeleteEvent) bool {
	gw, ok := e.Object.(*v1alpha1.Gateway)
	if ok {
		klog.InfoS("deleting gateway", "gateway", klog.KObj(gw))
		c.enqueue(gw)
	}
	return ok
}
