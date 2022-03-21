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
	"sync"
	"time"

	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"
	ravenclientset "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/clientset/versioned"
	raveninformer "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/informers/externalversions"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"

	networkengine "github.com/openyurtio/raven/pkg/network-engine"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	maxRetries = 30
)

type EngineController struct {
	synMutex *sync.Mutex
	nodeName string

	gateway        *types.Endpoint
	endpoint       *v1alpha1.Endpoint
	otherGateways  map[string]*types.Endpoint
	otherEndpoints map[string]*v1alpha1.Endpoint

	ravenClient   *ravenclientset.Clientset
	ravenInformer raveninformer.SharedInformerFactory
	hasSynced     func() bool
	queue         workqueue.RateLimitingInterface

	engine networkengine.NetworkEngine
}

func NewEngineController(nodeName string, ravenClient *ravenclientset.Clientset, engine networkengine.NetworkEngine) (*EngineController, error) {
	ctr := &EngineController{
		synMutex:       &sync.Mutex{},
		nodeName:       nodeName,
		otherEndpoints: make(map[string]*v1alpha1.Endpoint),
		otherGateways:  make(map[string]*types.Endpoint),
		ravenClient:    ravenClient,
		queue:          workqueue.NewRateLimitingQueue(workqueue.DefaultControllerRateLimiter()),
		engine:         engine,
	}

	ravenInformer := raveninformer.NewSharedInformerFactory(ctr.ravenClient, 24*time.Hour)
	ravenInformer.Raven().V1alpha1().Gateways().Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    ctr.addGateway,
		UpdateFunc: ctr.updateGateway,
		DeleteFunc: ctr.deleteGateway,
	})
	ctr.ravenInformer = ravenInformer
	ctr.hasSynced = ravenInformer.Raven().V1alpha1().Gateways().Informer().HasSynced

	return ctr, nil
}

func (c *EngineController) Start(stopCh <-chan struct{}) {
	defer utilruntime.HandleCrash()
	c.ravenInformer.Start(stopCh)
	if !cache.WaitForCacheSync(stopCh, c.hasSynced) {
		klog.Errorf("failed to wait for cache sync")
		return
	}
	go wait.Until(c.worker, time.Second, stopCh)
	klog.Info("engine controller successfully start")
}

func (c *EngineController) worker() {
	for c.processNextWorkItem() {
	}
}

func (c *EngineController) enqueue(obj *v1alpha1.Gateway, eventType EventType) {
	c.queue.Add(&Event{
		Obj:  obj,
		Type: eventType,
	})
}

func (c *EngineController) processNextWorkItem() bool {
	key, quit := c.queue.Get()
	if quit {
		return false
	}
	defer c.queue.Done(key)

	err := c.handlerEvent(key.(*Event))
	c.handleEventErr(err, key)

	return true
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

// handlerEvent handler events observed by the controller.
func (c *EngineController) handlerEvent(event *Event) error {
	switch event.Type {
	case GatewayAdd:
		return c.handleCreateGateway(event.Obj.(*v1alpha1.Gateway))
	case GatewayUpdate:
		return c.handleUpdateGateway(event.Obj.(*v1alpha1.Gateway))
	case GatewayDelete:
		return c.handleDeleteGateway(event.Obj.(*v1alpha1.Gateway))
	}
	return nil
}

func (c *EngineController) shouldHandleGateway(gateway *v1alpha1.Gateway) bool {
	if gateway.Status.ActiveEndpoint != nil {
		return true
	}
	klog.Info("waiting for gateway to sync")
	return false
}

func (c *EngineController) completeGateway(gateway *v1alpha1.Gateway) error {
	if gateway.Status.ActiveEndpoint.NodeName != c.nodeName {
		return nil
	}
	publicIP, err := utils.GetPublicIP()
	if err != nil {
		return err
	}
	// retry to update public ip of gateway
	err = retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		// get gateway from api server
		apiGw, err := c.ravenClient.RavenV1alpha1().Gateways().Get(context.Background(), gateway.Name, v1.GetOptions{})
		if err != nil {
			return err
		}
		for k, v := range apiGw.Spec.Endpoints {
			if v.NodeName == c.nodeName {
				apiGw.Spec.Endpoints[k].PublicIP = publicIP
				_, err = c.ravenClient.RavenV1alpha1().Gateways().Update(context.Background(), apiGw, v1.UpdateOptions{})
				return err
			}
		}
		return nil
	})
	return err
}

func (c *EngineController) addGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(gw) {
		klog.InfoS("skip handle create gateway", "gateway", gw.Name, "node", c.nodeName)
		return
	}
	c.enqueue(gw, GatewayAdd)
}

func (c *EngineController) updateGateway(oldObj interface{}, newObj interface{}) {
	oldGw := oldObj.(*v1alpha1.Gateway)
	newGw := newObj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(newGw) || oldGw.ResourceVersion == newGw.ResourceVersion {
		klog.InfoS("skip handle update gateway", "gateway", newGw.Name, "node", c.nodeName)
		return
	}
	c.enqueue(newGw, GatewayUpdate)
}

func (c *EngineController) deleteGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(gw) {
		klog.InfoS("skip handle delete gateway", "gateway", gw.Name, "node", c.nodeName)
		return
	}
	c.enqueue(gw, GatewayDelete)
}

func (c *EngineController) handleCreateGateway(gw *v1alpha1.Gateway) error {
	klog.Info("handle create gateway: ", gw.Name)
	return c.handleCreateOrUpdateGateway(gw)
}

func (c *EngineController) handleUpdateGateway(gw *v1alpha1.Gateway) error {
	klog.Info("handle update gateway: ", gw.Name)
	return c.handleCreateOrUpdateGateway(gw)
}

func (c *EngineController) handleDeleteGateway(gw *v1alpha1.Gateway) error {
	klog.Info("handle delete gateway: ", gw.Name)
	c.synMutex.Lock()
	defer c.synMutex.Unlock()
	_, _, ok := c.parseLocalEndpoints(gw)
	if ok { // handle local gateway
		c.gateway = nil
		c.endpoint = nil
		c.otherEndpoints = make(map[string]*v1alpha1.Endpoint)
		c.engine.Cleanup()
	} else {
		delete(c.otherGateways, gw.Name)
		c.UpdateNetwork()
	}
	// TODO error handling
	return nil
}

func (c *EngineController) handleCreateOrUpdateGateway(gateway *v1alpha1.Gateway) error {
	c.synMutex.Lock()
	defer c.synMutex.Unlock()

	if gateway.Status.ActiveEndpoint.PublicIP == "" {
		return c.completeGateway(gateway)
	}

	ep, others, ok := c.parseLocalEndpoints(gateway)
	if ok {
		c.gateway = EnsureEndpoint(gateway)
		c.endpoint = ep
		c.otherEndpoints = others
		delete(c.otherGateways, gateway.Name)
	} else {
		c.otherGateways[gateway.Name] = EnsureEndpoint(gateway)
	}
	// TODO error handling
	c.UpdateNetwork()
	return nil
}

func (c *EngineController) UpdateNetwork() {
	if c.gateway == nil || c.endpoint == nil {
		klog.InfoS("waiting for local gateway sync", "gateway", c.gateway, "endpoint", c.endpoint)
		return
	}
	gatewayInfo := &types.Gateway{
		GatewayIP: net.ParseIP(c.gateway.ID),
		RemoteIPs: make(map[string]net.IP),
		Routes:    make(map[string]types.Route),
	}
	if c.isGatewayRole() { // role gateway
		for _, ep := range c.otherEndpoints {
			gatewayInfo.RemoteIPs[ep.NodeName] = net.ParseIP(ep.PrivateIP)
		}
		klog.InfoS("generating network info", "role", types.NodeRoleGateway, "local-node-name", c.nodeName, "gateway-node-name", c.gateway.NodeName)
	} else { // role agent
		gatewayInfo.RemoteIPs[c.gateway.NodeName] = net.ParseIP(c.gateway.ID)
		gatewayInfo.Routes = types.EnsureRoutes(c.otherGateways, net.ParseIP(c.gateway.ID))
		klog.InfoS("generating network info", "role", types.NodeRoleAgent, "local-node-name", c.nodeName, "gateway-node-name", c.gateway.NodeName)
	}
	c.engine.Init(net.ParseIP(c.endpoint.PrivateIP), net.ParseIP(c.endpoint.PublicIP))
	err := c.engine.ConnectToGateway(gatewayInfo)
	if err != nil {
		klog.Errorf("error connect to local gateway: %v", err)
	}
	if c.isGatewayRole() { // role gateway
		central := EnsureCentralEndpoint(c.gateway, c.otherGateways)
		if central == nil {
			klog.Warning("error ensure forwarding endpoint")
			return
		}
		if c.gateway.NATEnabled {
			c.ConnectToCentral(central)
		} else {
			if c.gateway.NodeName == central.NodeName {
				c.ConnectToEdge(c.otherGateways)
			} else {
				c.ConnectToCentral(central)
			}
		}
	}
}

func (c *EngineController) ConnectToEdge(gateways map[string]*types.Endpoint) {
	c.engine.EnsureEndpoints(gateways)
	for _, ep := range gateways {
		c.engine.UpdateLocalEndpoint(UpdateCentralEndpoint(c.gateway, ep, gateways))
		if err := c.engine.ConnectToEndpoint(ep); err != nil {
			klog.Errorf("error connect to remote gateway: %v", err)
		}
	}
}

func (c *EngineController) ConnectToCentral(central *types.Endpoint) {
	c.engine.UpdateLocalEndpoint(c.gateway)
	c.engine.EnsureEndpoints(map[string]*types.Endpoint{central.NodeName: central})
	if err := c.engine.ConnectToEndpoint(central); err != nil {
		klog.Errorf("error connect to central gateway: %v", err)
	}
}

func (c *EngineController) parseLocalEndpoints(gateway *v1alpha1.Gateway) (*v1alpha1.Endpoint, map[string]*v1alpha1.Endpoint, bool) {
	var local *v1alpha1.Endpoint
	remotes := make(map[string]*v1alpha1.Endpoint)
	for index, ep := range gateway.Spec.Endpoints {
		if ep.NodeName == c.nodeName {
			local = &gateway.Spec.Endpoints[index]
		} else {
			remotes[ep.NodeName] = &gateway.Spec.Endpoints[index]
		}
	}
	if local != nil {
		return local, remotes, true
	}
	return local, remotes, false
}

func (c *EngineController) isGatewayRole() bool {
	return c.gateway.NodeName == c.nodeName
}
