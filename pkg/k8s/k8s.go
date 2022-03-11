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
	"fmt"
	"net"
	"sync"

	"github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	network_engine "github.com/openyurtio/raven/pkg/network-engine"
	"github.com/openyurtio/raven/pkg/types"
)

type EngineController struct {
	synMutex *sync.Mutex
	nodeName string

	gateway        *types.Endpoint
	endpoint       *v1alpha1.Endpoint
	otherGateways  map[string]*types.Endpoint
	otherEndpoints map[string]*v1alpha1.Endpoint

	ctrlManager manager.Manager

	engine network_engine.NetworkEngine
}

type Config struct {
	// NodeName
	NodeName string

	// Kubeconfig accepts the kubeconfig with the cluster credentials.
	Kubeconfig string
}

func New(config *Config) (*EngineController, error) {
	ctr := &EngineController{
		synMutex:       &sync.Mutex{},
		nodeName:       config.NodeName,
		otherEndpoints: make(map[string]*v1alpha1.Endpoint),
		otherGateways:  make(map[string]*types.Endpoint),
		engine:         network_engine.NewNetworkEngine(),
	}
	scheme := runtime.NewScheme()
	clientgoscheme.AddToScheme(scheme)
	v1alpha1.AddToScheme(scheme)
	cfg, err := clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("error build restconfig: %v", err)
	}
	ctrlManager, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme: scheme,
	})
	if err != nil {
		return nil, fmt.Errorf("error init ctrl manager %v", err)
	}
	ctr.ctrlManager = ctrlManager

	err = (&GatewayReconciler{
		Client:     ctrlManager.GetClient(),
		Log:        ctrl.Log.WithName("controllers").WithName("Gateway"),
		Scheme:     ctrlManager.GetScheme(),
		controller: ctr,
	}).SetupWithManager(ctrlManager)
	if err != nil {
		return nil, fmt.Errorf("error init gateway reconciler: %v", err)
	}

	return ctr, nil
}
func (c *EngineController) Start() {
	c.engine.Start()
	err := c.ctrlManager.Start(context.Background())
	if err != nil {
		panic(fmt.Sprintf("error start ctrl Manager: %v", err))
	}
	klog.Info("successfully start")
}

func (c *EngineController) shouldHandleGateway(gateway *v1alpha1.Gateway) bool {
	if gateway.Status.ActiveEndpoint != nil {
		return true
	}
	klog.Info("waiting for gateway to sync")
	return false
}

func (c *EngineController) handleCreateGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(gw) {
		klog.InfoS("skip handle create gateway", "gateway", gw.Name, "node", c.nodeName)
		return
	}
	klog.Info("handle create gateway: ", gw.Name)
	c.handleCreateOrUpdateGateway(gw)
}

func (c *EngineController) handleUpdateGateway(oldObj interface{}, newObj interface{}) {
	oldGw := oldObj.(*v1alpha1.Gateway)
	newGw := newObj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(newGw) || oldGw.ResourceVersion == newGw.ResourceVersion {
		klog.InfoS("skip handle update gateway", "gateway", newGw.Name, "node", c.nodeName)
		return
	}
	klog.Info("handle update gateway: ", newGw.Name)
	c.handleCreateOrUpdateGateway(newGw)
}

func (c *EngineController) handleDeleteGateway(obj interface{}) {
	gw := obj.(*v1alpha1.Gateway)
	if !c.shouldHandleGateway(gw) {
		klog.InfoS("skip handle delete gateway", "gateway", gw.Name, "node", c.nodeName)
		return
	}
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
}

func (c *EngineController) handleCreateOrUpdateGateway(gateway *v1alpha1.Gateway) {
	c.synMutex.Lock()
	defer c.synMutex.Unlock()

	ep, others, ok := c.parseLocalEndpoints(gateway)
	if ok {
		c.gateway = EnsureEndpoint(gateway)
		c.endpoint = ep
		c.otherEndpoints = others
		delete(c.otherGateways, gateway.Name)
	} else {
		c.otherGateways[gateway.Name] = EnsureEndpoint(gateway)
	}
	c.UpdateNetwork()
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
