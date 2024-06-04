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

package routedriver

import (
	"sync"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
)

// Driver is the interface for inner gateway routing mechanism.
type Driver interface {
	// Init inits the driver. If return an error, raven agent will exit.
	Init() error
	// Apply applies the given network to the cluster, which represents the desired state of the cluster.
	// If return an error, the caller is expected to retry again later.
	// Usually, the implementation should compare the current network state with the given desired state,
	// and make changes to reach the desired state.
	// This method should be idempotent.
	Apply(network *types.Network, vpnDriverMTUFn func() (int, error)) error
	// MTU return Minimal MTU in route driver
	MTU(network *types.Network) (int, error)
	// Cleanup performs the necessary uninstallation.
	Cleanup() error
}

var (
	driversMutex sync.Mutex
	drivers      = make(map[string]Factory)
)

type Factory func(cfg *config.Config) (Driver, error)

type Config struct {
	NodeName   string
	Client     *clientset.Clientset
	Kubeconfig *rest.Config
}

func RegisterRouteDriver(name string, factory Factory) {
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; found {
		klog.Fatal("route drivers %q was registered twice", name)
	}
	klog.Info("registered route driver %q", name)
	drivers[name] = factory
}

func New(name string, cfg *config.Config) (Driver, error) {
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; !found {
		klog.Fatal("route driver %q not found", name)
	}
	return drivers[name](cfg)
}
