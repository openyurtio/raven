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

package vpndriver

import (
	"fmt"
	"os"
	"sort"
	"sync"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	netlinkutil "github.com/openyurtio/raven/pkg/networkengine/util/netlink"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	DefaultPSK     = "openyurt-raven"
	DefaultVPNPort = "4500"
)

// Driver is the interface for VPN implementation.
type Driver interface {
	// Init inits the driver. If return an error, raven agent will exit.
	Init() error
	// Apply applies the given network to the cluster, which represents the desired state of the cluster.
	// If return an error, the caller is expected to retry again later.
	// Usually, the implementation should compare the current network state with the given desired state,
	// and make changes to reach the desired state.
	// This method should be idempotent.
	Apply(network *types.Network, routeDriverMTU func(*types.Network) (int, error)) error
	// MTU return Minimal MTU in vpn driver
	MTU() (int, error)
	// Cleanup performs the necessary uninstallation.
	Cleanup() error
}

// Connection is the struct for VPN connection.
type Connection struct {
	LocalEndpoint  *types.Endpoint
	RemoteEndpoint *types.Endpoint

	LocalSubnet  string
	RemoteSubnet string
}

type Factory func(cfg *config.Config) (Driver, error)

var (
	driversMutex sync.Mutex
	drivers      = make(map[string]Factory)
	natTraversal bool
)

func RegisterDriver(name string, factory Factory) {
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; found {
		klog.Fatalf("vpn driver %s was registered twice", name)
	}
	klog.V(1).Infof("registered vpn driver %s", name)
	drivers[name] = factory
}

func New(name string, cfg *config.Config) (Driver, error) {
	if cfg.Tunnel != nil {
		natTraversal = cfg.Tunnel.NATTraversal
	}
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; !found {
		klog.Fatalf("vpn driver %s not found", name)
	}
	return drivers[name](cfg)
}

// FindCentralGwFn tries to find a central gateway from the given network.
// Returns nil if no central gateway found.
// A central gateway is used to forward traffic between gateway under nat network,
// in which the gateways can not establish ipsec connection directly.
func FindCentralGwFn(network *types.Network) *types.Endpoint {
	candidates := make([]*types.Endpoint, 0)
	candidates = append(candidates, network.LocalEndpoint)
	for _, v := range network.RemoteEndpoints {
		candidates = append(candidates, v)
	}
	// TODO: Maybe cause central ep switch when add or delete a candidate gateway because of sorting
	sort.Slice(candidates, func(i, j int) bool {
		return candidates[i].NodeName < candidates[j].NodeName
	})

	var central *types.Endpoint
	for i := range candidates {
		if !candidates[i].UnderNAT {
			central = candidates[i]
		}
	}
	return central
}

// EnableCreateEdgeConnection determine whether VPN tunnels can be established between edges.
func EnableCreateEdgeConnection(localEndpoint *types.Endpoint, remoteEndpoint *types.Endpoint) bool {
	if !natTraversal {
		return false
	}
	if localEndpoint.NATType == utils.NATUndefined || remoteEndpoint.NATType == utils.NATUndefined {
		return false
	}
	if !localEndpoint.UnderNAT || !remoteEndpoint.UnderNAT {
		return false
	}
	return !((localEndpoint.NATType == utils.NATSymmetric && remoteEndpoint.NATType == utils.NATSymmetric) ||
		(localEndpoint.NATType == utils.NATSymmetric && remoteEndpoint.NATType == utils.NATPortRestricted) ||
		(localEndpoint.NATType == utils.NATPortRestricted && remoteEndpoint.NATType == utils.NATSymmetric))
}

func DefaultMTU() (int, error) {
	routes, err := netlinkutil.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: nil},
		netlink.RT_FILTER_DST)
	if err != nil {
		return 0, err
	}

	if len(routes) > 1 {
		klog.Warning("more than one default route found")
	}

	for _, route := range routes {
		if defaultLink, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
			klog.InfoS("find default link", "name", defaultLink.Attrs().Name)
			return defaultLink.Attrs().MTU, nil
		}
	}
	return 0, fmt.Errorf("error get default mtu")
}

func GetPSK() string {
	psk := os.Getenv("VPN_CONNECTION_PSK")
	if psk == "" {
		psk = DefaultPSK
		klog.Warning(fmt.Sprintf("use weak PSK: %s", psk))
	}
	return psk
}
