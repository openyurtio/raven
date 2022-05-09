package vpndriver

import (
	"sync"

	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
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
	Apply(network *types.Network) error
	// Cleanup performs the necessary uninstallation.
	Cleanup() error
}

type Factory func(cfg *config.Config) (Driver, error)

var (
	driversMutex sync.Mutex
	drivers      = make(map[string]Factory)
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
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; !found {
		klog.Fatalf("vpn driver %s not found", name)
	}
	return drivers[name](cfg)
}
