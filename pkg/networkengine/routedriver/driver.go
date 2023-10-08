package routedriver

import (
	"sync"

	clientset "k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/openyurtio/raven/pkg/utils"
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
		klog.Fatal(utils.FormatTunnel("route drivers %q was registered twice", name))
	}
	klog.V(1).Info(utils.FormatTunnel("registered route driver %q", name))
	drivers[name] = factory
}

func New(name string, cfg *config.Config) (Driver, error) {
	driversMutex.Lock()
	defer driversMutex.Unlock()
	if _, found := drivers[name]; !found {
		klog.Fatal(utils.FormatTunnel("route driver %q not found", name))
	}
	return drivers[name](cfg)
}
