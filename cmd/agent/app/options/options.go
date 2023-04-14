package options

import (
	"errors"
	"fmt"
	"os"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1alpha1"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/libreswan"
)

// AgentOptions has the information that required by the raven agent
type AgentOptions struct {
	NodeName           string
	Kubeconfig         string
	VPNDriver          string
	RouteDriver        string
	ForwardNodeIP      bool
	MetricsBindAddress string
}

// Validate validates the AgentOptions
func (o *AgentOptions) Validate() error {
	if o.NodeName == "" {
		o.NodeName = os.Getenv("NODE_NAME")
		if o.NodeName == "" {
			return errors.New("either --node-name or $NODE_NAME has to be set")
		}
	}
	return nil
}

// AddFlags returns flags for a specific yurttunnel-agent by section name
func (o *AgentOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeName, "node-name", o.NodeName, "The name of the node.")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", o.Kubeconfig, "Path to the kubeconfig file.")
	fs.StringVar(&o.VPNDriver, "vpn-driver", o.VPNDriver, `The VPN driver name. (default "libreswan")`)
	fs.StringVar(&o.RouteDriver, "route-driver", o.RouteDriver, `The Route driver name. (default "vxlan")`)
	fs.BoolVar(&o.ForwardNodeIP, "forward-node-ip", o.ForwardNodeIP, `Forward node IP or not. (default "false")`)
	fs.StringVar(&o.MetricsBindAddress, "metric-bind-addr", o.MetricsBindAddress, `Binding address of metrics. (default ":8080")`)
}

// Config return a raven agent config objective
func (o *AgentOptions) Config() (*config.Config, error) {
	var err error
	c := &config.Config{
		NodeName:           o.NodeName,
		VPNDriver:          o.VPNDriver,
		RouteDriver:        o.RouteDriver,
		ForwardNodeIP:      o.ForwardNodeIP,
		MetricsBindAddress: o.MetricsBindAddress,
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %s", err)
	}
	cfg = restclient.AddUserAgent(cfg, "raven-agent")
	c.Kubeconfig = cfg
	c.Manager, err = newMgr(cfg, c.MetricsBindAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %s", err)
	}
	if c.VPNDriver == "" {
		c.VPNDriver = libreswan.DriverName
	}
	if c.RouteDriver == "" {
		c.RouteDriver = vxlan.DriverName
	}
	return c, err
}

func newMgr(cfg *restclient.Config, metricsBindAddress string) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	_ = v1alpha1.AddToScheme(scheme)
	opt := ctrl.Options{
		Scheme:             scheme,
		MetricsBindAddress: metricsBindAddress,
	}

	mgr, err := ctrl.NewManager(cfg, opt)
	if err != nil {
		klog.ErrorS(err, "failed to new manager for raven agent controller")
		return nil, err
	}
	return mgr, nil
}
