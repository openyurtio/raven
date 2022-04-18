package options

import (
	"errors"
	"fmt"
	"os"

	ravenclientset "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/client/clientset/versioned"
	"github.com/spf13/pflag"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/libreswan"
)

// AgentOptions has the information that required by the raven agent
type AgentOptions struct {
	NodeName    string
	Kubeconfig  string
	VPNDriver   string
	RouteDriver string
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
}

// Config return a raven agent config objective
func (o *AgentOptions) Config() (*config.Config, error) {
	var err error
	c := &config.Config{
		NodeName:    o.NodeName,
		VPNDriver:   o.VPNDriver,
		RouteDriver: o.RouteDriver,
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %s", err)
	}
	cfg = restclient.AddUserAgent(cfg, "raven-agent")
	c.Kubeconfig = cfg
	c.RavenClient = ravenclientset.NewForConfigOrDie(cfg)
	if c.VPNDriver == "" {
		c.VPNDriver = libreswan.DriverName
	}
	if c.RouteDriver == "" {
		c.RouteDriver = vxlan.DriverName
	}
	return c, err
}
