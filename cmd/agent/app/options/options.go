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
)

// AgentOptions has the information that required by the raven agent
type AgentOptions struct {
	NodeName   string
	Kubeconfig string
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
}

// Config return a raven agent config objective
func (o *AgentOptions) Config() (*config.Config, error) {
	var err error
	c := &config.Config{
		NodeName: o.NodeName,
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %s", err)
	}
	cfg = restclient.AddUserAgent(cfg, "raven-agent")
	c.Kubeconfig = cfg

	c.RavenClient = ravenclientset.NewForConfigOrDie(cfg)
	return c, err
}
