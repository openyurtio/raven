package options

import (
	"errors"
	"fmt"

	"net"
	"os"
	"strconv"

	"github.com/openyurtio/raven/pkg/utils"
	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/libreswan"
)

const (
	DefaultTunnelMetricsPort = 10265
	DefaultProxyMetricsPort  = 10266
)

// AgentOptions has the information that required by the raven agent
type AgentOptions struct {
	TunnelOptions
	ProxyOptions
	NodeName           string
	NodeIP             string
	Kubeconfig         string
	MetricsBindAddress string
}

type TunnelOptions struct {
	VPNDriver     string
	VPNPort       string
	RouteDriver   string
	ForwardNodeIP bool
}

type ProxyOptions struct {
	ProxyMetricsAddress      string
	InternalInsecureAddress  string
	InternalSecureAddress    string
	ExternalAddress          string
	ProxyServerCertDNSNames  string
	ProxyServerCertIPs       string
	ProxyServerCertDir       string
	ProxyClientCertDir       string
	InterceptorServerUDSFile string
}

// Validate validates the AgentOptions
func (o *AgentOptions) Validate() error {
	if o.NodeName == "" {
		o.NodeName = os.Getenv("NODE_NAME")
		if o.NodeName == "" {
			return errors.New("either --node-name or $NODE_NAME has to be set")
		}
	}
	if o.NodeIP == "" {
		o.NodeIP = os.Getenv("NODE_IP")
		if o.NodeIP == "" {
			return errors.New("either --node-name or $NODE_NAME has to be set")
		}
	}
	if o.VPNPort == "" {
		o.VPNPort = os.Getenv("VPN_BIND_ADDRESS")
		if o.VPNPort == "" {
			return errors.New("either --vpn-bind-address or $VPN_BIND_PORT has to be set")
		}
	}
	if o.InternalSecureAddress == "" {
		o.InternalSecureAddress = os.Getenv("PROXY_SERVER_INTERNAL_SECURE_ADDRESS")
		if o.InternalSecureAddress == "" {
			return errors.New("either --proxy-internal-secure-address or PROXY_SERVER_INTERNAL_SECURE_ADDRESS has to be set")
		}
	}
	if o.InternalInsecureAddress == "" {
		o.InternalInsecureAddress = os.Getenv("PROXY_SERVER_INTERNAL_INSECURE_ADDRESS")
		if o.InternalInsecureAddress == "" {
			return errors.New("either --proxy-internal-insecure-address or PROXY_SERVER_INTERNAL_INSECURE_ADDRESS has to be set")
		}
	}
	if o.ExternalAddress == "" {
		o.ExternalAddress = os.Getenv("PROXY_SERVER_EXTERNAL_ADDRESS")
		if o.ExternalAddress == "" {
			return errors.New("either --proxy-external-address or $PROXY_SERVER_EXTERNAL_ADDRESS has to be set")
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
	fs.StringVar(&o.MetricsBindAddress, "metric-bind-addr", o.MetricsBindAddress, `Binding address of tunnel metrics. (default ":10265")`)
	fs.StringVar(&o.VPNPort, "vpn-bind-port", o.VPNPort, `Binding port of vpn. (default ":4500")`)
	fs.StringVar(&o.ProxyMetricsAddress, "proxy-metric-bind-addr", o.ProxyMetricsAddress, `Binding address of proxy metrics. (default ":10266")`)
	fs.StringVar(&o.InternalSecureAddress, "proxy-internal-secure-addr", o.InternalSecureAddress, `Binding secure address of proxy server. (default ":10263")`)
	fs.StringVar(&o.InternalInsecureAddress, "proxy-internal-insecure-addr", o.InternalInsecureAddress, `Binding insecure address of proxy server. (default ":10264")`)
	fs.StringVar(&o.ExternalAddress, "proxy-external-addr", o.ExternalAddress, `Binding address of proxy. (default ":10262")`)

	fs.StringVar(&o.ProxyClientCertDir, "client-cert-dir", o.ProxyClientCertDir, "The directory of certificate stored at.")
	fs.StringVar(&o.ProxyServerCertDir, "server-cert-dir", o.ProxyServerCertDir, "The directory of certificate stored at.")
	fs.StringVar(&o.ProxyServerCertDNSNames, "server-cert-dns-names", o.ProxyServerCertDNSNames, "DNS names that will be added into server's certificate. (e.g., dns1,dns2)")
	fs.StringVar(&o.ProxyServerCertIPs, "server-cert-ips", o.ProxyServerCertIPs, "IPs that will be added into server's certificate. (e.g., ip1,ip2)")
}

// Config return a raven agent config objective
func (o *AgentOptions) Config() (*config.Config, error) {
	var err error
	c := &config.Config{
		NodeName:           o.NodeName,
		NodeIP:             o.NodeIP,
		MetricsBindAddress: o.MetricsBindAddress,
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %s", err)
	}
	cfg = restclient.AddUserAgent(cfg, "raven-agent-ds")
	c.KubeConfig = cfg
	c.MetricsBindAddress = resolveAddress(c.MetricsBindAddress, c.NodeIP, strconv.Itoa(DefaultTunnelMetricsPort))
	c.Manager, err = newMgr(cfg, c.MetricsBindAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %s", err)
	}
	_, port, err := net.SplitHostPort(o.VPNPort)
	if err != nil {
		port = strconv.Itoa(v1beta1.DefaultTunnelServerExposedPort)
	}
	c.Tunnel = &config.TunnelConfig{
		VPNPort:       port,
		VPNDriver:     o.VPNDriver,
		RouteDriver:   o.RouteDriver,
		ForwardNodeIP: o.ForwardNodeIP,
	}
	c.Proxy = &config.ProxyConfig{
		ProxyMetricsAddress:     o.ProxyMetricsAddress,
		InternalInsecureAddress: o.InternalInsecureAddress,
		InternalSecureAddress:   o.InternalSecureAddress,
		ExternalAddress:         o.ExternalAddress,
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %s", err)
	}
	if c.Tunnel.VPNDriver == "" {
		c.Tunnel.VPNDriver = libreswan.DriverName
	}
	if c.Tunnel.RouteDriver == "" {
		c.Tunnel.RouteDriver = vxlan.DriverName
	}
	if c.Tunnel.VPNPort == "" {
		c.Tunnel.VPNPort = vpndriver.DefaultVPNPort
	}
	if c.Proxy.ProxyClientCertDir == "" {
		c.Proxy.ProxyClientCertDir = utils.RavenProxyClientCertDir
	}
	if c.Proxy.ProxyServerCertDir == "" {
		c.Proxy.ProxyServerCertDir = utils.RavenProxyServerCertDir
	}
	if c.Proxy.InterceptorServerUDSFile == "" {
		c.Proxy.InterceptorServerUDSFile = utils.RavenProxyServerUDSFile
	}

	c.Proxy.InternalInsecureAddress = resolveAddress(c.Proxy.InternalInsecureAddress, c.NodeIP, strconv.Itoa(v1beta1.DefaultProxyServerInsecurePort))
	c.Proxy.InternalSecureAddress = resolveAddress(c.Proxy.InternalSecureAddress, c.NodeIP, strconv.Itoa(v1beta1.DefaultProxyServerSecurePort))
	c.Proxy.ExternalAddress = resolveAddress(c.Proxy.ExternalAddress, c.NodeIP, strconv.Itoa(v1beta1.DefaultProxyServerExposedPort))
	c.Proxy.ProxyMetricsAddress = resolveAddress(c.Proxy.ProxyMetricsAddress, c.NodeIP, strconv.Itoa(DefaultProxyMetricsPort))

	return c, err
}

func newMgr(cfg *restclient.Config, metricsBindAddress string) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = v1beta1.AddToScheme(scheme)

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

func resolveAddress(srcAddr, defaultHost, defaultPort string) string {
	host, port, err := net.SplitHostPort(srcAddr)
	if err != nil {
		return net.JoinHostPort(defaultHost, defaultPort)
	}
	if host == "" {
		host = defaultHost
	}
	if port == "" {
		port = defaultPort
	}
	return net.JoinHostPort(host, port)
}
