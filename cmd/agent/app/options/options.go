package options

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/pflag"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apiserver/pkg/endpoints/discovery"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/apiutil"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver/vxlan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/libreswan"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver/wireguard"
	"github.com/openyurtio/raven/pkg/utils"
)

const (
	DefaultTunnelMetricsPort = 10265
	DefaultProxyMetricsPort  = 10266
	DefaultHealthyProbeAddr  = 10275
	DefaultLocalHost         = "127.0.0.1"
	DefaultMACPrefix         = "aa:0f"
)

// AgentOptions has the information that required by the raven agent
type AgentOptions struct {
	TunnelOptions
	ProxyOptions
	NodeName           string
	NodeIP             string
	Kubeconfig         string
	MetricsBindAddress string
	HealthProbeAddr    string
	SyncRules          bool
	SyncPeriod         metav1.Duration
}

type TunnelOptions struct {
	VPNDriver         string
	VPNPort           string
	RouteDriver       string
	MACPrefix         string
	ForwardNodeIP     bool
	NATTraversal      bool
	KeepAliveInterval int
	KeepAliveTimeout  int
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
	if o.VPNDriver != "" {
		if o.VPNDriver != libreswan.DriverName && o.VPNDriver != wireguard.DriverName {
			return errors.New("currently only supports libreswan and wireguard VPN drivers")
		}
	}
	if o.MACPrefix != "" {
		reg := regexp.MustCompile(`^[0-9a-fA-F]+$`)
		strs := strings.Split(o.MACPrefix, ":")
		for i := range strs {
			if !reg.MatchString(strings.ToLower(strs[i])) {
				return fmt.Errorf("mac prefix %s is nonstandard", o.MACPrefix)
			}
		}
	}
	if o.SyncPeriod.Duration < time.Minute {
		o.SyncPeriod.Duration = time.Minute
	}
	if o.SyncPeriod.Duration > 24*time.Hour {
		o.SyncPeriod.Duration = 24 * time.Hour
	}
	return nil
}

// AddFlags returns flags for a specific yurttunnel-agent by section name
func (o *AgentOptions) AddFlags(fs *pflag.FlagSet) {
	fs.StringVar(&o.NodeName, "node-name", o.NodeName, "The name of the node.")
	fs.StringVar(&o.NodeIP, "node-ip", o.NodeIP, "The ip of the node.")
	fs.StringVar(&o.Kubeconfig, "kubeconfig", o.Kubeconfig, "Path to the kubeconfig file.")
	fs.StringVar(&o.VPNDriver, "vpn-driver", o.VPNDriver, `The VPN driver name. (default "libreswan")`)
	fs.StringVar(&o.RouteDriver, "route-driver", o.RouteDriver, `The Route driver name. (default "vxlan")`)
	fs.StringVar(&o.MetricsBindAddress, "metric-bind-addr", o.MetricsBindAddress, `Binding address of tunnel metrics. (default ":10265")`)
	fs.StringVar(&o.HealthProbeAddr, "health-probe-addr", o.HealthProbeAddr, `The address the healthz/readyz endpoint binds to.. (default ":10275")`)
	fs.BoolVar(&o.SyncRules, "sync-raven-rules", true, "Whether to synchronize raven rules regularly")
	fs.DurationVar(&o.SyncPeriod.Duration, "sync-raven-rules-period", 10*time.Minute, "The period for reconciling routes created for nodes by cloud provider. The minimum value is 1 minute and the maximum value is 24 hour")

	fs.StringVar(&o.VPNPort, "vpn-bind-port", o.VPNPort, `Binding port of vpn. (default ":4500")`)
	fs.BoolVar(&o.NATTraversal, "nat-traversal", o.NATTraversal, `Enable NAT Traversal or not. (default "false")`)
	fs.BoolVar(&o.ForwardNodeIP, "forward-node-ip", o.ForwardNodeIP, `Forward node IP or not. (default "false")`)
	fs.IntVar(&o.KeepAliveInterval, "keep-alive-interval", o.KeepAliveInterval, `Interval for sending keepalive packets in the VPN tunnel, (default "0", closed)`)
	fs.IntVar(&o.KeepAliveTimeout, "keep-alive-timeout", o.KeepAliveTimeout, `Timeout for sending keepalive packets in the VPN tunnel, (default "0", closed)`)
	fs.StringVar(&o.MACPrefix, "customized-mac-prefix", o.MACPrefix, `Customized MAC address prefix for vxlan link, (default "aa:0f")`)

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
	if o.NodeName == "" {
		o.NodeName = os.Getenv("NODE_NAME")
		if o.NodeName == "" {
			return nil, errors.New("either --node-name or $NODE_NAME has to be set")
		}
	}
	if o.NodeIP == "" {
		o.NodeIP = os.Getenv("NODE_IP")
		if o.NodeIP == "" {
			return nil, errors.New("either --node-ip or $NODE_IP has to be set")
		}
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", o.Kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kube client: %s", err)
	}
	cfg = restclient.AddUserAgent(cfg, "raven-agent-ds")
	c := &config.Config{
		NodeName:   o.NodeName,
		NodeIP:     o.NodeIP,
		SyncRules:  o.SyncRules,
		SyncPeriod: o.SyncPeriod,
	}
	c.KubeConfig = cfg
	c.MetricsBindAddress = resolveAddress(c.MetricsBindAddress, resolveLocalHost(), strconv.Itoa(DefaultTunnelMetricsPort))
	c.HealthProbeAddr = resolveAddress(c.HealthProbeAddr, c.NodeIP, strconv.Itoa(DefaultHealthyProbeAddr))
	c.Manager, err = newMgr(cfg, c.MetricsBindAddress, c.HealthProbeAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create manager: %s", err)
	}
	_, port, err := net.SplitHostPort(o.VPNPort)
	if err != nil {
		klog.Warningf("failed to parse VPN port %s, fallback to default %d: %s", o.VPNPort, v1beta1.DefaultTunnelServerExposedPort, err)
		port = strconv.Itoa(v1beta1.DefaultTunnelServerExposedPort)
	}
	c.Tunnel = &config.TunnelConfig{
		VPNPort:           port,
		VPNDriver:         o.VPNDriver,
		RouteDriver:       o.RouteDriver,
		MACPrefix:         o.MACPrefix,
		ForwardNodeIP:     o.ForwardNodeIP,
		NATTraversal:      o.NATTraversal,
		KeepAliveInterval: o.KeepAliveInterval,
		KeepAliveTimeout:  o.KeepAliveTimeout,
	}
	c.Proxy = &config.ProxyConfig{
		ProxyMetricsAddress:     o.ProxyMetricsAddress,
		InternalInsecureAddress: o.InternalInsecureAddress,
		InternalSecureAddress:   o.InternalSecureAddress,
		ExternalAddress:         o.ExternalAddress,

		ProxyServerCertDNSNames:  o.ProxyServerCertDNSNames,
		ProxyServerCertIPs:       o.ProxyServerCertIPs,
		ProxyClientCertDir:       o.ProxyClientCertDir,
		ProxyServerCertDir:       o.ProxyServerCertDir,
		InterceptorServerUDSFile: o.InterceptorServerUDSFile,
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
	if c.Tunnel.MACPrefix == "" {
		c.Tunnel.MACPrefix = DefaultMACPrefix
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
	c.Proxy.ProxyMetricsAddress = resolveAddress(c.Proxy.ProxyMetricsAddress, resolveLocalHost(), strconv.Itoa(DefaultProxyMetricsPort))

	return c, nil
}

func newMgr(cfg *restclient.Config, metricsBindAddress, healthyProbeAddress string) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = v1beta1.AddToScheme(scheme)

	opt := ctrl.Options{
		Scheme:                 scheme,
		MetricsBindAddress:     metricsBindAddress,
		HealthProbeBindAddress: healthyProbeAddress,
		MapperProvider: func(c *restclient.Config) (meta.RESTMapper, error) {
			opt := func() (meta.RESTMapper, error) {
				return restmapper.NewDiscoveryRESTMapper(
					[]*restmapper.APIGroupResources{getGatewayAPIGroupResource(), getLegacyAPIGroupResource()}), nil
			}
			return apiutil.NewDynamicRESTMapper(c, apiutil.WithCustomMapper(opt))
		},
	}

	mgr, err := ctrl.NewManager(cfg, opt)
	if err != nil {
		klog.ErrorS(err, "failed to new manager for raven agent controller")
		return nil, err
	}

	if err = mgr.AddHealthzCheck("health", healthz.Ping); err != nil {
		klog.ErrorS(err, "unable to set up health check")
		os.Exit(1)
	}
	if err = mgr.AddReadyzCheck("check", healthz.Ping); err != nil {
		klog.ErrorS(err, "unable to set up ready check")
		os.Exit(1)
	}

	return mgr, nil
}

func getLegacyAPIGroupResource() *restmapper.APIGroupResources {
	return &restmapper.APIGroupResources{
		Group: metav1.APIGroup{
			Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: "v1", Version: "v1"}},
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: "v1", Version: "v1"},
		},
		VersionedResources: map[string][]metav1.APIResource{
			"v1": {
				{
					Name:               "nodes",
					Namespaced:         false,
					Kind:               "Node",
					Verbs:              metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
					ShortNames:         []string{"no"},
					StorageVersionHash: discovery.StorageVersionHash("", "v1", "Node"),
				},
				{
					Name:               "pods",
					Namespaced:         true,
					Kind:               "Pod",
					Verbs:              metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
					ShortNames:         []string{"po"},
					StorageVersionHash: discovery.StorageVersionHash("", "v1", "Pod"),
				},
				{
					Name:               "services",
					Namespaced:         true,
					Kind:               "Service",
					Verbs:              metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
					ShortNames:         []string{"svc"},
					StorageVersionHash: discovery.StorageVersionHash("", "v1", "Service"),
				},
			},
		},
	}
}

func getGatewayAPIGroupResource() *restmapper.APIGroupResources {
	return &restmapper.APIGroupResources{
		Group: metav1.APIGroup{
			Name:             v1beta1.GroupVersion.Group,
			Versions:         []metav1.GroupVersionForDiscovery{{GroupVersion: v1beta1.GroupVersion.String(), Version: v1beta1.GroupVersion.Version}},
			PreferredVersion: metav1.GroupVersionForDiscovery{GroupVersion: v1beta1.GroupVersion.String(), Version: v1beta1.GroupVersion.Version},
		},
		VersionedResources: map[string][]metav1.APIResource{
			v1beta1.GroupVersion.Version: {
				{
					Name:               "gateways",
					Namespaced:         false,
					SingularName:       "gateway",
					Kind:               "Gateway",
					Verbs:              metav1.Verbs{"create", "delete", "deletecollection", "get", "list", "patch", "update", "watch"},
					ShortNames:         []string{"gw"},
					Categories:         []string{"all"},
					StorageVersionHash: discovery.StorageVersionHash(v1beta1.GroupVersion.Group, v1beta1.GroupVersion.Version, "Gateway"),
				},
				{
					Name:       "gateways/status",
					Namespaced: false,
					Kind:       "Gateway",
					Verbs:      metav1.Verbs{"get", "patch", "update"},
				},
			},
		},
	}
}

func resolveLocalHost() string {
	ipv4Addr, err := net.ResolveIPAddr("ip4", "localhost")
	if err != nil {
		klog.Warningf("can not get localhost addr, error %s, using default address %s", err.Error(), DefaultLocalHost)
		return DefaultLocalHost
	}
	return ipv4Addr.String()
}

func resolveAddress(srcAddr, defaultHost, defaultPort string) string {
	if srcAddr == "" {
		return net.JoinHostPort(defaultHost, defaultPort)
	}
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
