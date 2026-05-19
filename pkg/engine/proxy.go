package engine

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/proxyengine"
	"github.com/openyurtio/raven/pkg/proxyengine/proxyclient"
	"github.com/openyurtio/raven/pkg/proxyengine/proxyserver"
	"github.com/openyurtio/raven/pkg/utils"
	"github.com/openyurtio/raven/pkg/utils/certmanager/store"
)

type ActionType string

const (
	StartType   ActionType = "Start"
	StopType    ActionType = "Stop"
	RestartType ActionType = "Restart"
	SkipType    ActionType = "Skip"
)

func JudgeAction(curr, spec bool) ActionType {
	if curr && spec {
		return RestartType
	}
	if curr && !spec {
		return StopType
	}
	if !curr && spec {
		return StartType
	}
	return SkipType
}

type ProxyEngine struct {
	nodeName              string
	nodeIP                string
	serverPublicIPs       []string
	clientRemoteEndpoints []string
	localGateway          *v1beta1.Gateway
	config                *config.Config
	client                client.Client
	ctx                   context.Context
	option                *Option
	proxyCtx              ProxyContext
	proxyOption           *proxyOption
}

func (p *ProxyEngine) Status() bool {
	gw := p.localGateway
	if gw == nil {
		gw = findCentreGateway(p.client)
	}
	if gw == nil {
		return false
	}
	return gw.Spec.ProxyConfig.Replicas > 0
}

func (p *ProxyEngine) Handler() error {
	p.option.SetProxyStatus(p.Status())
	specServer, specClient := p.getRole(p.option.GetProxyStatus())

	if err := p.proxyServerHandler(specServer); err != nil {
		return fmt.Errorf("failed to proxy server handler, error: %v", err)
	}

	if err := p.proxyClientHandler(specClient); err != nil {
		return fmt.Errorf("failed to proxy client handler, error: %v", err)
	}

	return nil
}

func (p *ProxyEngine) proxyServerHandler(enableServer bool) error {
	switch JudgeAction(p.proxyOption.GetServerStatus(), enableServer) {
	case StartType:
		if err := p.startProxyServer(); err != nil {
			klog.Errorf("failed to start proxy server, error %s", err.Error())
			return err
		}
		p.serverPublicIPs = collectGatewayProxyPublicIPs(p.localGateway)
	case StopType:
		p.stopProxyServer()
		p.purgeServerCert()
		p.serverPublicIPs = nil
	case RestartType:
		curr := collectGatewayProxyPublicIPs(p.localGateway)
		if reflect.DeepEqual(curr, p.serverPublicIPs) {
			return nil
		}
		klog.Infof("proxy server gateway public IPs changed: %v -> %v, restarting", p.serverPublicIPs, curr)
		p.stopProxyServer()
		p.purgeServerCert()
		time.Sleep(2 * time.Second)
		if err := p.startProxyServer(); err != nil {
			klog.Errorf("failed to start proxy server, error %s", err.Error())
			return err
		}
		p.serverPublicIPs = curr
	default:

	}
	return nil
}

// collectGatewayProxyPublicIPs returns the deduplicated, sorted set of
// PublicIPs from gw.Status.ActiveEndpoints whose Type==Proxy and PublicIP
// is non-empty. It mirrors the Gateway-side filter used by the proxy
// server cert SAN computation in pkg/proxyengine/proxyserver, so that the
// restart trigger and the cert SAN draw from the same source set.
func collectGatewayProxyPublicIPs(gw *v1beta1.Gateway) []string {
	if gw == nil {
		return nil
	}
	set := make(map[string]struct{})
	for _, aep := range gw.Status.ActiveEndpoints {
		if aep == nil || aep.Type != v1beta1.Proxy || aep.PublicIP == "" {
			continue
		}
		set[aep.PublicIP] = struct{}{}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for ip := range set {
		out = append(out, ip)
	}
	sort.Strings(out)
	return out
}

// purgeServerCert removes the proxy server cert/key files from the
// configured cert directory so that the next certificate.Manager load
// sees a missing certificate and triggers a fresh CSR with the current
// SAN. Failures are logged and ignored: the cert manager dynamicTemplate
// path remains a fallback.
func (p *ProxyEngine) purgeServerCert() {
	if p.config == nil || p.config.Proxy == nil {
		return
	}
	if err := store.PurgeCert(p.config.Proxy.ProxyServerCertDir, utils.RavenProxyServerName); err != nil {
		klog.Warningf("failed to purge proxy server cert (will rely on cert manager rotation): %v", err)
	}
}

func (p *ProxyEngine) startProxyServer() error {
	klog.Infoln("start raven l7 proxy server")
	if p.localGateway == nil {
		return fmt.Errorf("unknown gateway for node %s, can not start proxy server", p.nodeName)
	}
	pe := &proxyengine.EnginConfig{
		Name:                         p.nodeName,
		IP:                           p.nodeIP,
		GatewayName:                  p.localGateway.Name,
		CertDir:                      p.config.Proxy.ProxyServerCertDir,
		MetaAddress:                  p.config.Proxy.ProxyMetricsAddress,
		CertIPs:                      p.config.Proxy.ProxyServerCertIPs,
		CertDNSNames:                 p.config.Proxy.ProxyServerCertDNSNames,
		InterceptorUDSFile:           p.config.Proxy.InterceptorServerUDSFile,
		InternalSecureAddress:        p.config.Proxy.InternalSecureAddress,
		InternalInsecureAddress:      p.config.Proxy.InternalInsecureAddress,
		ExposedAddress:               p.config.Proxy.ExternalAddress,
		EnableManagedPrometheusProxy: p.config.Proxy.EnableManagedPrometheusProxy,
	}
	ctx := p.proxyCtx.GetServerContext()
	ps, err := proxyserver.NewProxyServer(pe, p.client, p.config.Manager.GetConfig(), p.localGateway.DeepCopy())
	if err != nil {
		return fmt.Errorf("failed to new proxy server, error %s", err.Error())
	}
	err = ps.Start(ctx)
	if err != nil {
		return fmt.Errorf("failed to start proxy server, error %s", err.Error())
	}
	p.proxyOption.SetServerStatus(true)
	return nil
}

func (p *ProxyEngine) stopProxyServer() {
	klog.Infoln("Stop raven l7 proxy server")
	cancel := p.proxyCtx.GetServerCancelFunc()
	cancel()
	p.proxyOption.SetServerStatus(false)
	p.proxyCtx.ReloadServerContext(p.ctx)
}

func (p *ProxyEngine) proxyClientHandler(enableClient bool) error {
	switch JudgeAction(p.proxyOption.GetClientStatus(), enableClient) {
	case StartType:
		err := p.startProxyClient()
		if err != nil {
			klog.Errorf("failed to start proxy client, error %s", err.Error())
			return err
		}
	case StopType:
		p.stopProxyClient()
	case RestartType:
		dstAddr := getDestAddressForProxyClient(p.client, p.localGateway, p.nodeName)
		if len(dstAddr) < 1 {
			// Remote dial targets disappeared (e.g. localGateway was previously nil
			// during bootstrap and the client was started against a now-filtered set).
			// Stop the existing client so its stale connections do not leak.
			klog.Infoln("dest address is empty, stop existing proxy client")
			p.stopProxyClient()
			p.clientRemoteEndpoints = nil
			return nil
		}
		if strings.Join(p.clientRemoteEndpoints, ",") != strings.Join(dstAddr, ",") {
			p.stopProxyClient()
			time.Sleep(2 * time.Second)
			err := p.startProxyClient()
			if err != nil {
				klog.Errorf("failed to start proxy client, error %s", err.Error())
				return err
			}
		}
	default:
	}
	return nil
}

func (p *ProxyEngine) startProxyClient() error {
	klog.Infoln("start raven l7 proxy client")
	var err error
	dstAddr := getDestAddressForProxyClient(p.client, p.localGateway, p.nodeName)
	if len(dstAddr) < 1 {
		klog.Infoln("dest address is empty, will not connected it")
		return nil
	}
	p.clientRemoteEndpoints = dstAddr
	pe := &proxyengine.EnginConfig{
		Name:        p.nodeName,
		IP:          p.nodeIP,
		CertDir:     p.config.Proxy.ProxyClientCertDir,
		MetaAddress: p.config.Proxy.ProxyMetricsAddress,
	}
	pc, err := proxyclient.NewProxyClient(pe, p.clientRemoteEndpoints, p.config.KubeConfig)
	if err != nil {
		klog.Errorf("failed to new proxy client, error %s", err.Error())
		return err
	}
	ctx := p.proxyCtx.GetClientContext()
	err = pc.Start(ctx)
	if err != nil {
		klog.Errorf("failed to start proxy client, error %s", err.Error())
		return err
	}
	p.proxyOption.SetClientStatus(true)
	return nil
}

func (p *ProxyEngine) stopProxyClient() {
	klog.Infoln("stop raven l7 proxy client")
	cancel := p.proxyCtx.GetClientCancelFunc()
	cancel()
	p.proxyOption.SetClientStatus(false)
	p.proxyCtx.ReloadClientContext(p.ctx)
}
func getDestAddressForProxyClient(client client.Client, localGateway *v1beta1.Gateway, nodeName string) []string {
	destAddr := make([]string, 0)
	var gwList v1beta1.GatewayList
	err := client.List(context.TODO(), &gwList)
	if err != nil {
		return destAddr
	}
	for _, gw := range gwList.Items {
		if gw.Spec.ExposeType == "" {
			continue
		}
		if localGateway != nil && localGateway.Name == gw.Name {
			continue
		}
		// Defensive filter: even when localGateway has not been resolved yet
		// (Status.Nodes for this node not yet reconciled by controller-manager),
		// avoid dialing a Gateway that already lists this node in its Status.Nodes.
		// This prevents the proxy client from hairpinning to its own Gateway's
		// public VIP during the bootstrap window.
		if localGateway == nil && gatewayContainsNode(&gw, nodeName) {
			continue
		}
		destAddr = append(destAddr, getDestAddressFromRemoteGateway(localGateway, &gw)...)
	}

	sort.Slice(destAddr, func(i, j int) bool { return destAddr[i] < destAddr[j] })
	return destAddr
}

func gatewayContainsNode(gw *v1beta1.Gateway, nodeName string) bool {
	if gw == nil || nodeName == "" {
		return false
	}
	for _, n := range gw.Status.Nodes {
		if n.NodeName == nodeName {
			return true
		}
	}
	return false
}

func getDestAddressFromRemoteGateway(localGateway, remoteGateway *v1beta1.Gateway) []string {
	var result []string
	for _, aep := range remoteGateway.Status.ActiveEndpoints {
		if aep.Type == v1beta1.Proxy && aep.PublicIP != "" {
			result = append(result, net.JoinHostPort(aep.PublicIP, strconv.Itoa(aep.Port)))
		}
	}
	return result
}

func (p *ProxyEngine) getRole(enableProxy bool) (enableServer, enableClient bool) {
	enableServer = false
	enableClient = false
	if !enableProxy {
		return
	}
	if p.localGateway != nil {
		for _, aep := range p.localGateway.Status.ActiveEndpoints {
			if aep.NodeName == p.nodeName && aep.Type == v1beta1.Proxy {
				enableClient = true
				if p.localGateway.Spec.ExposeType != "" {
					enableServer = true
				} else {
					enableServer = false
				}
				return
			}
		}
		for _, node := range p.localGateway.Status.Nodes {
			if node.NodeName == p.nodeName {
				enableServer = false
				enableClient = false
				return
			}
		}
	}
	enableServer = false
	enableClient = true
	return
}

func (p *ProxyEngine) stop() {
	if p.proxyOption.GetServerStatus() {
		cancelServer := p.proxyCtx.GetServerCancelFunc()
		cancelServer()
	}
	if p.proxyOption.GetClientStatus() {
		cancelClient := p.proxyCtx.GetClientCancelFunc()
		cancelClient()
	}
}
