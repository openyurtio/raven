package engine

import (
	"context"
	"fmt"
	"net"
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
	serverLocalEndpoints  []string
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
	aep := getActiveEndpoints(p.localGateway, v1beta1.Proxy)
	if aep == nil {
		aep = getActiveEndpoints(findCentreGateway(p.client), v1beta1.Proxy)
	}
	if aep != nil && aep.Config != nil {
		enable, err := strconv.ParseBool(aep.Config[utils.RavenEnableProxy])
		if err == nil {
			return enable
		}
	}
	return false
}

func (p *ProxyEngine) Handler() error {
	var err error
	p.option.SetProxyStatus(p.Status())
	specServer, specClient := p.getRole(p.option.GetProxyStatus())
	switch JudgeAction(p.proxyOption.GetServerStatus(), specServer) {
	case StartType:
		srcAddr := getSrcAddressForProxyServer(p.client, p.nodeName)
		err = p.startProxyServer()
		if err != nil {
			klog.Errorf("failed to start proxy server, error %s", err.Error())
			return err
		}
		p.serverLocalEndpoints = srcAddr
	case StopType:
		p.stopProxyServer()
		p.serverLocalEndpoints = []string{}
	case RestartType:
		srcAddr := getSrcAddressForProxyServer(p.client, p.nodeName)
		if strings.Join(p.serverLocalEndpoints, ",") != strings.Join(srcAddr, ",") {
			p.stopProxyServer()
			time.Sleep(2 * time.Second)
			err = p.startProxyServer()
			if err != nil {
				klog.Errorf("failed to start proxy server, error %s", err.Error())
				return err
			}
			p.serverLocalEndpoints = srcAddr
		}
	default:

	}

	switch JudgeAction(p.proxyOption.GetClientStatus(), specClient) {
	case StartType:
		err = p.startProxyClient()
		if err != nil {
			klog.Errorf("failed to start proxy client, error %s", err.Error())
			return err
		}
	case StopType:
		p.stopProxyClient()
	case RestartType:
		dstAddr := getDestAddressForProxyClient(p.client, p.localGateway)
		if len(dstAddr) < 1 {
			klog.Infoln("dest address is empty, will not connected it")
			return nil
		}
		if strings.Join(p.clientRemoteEndpoints, ",") != strings.Join(dstAddr, ",") {
			p.stopProxyClient()
			time.Sleep(2 * time.Second)
			err = p.startProxyClient()
			if err != nil {
				klog.Errorf("failed to start proxy client, error %s", err.Error())
				return err
			}
		}
	default:

	}
	return nil
}

func (p *ProxyEngine) startProxyServer() error {
	klog.Infoln("start raven l7 proxy server")
	if p.localGateway == nil {
		return fmt.Errorf("unknown gateway for node %s, can not start proxy server", p.nodeName)
	}
	pe := &proxyengine.EnginConfig{
		Name:                    p.nodeName,
		IP:                      p.nodeIP,
		GatewayName:             p.localGateway.Name,
		CertDir:                 p.config.Proxy.ProxyServerCertDir,
		MetaAddress:             p.config.Proxy.ProxyMetricsAddress,
		CertIPs:                 p.config.Proxy.ProxyServerCertIPs,
		CertDNSNames:            p.config.Proxy.ProxyServerCertDNSNames,
		InterceptorUDSFile:      p.config.Proxy.InterceptorServerUDSFile,
		InternalSecureAddress:   p.config.Proxy.InternalSecureAddress,
		InternalInsecureAddress: p.config.Proxy.InternalInsecureAddress,
		ExposedAddress:          p.config.Proxy.ExternalAddress,
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

func (p *ProxyEngine) startProxyClient() error {
	klog.Infoln("start raven l7 proxy client")
	var err error
	dstAddr := getDestAddressForProxyClient(p.client, p.localGateway)
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
func getSrcAddressForProxyServer(client client.Client, nodeName string) []string {
	srcAddr := make([]string, 0)
	var gwList v1beta1.GatewayList
	err := client.List(context.TODO(), &gwList)
	if err != nil {
		return srcAddr
	}
	for _, gw := range gwList.Items {
		if gw.Spec.ExposeType == "" {
			continue
		}
		for _, aep := range gw.Status.ActiveEndpoints {
			if aep.NodeName == nodeName && aep.Type == v1beta1.Proxy {
				srcAddr = append(srcAddr, aep.PublicIP)
			}
		}
	}
	return srcAddr
}

func getDestAddressForProxyClient(client client.Client, localGateway *v1beta1.Gateway) []string {
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
		for _, aep := range gw.Status.ActiveEndpoints {
			if aep.Type == v1beta1.Proxy && aep.PublicIP != "" {
				destAddr = append(destAddr, net.JoinHostPort(aep.PublicIP, strconv.Itoa(aep.Port)))
			}
		}
	}
	sort.Slice(destAddr, func(i, j int) bool { return destAddr[i] < destAddr[j] })
	return destAddr
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
