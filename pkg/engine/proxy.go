package engine

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1beta1"
	ravenutil "github.com/openyurtio/openyurt/pkg/yurtmanager/controller/raven/utils"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/proxyengine"
	"github.com/openyurtio/raven/pkg/proxyengine/proxyclient"
	"github.com/openyurtio/raven/pkg/proxyengine/proxyserver"
	"github.com/openyurtio/raven/pkg/utils"
)

type ProxyEngine struct {
	nodeName             string
	nodeIP               string
	proxyServerAddresses []string
	gateway              *v1beta1.Gateway
	config               *config.Config
	client               client.Client
	engineOption         StatusOption
	proxyOption          *proxyOption
	ravenContext         context.Context
	proxyContext         ProxyContext
	queue                workqueue.RateLimitingInterface
}

func newProxyEngine(ctx context.Context, cfg *config.Config, client client.Client, opt StatusOption, queue workqueue.RateLimitingInterface) *ProxyEngine {
	return &ProxyEngine{
		nodeName:     cfg.NodeName,
		nodeIP:       cfg.NodeIP,
		config:       cfg,
		client:       client,
		engineOption: opt,
		ravenContext: ctx,
		proxyOption:  newProxyOption(),
		proxyContext: newProxyContext(ctx),
		queue:        queue,
	}
}

func (p *ProxyEngine) worker() {
	for p.processNextWorkItem() {
	}
}

func (p *ProxyEngine) processNextWorkItem() bool {
	obj, quit := p.queue.Get()
	if quit {
		return false
	}
	gw, ok := obj.(*v1beta1.Gateway)
	if !ok {
		return false
	}
	defer p.queue.Done(gw)

	err := p.handler(gw)
	p.handleEventErr(err, gw)
	return true
}

func (p *ProxyEngine) handler(gw *v1beta1.Gateway) error {
	curServer := p.proxyOption.GetServerStatus()
	curClient := p.proxyOption.GetClientStatus()
	specServer, specClient := p.getRole(enableProxy(gw))
	var err error
	p.gateway, err = utils.GetOwnGateway(p.client, p.nodeName)
	if err != nil {
		klog.Errorf("failed get gateway for %s, can not start proxy server", p.nodeName)
		return fmt.Errorf("failed get gateway name for %s, can not start proxy server", p.nodeName)
	}
	if !curServer && specServer {
		klog.Infoln(utils.FormatProxyServer("start raven l7 proxy server"))
		if p.gateway == nil {
			klog.Errorf("unknown gateway for node %s, can not start proxy server", p.nodeName)
		}
		pe := &proxyengine.EnginConfig{
			Name:                    p.nodeName,
			IP:                      p.nodeIP,
			GatewayName:             p.gateway.Name,
			CertDir:                 p.config.Proxy.ProxyServerCertDir,
			MetaAddress:             p.config.Proxy.ProxyMetricsAddress,
			CertIPs:                 p.config.Proxy.ProxyServerCertIPs,
			CertDNSNames:            p.config.Proxy.ProxyServerCertDNSNames,
			InterceptorUDSFile:      p.config.Proxy.InterceptorServerUDSFile,
			InternalSecureAddress:   p.config.Proxy.InternalSecureAddress,
			InternalInsecureAddress: p.config.Proxy.InternalInsecureAddress,
			ExposedAddress:          p.config.Proxy.ExternalAddress,
		}
		ctx := p.proxyContext.GetServerContext()
		ps, err := proxyserver.NewProxyServer(pe, p.client, p.config.Manager.GetConfig(), p.gateway.DeepCopy())
		if err != nil {
			klog.Errorf("failed to new proxy server, error %s", err.Error())
			return err
		}
		err = ps.Start(ctx)
		if err != nil {
			klog.Errorf("failed to start proxy server, error %s", err.Error())
		}
		p.proxyOption.SetServerStatus(specServer)
	} else if curServer && !specServer {
		klog.Infoln(utils.FormatProxyServer("Stop raven l7 proxy server"))
		cancel := p.proxyContext.GetServerCancelFunc()
		cancel()
		p.proxyOption.SetServerStatus(specServer)
		p.proxyContext.ReloadServerContext(p.ravenContext)
	}

	if !curClient && specClient {
		klog.Infoln(utils.FormatProxyClient("start raven l7 proxy client"))
		var err error
		dstAddr := getDestAddressForProxyClient(p.client, p.gateway)
		if len(dstAddr) < 1 {
			klog.Infoln(utils.FormatProxyClient("dest address is empty, will not connected it"))
			return nil
		}
		p.proxyServerAddresses = dstAddr
		pe := &proxyengine.EnginConfig{
			Name:        p.nodeName,
			IP:          p.nodeIP,
			CertDir:     p.config.Proxy.ProxyClientCertDir,
			MetaAddress: p.config.Proxy.ProxyMetricsAddress,
		}
		pc, err := proxyclient.NewProxyClient(pe, p.proxyServerAddresses, p.config.KubeConfig)
		if err != nil {
			klog.Errorf("failed to new proxy client, error %s", err.Error())
			return err
		}
		ctx := p.proxyContext.GetClientContext()
		err = pc.Start(ctx)
		if err != nil {
			klog.Errorf("failed to start proxy client, error %s", err.Error())
		}
		p.proxyOption.SetClientStatus(specClient)
		return nil
	} else if curClient && !specClient {
		klog.Infoln(utils.FormatProxyClient("stop raven l7 proxy client"))
		cancel := p.proxyContext.GetClientCancelFunc()
		cancel()
		p.proxyOption.SetClientStatus(specClient)
		p.proxyContext.ReloadClientContext(p.ravenContext)
	} else if curClient && specClient {
		dstAddr := getDestAddressForProxyClient(p.client, p.gateway)
		if len(dstAddr) < 1 {
			klog.Infoln(utils.FormatProxyClient("dest address is empty, will not connected it"))
			return nil
		}
		if computeHash(strings.Join(p.proxyServerAddresses, ",")) != computeHash(strings.Join(dstAddr, ",")) {
			klog.Infoln(utils.FormatProxyClient("Update raven l7 proxy client"))
			cancel := p.proxyContext.GetClientCancelFunc()
			cancel()
			time.Sleep(2 * time.Second)
			p.proxyContext.ReloadClientContext(p.ravenContext)
			p.proxyServerAddresses = dstAddr
			pe := &proxyengine.EnginConfig{
				Name:        p.nodeName,
				IP:          p.nodeIP,
				CertDir:     p.config.Proxy.ProxyClientCertDir,
				MetaAddress: p.config.Proxy.ProxyMetricsAddress,
			}
			pc, err := proxyclient.NewProxyClient(pe, p.proxyServerAddresses, p.config.KubeConfig)
			if err != nil {
				klog.Errorf("failed to new proxy server, error %s", err.Error())
				return err
			}
			ctx := p.proxyContext.GetClientContext()
			err = pc.Start(ctx)
			if err != nil {
				klog.Errorf("failed to start proxy client, error %s", err.Error())
			}
		}
	}
	return nil
}

func getDestAddressForProxyClient(client client.Client, ownGateway *v1beta1.Gateway) []string {
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
		if ownGateway != nil && ownGateway.Name == gw.Name {
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
	var gwList v1beta1.GatewayList
	err := p.client.List(p.ravenContext, &gwList)
	if err != nil {
		return
	}

	for _, gw := range gwList.Items {
		for _, aep := range gw.Status.ActiveEndpoints {
			if aep.NodeName == p.nodeName && aep.Type == v1beta1.Proxy {
				enableClient = true
				if gw.Spec.ExposeType != "" {
					enableServer = true
				} else {
					enableServer = false
				}
				return
			}
		}
		for _, node := range gw.Status.Nodes {
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

func (p *ProxyEngine) stopServers() {
	if p.proxyOption.GetServerStatus() {
		cancelServer := p.proxyContext.GetServerCancelFunc()
		cancelServer()
	}
	if p.proxyOption.GetClientStatus() {
		cancelClient := p.proxyContext.GetClientCancelFunc()
		cancelClient()
	}
}

func enableProxy(gw *v1beta1.Gateway) (enable bool) {
	enable = false
	for _, aep := range gw.Status.ActiveEndpoints {
		if aep.Type == v1beta1.Proxy {
			if aep.Config == nil {
				enable = false
				return
			}
			start, ok := aep.Config[ravenutil.RavenEnableProxy]
			if !ok {
				enable = false
				return
			}
			if strings.ToLower(start) == "true" {
				enable = true
			}
		}
	}
	return
}

func (p *ProxyEngine) handleEventErr(err error, event interface{}) {
	if err == nil {
		p.queue.Forget(event)
		return
	}
	if p.queue.NumRequeues(event) < utils.MaxRetries {
		klog.Infof("error syncing event %v: %v", event, err)
		p.queue.AddRateLimited(event)
		return
	}
	klog.Infof("dropping event %q out of the queue: %v", event, err)
	p.queue.Forget(event)
}

func computeHash(target string) string {
	hash := sha256.Sum224([]byte(target))
	return strings.ToLower(hex.EncodeToString(hash[:]))
}
