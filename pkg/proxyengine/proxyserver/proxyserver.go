/*
Copyright 2023 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package proxyserver

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	utilnet "k8s.io/utils/net"
	anpserver "sigs.k8s.io/apiserver-network-proxy/pkg/server"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/pkg/proxyengine"
	"github.com/openyurtio/raven/pkg/utils"
	"github.com/openyurtio/raven/pkg/utils/certmanager"
	"github.com/openyurtio/raven/pkg/utils/certmanager/factory"
)

type ProxyServer struct {
	nodeName                string
	nodeIP                  string
	metaAddress             string
	exposedAddress          string
	internalInsecureAddress string
	internalSecureAddress   string
	certDir                 string
	interceptorUDSFile      string
	certDNSNames            []string
	gateway                 *v1beta1.Gateway
	certIPs                 []net.IP
	clientSet               kubernetes.Interface
	client                  client.Client
	rootCert                *x509.CertPool
	serverTLSConfig         *tls.Config
	proxyTLSConfig          *tls.Config
}

func NewProxyServer(cfg *proxyengine.EnginConfig, client client.Client, kubeCfg *rest.Config, gw *v1beta1.Gateway) (*ProxyServer, error) {
	certIPs := make([]net.IP, 0)
	if cfg.CertIPs != "" {
		for _, ip := range strings.Split(cfg.CertIPs, ",") {
			if addr := net.ParseIP(ip); addr != nil {
				certIPs = append(certIPs, addr)
			}
		}
	}
	certDNSNames := make([]string, 0)
	if cfg.CertDNSNames != "" {
		for _, dns := range strings.Split(cfg.CertDNSNames, ",") {
			if dns != "" {
				certDNSNames = append(certDNSNames, dns)
			}
		}
	}
	server := &ProxyServer{
		nodeName:                cfg.Name,
		gateway:                 gw,
		nodeIP:                  cfg.IP,
		metaAddress:             cfg.MetaAddress,
		internalInsecureAddress: cfg.InternalInsecureAddress,
		internalSecureAddress:   cfg.InternalSecureAddress,
		exposedAddress:          cfg.ExposedAddress,
		interceptorUDSFile:      cfg.InterceptorUDSFile,
		certDir:                 cfg.CertDir,
		certDNSNames:            certDNSNames,
		certIPs:                 certIPs,
		client:                  client,
	}
	var err error
	server.clientSet, err = kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, err
	}
	server.rootCert, err = certmanager.GenCertPoolUseCA(utils.RavenCAFile)
	if err != nil {
		return nil, err
	}
	return server, nil
}

func (c *ProxyServer) Start(ctx context.Context) error {
	dnsNames, IPs := c.getProxyServerIPsAndDNSName()
	certFactory := factory.NewCertManagerFactory(c.clientSet)
	serverCertCfg := &factory.CertManagerConfig{
		IPs: append(c.certIPs, IPs...),
		IPGetter: func() ([]net.IP, error) {
			_, ips := c.getProxyServerIPsAndDNSName()
			return ips, nil
		},
		DNSNames:       append(c.certDNSNames, dnsNames...),
		ComponentName:  utils.RavenProxyServerName,
		CertDir:        c.certDir,
		SignerName:     certificatesv1.KubeletServingSignerName,
		CommonName:     fmt.Sprintf("system:node:%s", utils.RavenProxyServerCSRCN),
		Organizations:  []string{user.NodesGroup},
		ForServerUsage: true,
	}
	serverCertMgr, err := certFactory.New(serverCertCfg)
	if err != nil {
		return fmt.Errorf("failed to new server cert manager factory for proxy server %s, error %s", c.nodeName, err.Error())
	}
	serverCertMgr.Start()
	defer serverCertMgr.Stop()

	proxyCertCfg := &factory.CertManagerConfig{
		CertDir:       c.certDir,
		ComponentName: utils.RavenProxyUserName,
		SignerName:    certificatesv1.KubeAPIServerClientSignerName,
		Organizations: []string{utils.RavenCSROrg},
		CommonName:    utils.RavenProxyUserCSRCN,
	}
	proxyCertMgr, err := certFactory.New(proxyCertCfg)
	if err != nil {
		return fmt.Errorf("failed to new proxy cert manager factory for proxy server %s, error %s", c.nodeName, err.Error())
	}
	proxyCertMgr.Start()

	_ = wait.PollUntil(5*time.Second, func() (bool, error) {
		if serverCertMgr.Current() != nil && proxyCertMgr.Current() != nil {
			return true, nil
		}
		klog.Infof("certificate %s and %s not signed, waiting...", serverCertCfg.ComponentName, proxyCertCfg.ComponentName)
		return false, nil
	}, ctx.Done())

	klog.Infof("certificate %s and %s ok", serverCertCfg.ComponentName, proxyCertCfg.ComponentName)
	c.serverTLSConfig, err = certmanager.GenTLSConfigUseCurrentCertAndCertPool(serverCertMgr.Current, c.rootCert, "server")
	if err != nil {
		return err
	}
	c.proxyTLSConfig, err = certmanager.GenTLSConfigUseCurrentCertAndCertPool(proxyCertMgr.Current, c.rootCert, "client")
	if err != nil {
		return err
	}
	utils.RunMetaServer(ctx, c.metaAddress)
	err = c.runServers(ctx)
	if err != nil {
		return fmt.Errorf("failed to run proxy servers, error %s", err.Error())
	}
	return nil
}

func (c *ProxyServer) runServers(ctx context.Context) error {
	klog.Info("start proxy server")
	strategy := []anpserver.ProxyStrategy{anpserver.ProxyStrategyDestHost}
	proxyServer := anpserver.NewProxyServer(c.nodeName, strategy, 1, &anpserver.AgentTokenAuthenticationOptions{})
	NewProxies(&anpserver.Tunnel{Server: proxyServer}, c.interceptorUDSFile).Run(ctx)
	interceptor := NewInterceptor(c.interceptorUDSFile, c.proxyTLSConfig)
	headerMgr := NewHeaderManager(c.client, c.gateway.GetName(), utilnet.IsIPv4String(c.nodeIP))
	NewMaster(headerMgr.Handler(interceptor), c.serverTLSConfig, c.internalSecureAddress, c.internalInsecureAddress).Run(ctx)
	NewAgent(c.serverTLSConfig, proxyServer, c.exposedAddress).Run(ctx)
	return nil
}

func (c *ProxyServer) getProxyServerIPsAndDNSName() (dnsName []string, ipAddr []net.IP) {

	ipAddr = append(ipAddr, net.ParseIP(c.nodeIP))
	ipAddr = append(ipAddr, net.ParseIP(utils.DefaultLoopBackIP4))
	ipAddr = append(ipAddr, c.certIPs...)
	dnsName = append(dnsName, c.nodeName)

	var svc v1.Service
	err := c.client.Get(context.TODO(), types.NamespacedName{Namespace: utils.WorkingNamespace, Name: utils.GatewayProxyInternalService}, &svc)
	if err != nil {
		klog.Errorf("failed to get internal service %s/%s to get proxy server IPs and DNSNames, error %s",
			svc.GetNamespace(), svc.GetName(), err.Error())
		return
	}
	dnsName = append(dnsName, getDefaultDomainsForSvc(svc.GetNamespace(), svc.GetName())...)
	if svc.Spec.ClusterIP != "" {
		ipAddr = append(ipAddr, net.ParseIP(svc.Spec.ClusterIP))
	}
	var svcList v1.ServiceList
	err = c.client.List(context.TODO(), &svcList, &client.ListOptions{
		LabelSelector: labels.Set{
			raven.LabelCurrentGateway:          c.gateway.GetName(),
			utils.LabelCurrentGatewayType:      v1beta1.Proxy,
			utils.LabelCurrentGatewayEndpoints: c.nodeName,
		}.AsSelector(),
	})
	if err != nil {
		klog.Errorf("failed to get public serivce for gateway %s, node %s to get proxy server IPs and DNSNames, error %s",
			c.gateway.GetName(), c.nodeName, err.Error())
		return
	}

	for _, svc = range svcList.Items {
		dnsName = append(dnsName, getDefaultDomainsForSvc(svc.GetNamespace(), svc.GetName())...)
		dnsName = append(dnsName, getExternalDNSName(&svc)...)
		ipAddr = append(ipAddr, getExternalIPForSvc(&svc)...)
		if svc.Spec.ClusterIP != "" {
			ipAddr = append(ipAddr, net.ParseIP(svc.Spec.ClusterIP))
		}
		if svc.Status.LoadBalancer.Ingress != nil {
			for _, ing := range svc.Status.LoadBalancer.Ingress {
				if ing.IP != "" {
					ipAddr = append(ipAddr, net.ParseIP(ing.IP))
				}
				if ing.Hostname != "" {
					dnsName = append(dnsName, ing.Hostname)
				}
			}
		}
	}
	klog.V(3).Info("cert address is %v", ipAddr)
	return
}

func getExternalIPForSvc(svc *v1.Service) []net.IP {
	ret := make([]net.IP, 0)
	if svc.Annotations == nil {
		return ret
	}
	_, ok := svc.Annotations["raven.openyurt.io/public-service-external-ip"]
	if !ok {
		return ret
	}
	addresses := strings.Split(svc.Annotations["raven.openyurt.io/public-service-external-ip"], ",")
	for _, val := range addresses {
		ip := net.ParseIP(strings.TrimSpace(val))
		if ip != nil {
			ret = append(ret, ip)
		}
	}
	return ret
}

func getExternalDNSName(svc *v1.Service) []string {
	ret := make([]string, 0)
	if svc.Annotations == nil {
		return ret
	}
	_, ok := svc.Annotations["raven.openyurt.io/public-service-external-dns-name"]
	if !ok {
		return ret
	}
	dnsNames := strings.Split(svc.Annotations["raven.openyurt.io/public-service-external-dns-name"], ",")
	for _, val := range dnsNames {
		ret = append(ret, strings.TrimSpace(val))
	}
	return ret
}

func getDefaultDomainsForSvc(ns, name string) []string {
	domains := make([]string, 0)
	if len(ns) == 0 || len(name) == 0 {
		return domains
	}
	domains = append(domains, name)
	domains = append(domains, fmt.Sprintf("%s.%s", name, ns))
	domains = append(domains, fmt.Sprintf("%s.%s.svc", name, ns))
	domains = append(domains, fmt.Sprintf("%s.%s.svc.cluster.local", name, ns))
	return domains
}
