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

package proxyclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	certificatesv1 "k8s.io/api/certificates/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
	anp "sigs.k8s.io/apiserver-network-proxy/pkg/agent"

	"github.com/openyurtio/raven/pkg/proxyengine"
	"github.com/openyurtio/raven/pkg/utils"
	"github.com/openyurtio/raven/pkg/utils/certmanager"
	"github.com/openyurtio/raven/pkg/utils/certmanager/factory"
)

type ProxyClient struct {
	name        string
	ip          string
	certDir     string
	metaAddress string
	servers     map[string]*tls.Config
	client      kubernetes.Interface
}

func NewProxyClient(proxyCfg *proxyengine.EnginConfig, addresses []string, kubeCfg *rest.Config) (*ProxyClient, error) {
	if len(addresses) < 1 {
		return nil, fmt.Errorf("failed to get proxy server address")
	}
	client, err := kubernetes.NewForConfig(kubeCfg)
	if err != nil {
		return nil, err
	}
	servers := make(map[string]*tls.Config)
	for _, addr := range addresses {
		servers[addr] = nil
	}
	return &ProxyClient{name: proxyCfg.Name, ip: proxyCfg.IP, certDir: proxyCfg.CertDir, metaAddress: proxyCfg.MetaAddress, client: client, servers: servers}, nil
}

func (c *ProxyClient) Start(ctx context.Context) error {
	certMgrCfg := &factory.CertManagerConfig{
		ComponentName: utils.RavenProxyClientName,
		CertDir:       c.certDir,
		SignerName:    certificatesv1.KubeAPIServerClientSignerName,
		CommonName:    utils.RavenProxyClientCSRCN,
		Organizations: []string{utils.RavenCSROrg},
		DNSNames:      []string{c.name},
		IPs:           []net.IP{net.ParseIP(c.ip)},
	}
	clientCertManager, err := factory.NewCertManagerFactory(c.client).New(certMgrCfg)
	if err != nil {
		klog.Errorf("failed to new cert manager factory for proxy client %s, error %s", c.name, err.Error())
		return fmt.Errorf("failed to new cert manager factory for proxy client %s, error %s", c.name, err.Error())
	}
	clientCertManager.Start()
	defer clientCertManager.Stop()
	_ = wait.PollUntil(5*time.Second, func() (bool, error) {
		if clientCertManager.Current() != nil {
			return true, nil
		}
		klog.Infof("certificate %s not signed, waiting...", certMgrCfg.CommonName)
		return false, nil
	}, ctx.Done())
	for addr := range c.servers {
		tlsCfg, err := certmanager.GenTLSConfigUseCertMgrAndCA(clientCertManager, addr, utils.RavenCAFile)
		if err != nil {
			klog.Error("failed to generate TLS Config")
			return fmt.Errorf("failed to generate TLS Config")
		}
		c.servers[addr] = tlsCfg
	}
	klog.Infof("certificate %s ok", certMgrCfg.CommonName)

	utils.RunMetaServer(ctx, c.metaAddress)
	c.run(ctx.Done())
	return nil
}

func (c *ProxyClient) run(stopCh <-chan struct{}) {
	for addr, cert := range c.servers {
		client := c.NewClient(addr, cert, stopCh)
		client.Serve()
		klog.Infof("start serving grpc request redirected from %s", addr)
	}
}

func (c *ProxyClient) NewClient(dstAddr string, tlsCfg *tls.Config, stopCh <-chan struct{}) *anp.ClientSet {
	dialOption := grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg))
	cc := &anp.ClientSetConfig{
		AgentID:                 c.name,
		Address:                 dstAddr,
		AgentIdentifiers:        fmt.Sprintf("host=%s", c.name),
		SyncInterval:            5 * time.Second,
		ProbeInterval:           5 * time.Second,
		DialOptions:             []grpc.DialOption{dialOption},
		ServiceAccountTokenPath: "",
	}
	return cc.NewAgentClientSet(stopCh)
}
