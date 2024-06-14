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
	"net"
	"net/http"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"k8s.io/klog/v2"
	anpserver "sigs.k8s.io/apiserver-network-proxy/pkg/server"
	anpagent "sigs.k8s.io/apiserver-network-proxy/proto/agent"
)

type Server interface {
	Run(ctx context.Context)
}

type proxies struct {
	handler     http.Handler
	udsSockFile string
}

func NewProxies(handler http.Handler, udsFile string) Server {
	return &proxies{handler: handler, udsSockFile: udsFile}
}

func (p *proxies) Run(ctx context.Context) {
	go func(ctx context.Context) {
		klog.Info("start listen unix %s", p.udsSockFile)
		defer klog.Info("finish listen unix %s", p.udsSockFile)
		server := &http.Server{
			Handler:     p.handler,
			ReadTimeout: 10 * time.Second,
		}
		listen, err := net.Listen("unix", p.udsSockFile)
		if err != nil {
			klog.Errorf("proxies failed to listen uds %s", err.Error())
		}
		defer listen.Close()
		go func(ctx context.Context) {
			<-ctx.Done()
			err := server.Shutdown(context.TODO())
			if err != nil {
				klog.Errorf("failed to shutdown proxies server, error %s", err.Error())
			}
		}(ctx)
		if err := server.Serve(listen); err != nil {
			klog.Errorf("proxies failed to serving request through uds %s", err.Error())
		}

	}(ctx)
}

type master struct {
	handler      http.Handler
	secureAddr   string
	insecureAddr string
	tlsCfg       *tls.Config
}

func NewMaster(handler http.Handler, tlsCfg *tls.Config, secureAddr, insecureAddr string) Server {
	return &master{handler: handler, tlsCfg: tlsCfg, secureAddr: secureAddr, insecureAddr: insecureAddr}
}

func (m *master) Run(ctx context.Context) {
	go func(ctx context.Context) {
		klog.Info("start handling https request from master at %s", m.secureAddr)
		defer klog.Info("finish handling https request from master at %s", m.secureAddr)
		server := http.Server{
			Addr:         m.secureAddr,
			Handler:      m.handler,
			ReadTimeout:  10 * time.Second,
			TLSConfig:    m.tlsCfg,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		go func(ctx context.Context) {
			<-ctx.Done()
			err := server.Shutdown(context.TODO())
			if err != nil {
				klog.Errorf("failed to shutdown master secure server, error %s", err.Error())
			}
		}(ctx)
		if err := server.ListenAndServeTLS("", ""); err != nil {
			klog.Errorf("failed to serve https request from master: %s", err.Error())
		}
	}(ctx)

	go func(ctx context.Context) {
		klog.Infof("start handling https request from master at %s", m.insecureAddr)
		defer klog.Infof("finish handling https request from master at %s", m.insecureAddr)
		server := http.Server{
			Addr:         m.insecureAddr,
			Handler:      m.handler,
			ReadTimeout:  10 * time.Second,
			TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler)),
		}
		go func(ctx context.Context) {
			<-ctx.Done()
			err := server.Shutdown(context.TODO())
			if err != nil {
				klog.Errorf("failed to shutdown master insecure server, error %s", err.Error())
			}
		}(ctx)
		if err := server.ListenAndServe(); err != nil {
			klog.Errorf("failed to serve https request from master: %s", err.Error())
		}
	}(ctx)
}

type agent struct {
	address     string
	tlsCfg      *tls.Config
	proxyServer *anpserver.ProxyServer
}

func NewAgent(tlsCfg *tls.Config, proxyServer *anpserver.ProxyServer, address string) Server {
	return &agent{tlsCfg: tlsCfg, proxyServer: proxyServer, address: address}
}

func (c *agent) Run(ctx context.Context) {
	go func(ctx context.Context) {
		klog.Info("start handling grpc request from proxy client at %s", c.address)
		defer klog.Info("finish handling grpc request from proxy client at %s", c.address)
		ka := keepalive.ServerParameters{
			MaxConnectionIdle: 10 * time.Minute,
			Time:              10 * time.Second,
			Timeout:           5 * time.Second,
		}
		grpcServer := grpc.NewServer(grpc.KeepaliveParams(ka), grpc.Creds(credentials.NewTLS(c.tlsCfg)))
		anpagent.RegisterAgentServiceServer(grpcServer, c.proxyServer)
		listen, err := net.Listen("tcp", c.address)
		if err != nil {
			klog.Errorf("failed to listen to agent on %s: %s", c.address, err.Error())
			return
		}
		defer listen.Close()
		go func(ctx context.Context) {
			<-ctx.Done()
			grpcServer.Stop()
		}(ctx)
		if err := grpcServer.Serve(listen); err != nil {
			klog.Errorf("failed to server grpc request from proxy agent server, error %s", err.Error())
		}
	}(ctx)
}
