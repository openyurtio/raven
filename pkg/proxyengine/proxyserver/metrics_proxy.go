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
	"fmt"
	"net"
	"net/http"
	"time"

	"k8s.io/klog/v2"
)

type MetricsProxyPortMapping struct {
	ListenPort string
	TargetPort string
	UseTLS     bool
}

var MetricsProxyPorts = []MetricsProxyPortMapping{
	{ListenPort: "10290", TargetPort: "9445", UseTLS: false},
	{ListenPort: "10291", TargetPort: "9100", UseTLS: true},
	{ListenPort: "10292", TargetPort: "10250", UseTLS: true},
}

type portRewriteHandler struct {
	targetPort string
	next       http.Handler
}

func NewPortRewriteHandler(targetPort string, next http.Handler) http.Handler {
	return &portRewriteHandler{targetPort: targetPort, next: next}
}

func (h *portRewriteHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	r.Host = net.JoinHostPort(host, h.targetPort)
	h.next.ServeHTTP(w, r)
}

type metricsProxyServer struct {
	address string
	tlsCfg  *tls.Config
	handler http.Handler
}

func NewMetricsProxyServer(handler http.Handler, tlsCfg *tls.Config, address string) Server {
	return &metricsProxyServer{handler: handler, tlsCfg: tlsCfg, address: address}
}

func (m *metricsProxyServer) Run(stopCh <-chan struct{}) {
	go func() {
		useTLS := m.tlsCfg != nil
		scheme := "http"
		if useTLS {
			scheme = "https"
		}
		klog.Infof("start handling %s metrics proxy request at %s", scheme, m.address)
		defer klog.Infof("finish handling %s metrics proxy request at %s", scheme, m.address)

		server := &http.Server{
			Addr:        m.address,
			Handler:     m.handler,
			ReadTimeout: 10 * time.Second,
		}
		if useTLS {
			server.TLSConfig = m.tlsCfg
			server.TLSNextProto = make(map[string]func(*http.Server, *tls.Conn, http.Handler))
		}

		go func() {
			<-stopCh
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			if err := server.Shutdown(shutdownCtx); err != nil {
				klog.Errorf("failed to shutdown metrics proxy server at %s, error %s", m.address, err.Error())
			}
			cancel()
		}()

		var err error
		if useTLS {
			err = server.ListenAndServeTLS("", "")
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && err != http.ErrServerClosed {
			klog.Errorf("failed to serve metrics proxy request at %s: %s", m.address, err.Error())
		}
	}()
}

func startMetricsProxyServers(nodeIP string, tlsCfg *tls.Config, baseHandler http.Handler, stopCh <-chan struct{}) {
	for _, mapping := range MetricsProxyPorts {
		address := fmt.Sprintf("%s:%s", nodeIP, mapping.ListenPort)
		handler := NewPortRewriteHandler(mapping.TargetPort, baseHandler)
		var serverTLS *tls.Config
		if mapping.UseTLS {
			serverTLS = tlsCfg
		}
		NewMetricsProxyServer(handler, serverTLS, address).Run(stopCh)
		klog.Infof("metrics proxy port mapping: %s -> %s (tls=%v)", mapping.ListenPort, mapping.TargetPort, mapping.UseTLS)
	}
}
