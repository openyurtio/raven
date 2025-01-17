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
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/pkg/metrics"
	"github.com/openyurtio/raven/pkg/utils"
)

var (
	requestsPathPrefix = map[string]struct{}{
		"exec":          {},
		"attach":        {},
		"portForward":   {},
		"containerLogs": {}}
)

type WrapperHandler interface {
	Handler(handler http.Handler) http.Handler
}

type headerManger struct {
	client      client.Client
	gatewayName string
	isIPv4      bool
}

func NewHeaderManager(client client.Client, gatewayName string, isIPv4 bool) WrapperHandler {
	return &headerManger{
		client:      client,
		gatewayName: gatewayName,
		isIPv4:      isIPv4,
	}
}

func (h *headerManger) Handler(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			klog.Errorf("request is nil, skip it")
			return
		}
		oldHost := r.Host
		var host, ip, port string
		var err error
		if isAPIServerRequest(r) {
			klog.Infof("request from apiserver with host %s and url %s is processed by header manager", oldHost, r.URL.String())
			host, ip, port, err = h.getAPIServerRequestDestAddress(r)
			if err != nil {
				logAndHTTPError(w, http.StatusBadRequest, "request host %s and url %s is invalid, %s", r.Host, r.URL.String(), err.Error())
				return
			}
		} else {
			klog.Infof("normal request with host %s and url %s is processed by header manager", oldHost, r.URL.String())
			host, ip, port, err = h.getNormalRequestDestAddress(r)
			if err != nil {
				logAndHTTPError(w, http.StatusBadRequest, "request host %s and url %s is invalid, %s", r.Host, r.URL.String(), err.Error())
				return
			}
		}
		if host == "" || ip == "" || port == "" {
			logAndHTTPError(w, http.StatusBadRequest, "request host %s and url %s is invalid", r.Host, r.URL.String())
			return
		}
		// Complete request header information
		if r.TLS == nil {
			r.URL.Scheme = "http"
		} else {
			r.URL.Scheme = "https"
		}
		proxyDest := fmt.Sprintf("%s:%s", ip, port)
		proxyHost := fmt.Sprintf("%s:%s", host, port)
		proxyMode, err := h.getProxyMode(host)
		if err != nil {
			logAndHTTPError(w, http.StatusServiceUnavailable, "request host %s and url %s can not get proxy mode, error %s",
				r.Host, r.URL.String(), err.Error())
			return
		}

		r.Host = proxyDest
		r.Header.Set("Host", proxyDest)
		r.URL.Host = proxyDest
		r.Header.Set(utils.RavenProxyHostHeaderKey, proxyHost)
		r.Header.Set(utils.RavenProxyDestHeaderKey, proxyDest)
		r.Header.Set(utils.RavenProxyServerForwardModeHeaderKey, proxyMode)
		// observe metrics
		metrics.Metrics.IncInFlightRequests(r.Method, r.URL.Path)
		defer metrics.Metrics.DecInFlightRequests(r.Method, r.URL.Path)

		klog.Infof("start handling request %s %s, req.Host changed from %s to %s, remote address is %s",
			r.Method, r.URL.String(), oldHost, r.Host, r.RemoteAddr)
		start := time.Now()
		handler.ServeHTTP(w, r)
		klog.Infof("finish handle request %s %s, handle lasts %v", r.Method, r.URL.String(), time.Since(start))
	})
}

func (h *headerManger) getAPIServerRequestDestAddress(r *http.Request) (name, ip, port string, err error) {
	nodeName := r.Header.Get(utils.RavenProxyHostHeaderKey)
	if nodeName == "" {
		parts := strings.Split(r.URL.Path, "/")
		var pod v1.Pod
		err = h.client.Get(context.TODO(), client.ObjectKey{Namespace: parts[2], Name: parts[3]}, &pod)
		if err != nil {
			return "", "", "", err
		}
		if pod.Spec.NodeName != "" {
			nodeName = pod.Spec.NodeName
		}
	}
	var node v1.Node
	err = h.client.Get(context.TODO(), client.ObjectKey{Name: nodeName}, &node)
	if err != nil {
		return "", "", "", err
	}
	name, err = h.getGatewayNodeName(&node)
	if err != nil {
		return "", "", "", fmt.Errorf("can not find gateway node for node %s, error %s", node.Name, err.Error())
	}
	ip = getNodeIP(&node)
	if ip == "" {
		return "", "", "", fmt.Errorf("node %s ip is empty", node.Name)
	}
	_, port, _ = net.SplitHostPort(r.Header.Get(utils.RavenProxyDestHeaderKey))
	if port == "" {
		port = strconv.Itoa(int(node.Status.DaemonEndpoints.KubeletEndpoint.Port))
	}
	return name, ip, port, nil
}

func (h *headerManger) getNormalRequestDestAddress(r *http.Request) (name, ip, port string, err error) {
	nodeName := r.Header.Get(utils.RavenProxyHostHeaderKey)
	_, port, _ = net.SplitHostPort(r.Header.Get(utils.RavenProxyDestHeaderKey))
	if nodeName == "" || port == "" {
		nodeName, port, err = net.SplitHostPort(r.Host)
		if err != nil {
			return "", "", "", err
		}
	}
	ipAddress := net.ParseIP(nodeName)
	if ipAddress != nil {
		klog.Warningf("raven proxy server not support dest address %s and request.URL is %s", ipAddress, r.URL.String())
		return "", "", "", nil
	}
	var node v1.Node
	err = h.client.Get(context.TODO(), client.ObjectKey{Name: nodeName}, &node)
	if err != nil {
		return "", "", "", err
	}
	name, err = h.getGatewayNodeName(&node)
	if err != nil {
		return "", "", "", fmt.Errorf("can not find gateway node for node %s, error %s", node.Name, err.Error())
	}
	ip = getNodeIP(&node)
	if ip == "" {
		return "", "", "", fmt.Errorf("node %s ip is empty", node.Name)
	}
	return name, ip, port, nil
}

func (h *headerManger) getProxyMode(nodeName string) (string, error) {
	var gw v1beta1.Gateway
	err := h.client.Get(context.TODO(), types.NamespacedName{Name: h.gatewayName}, &gw)
	if err != nil {
		return "", err
	}
	for _, localNode := range gw.Status.Nodes {
		if localNode.NodeName == nodeName {
			return utils.RavenProxyServerForwardLocalMode, nil
		}
	}
	return utils.RavenProxyServerForwardRemoteMode, nil
}

func isAPIServerRequest(r *http.Request) bool {
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 5 {
		return false
	}
	if _, ok := requestsPathPrefix[parts[1]]; ok {
		return true
	}
	return false
}

func getNodeIP(node *v1.Node) string {
	var ip string
	if node != nil && node.Status.Addresses != nil {
		for _, nodeAddr := range node.Status.Addresses {
			if nodeAddr.Type == v1.NodeInternalIP {
				ip = nodeAddr.Address
				break
			}
		}
	}
	return ip
}

func (h *headerManger) getGatewayNodeName(node *v1.Node) (string, error) {
	gwName, ok := node.Labels[raven.LabelCurrentGateway]
	if !ok {
		return node.Name, nil
	}
	var gw v1beta1.Gateway
	err := h.client.Get(context.TODO(), types.NamespacedName{Name: gwName}, &gw)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return node.Name, nil
		}
		return "", err
	}
	if gw.Status.ActiveEndpoints == nil {
		return "", fmt.Errorf("no active endpoints for gw %s", gwName)
	}
	names := make([]string, 0)
	for _, ep := range gw.Status.ActiveEndpoints {
		if ep.Type == v1beta1.Proxy {
			names = append(names, ep.NodeName)
		}
	}
	if len(names) == 0 {
		return "", fmt.Errorf("no active endpoints for gw %s", gwName)
	}
	rand.New(rand.NewSource(time.Now().Unix()))
	return names[rand.Intn(len(names))], nil
}
