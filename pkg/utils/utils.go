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

package utils

import (
	"context"
	"fmt"

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func FormatProxyServer(format string, args ...interface{}) string {
	s := fmt.Sprintf(format, args...)
	return fmt.Sprintf("ProxyServer: %s", s)
}

func FormatProxyClient(format string, args ...interface{}) string {
	s := fmt.Sprintf(format, args...)
	return fmt.Sprintf("ProxyClient: %s", s)
}

func FormatTunnel(format string, args ...interface{}) string {
	s := fmt.Sprintf(format, args...)
	return fmt.Sprintf("Tunnel: %s", s)
}

func FormatRavenEngine(format string, args ...interface{}) string {
	s := fmt.Sprintf(format, args...)
	return fmt.Sprintf("RavenEngine: %s", s)
}

func GetOwnGateway(client client.Client, nodeName string) (*v1beta1.Gateway, error) {
	var gwList v1beta1.GatewayList
	err := client.List(context.TODO(), &gwList)
	if err != nil {
		return nil, err
	}
	for _, gw := range gwList.Items {
		for _, node := range gw.Status.Nodes {
			if node.NodeName == nodeName {
				return gw.DeepCopy(), nil
			}
		}
	}
	return nil, nil
}
