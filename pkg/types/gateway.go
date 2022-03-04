/*
 * Copyright 2022 The OpenYurt Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package types

import (
	"net"
	"strconv"
)

const (
	EnableCloudForwardingConfig = "enable-cloud-forwarding"
	IsCloudEndpoint             = "is-cloud-endpoint"
)

type Endpoint struct {
	Subnets    []string
	ID         string
	Vtep       net.IP
	Topologies map[string]bool
	Config     map[string]string
}

type Gateway struct {
	GatewayIP net.IP
	RemoteIPs map[string]net.IP
	Routes    map[string]Route
}

func (e *Endpoint) String() string {
	return e.ID
}

func GetBoolConfig(config map[string]string, name string) (bool, error) {
	value, ok := config[name]
	if ok && len(value) != 0 {
		v, err := strconv.ParseBool(value)
		if err != nil {
			return false, err
		}
		return v, nil
	}
	return false, nil
}
