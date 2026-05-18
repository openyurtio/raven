//go:build linux

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

package vpndriver

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

func DefaultMTU() (int, error) {
	routes, err := netlink.RouteListFiltered(
		netlink.FAMILY_V4,
		&netlink.Route{Dst: nil},
		netlink.RT_FILTER_DST)
	if err != nil {
		return 0, err
	}

	if len(routes) > 1 {
		klog.Warning("more than one default route found")
	}

	for _, route := range routes {
		if defaultLink, err := netlink.LinkByIndex(route.LinkIndex); err == nil {
			klog.InfoS("find default link", "name", defaultLink.Attrs().Name)
			return defaultLink.Attrs().MTU, nil
		}
	}
	return 0, fmt.Errorf("error get default mtu")
}
