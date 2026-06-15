//go:build !linux

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

package netlinkutil

import (
	"errors"
	"net"

	"github.com/vishvananda/netlink"
)

// Non-linux stub: lets dependent packages compile for unit tests on macOS/Windows.
// All operations return ErrUnsupported. Production raven only runs on linux.

var ErrUnsupported = errors.New("netlinkutil: not supported on this platform")

var (
	RouteDel          = func(*netlink.Route) error { return ErrUnsupported }
	RouteReplace      = func(*netlink.Route) error { return ErrUnsupported }
	RouteAdd          = func(*netlink.Route) error { return ErrUnsupported }
	RouteListFiltered = func(int, *netlink.Route, uint64) ([]netlink.Route, error) { return nil, ErrUnsupported }
	RouteList         = func(netlink.Link, int) ([]netlink.Route, error) { return nil, ErrUnsupported }
	RouteGet          = func(net.IP) ([]netlink.Route, error) { return nil, ErrUnsupported }

	RuleListFiltered = func(int, *netlink.Rule, uint64) ([]netlink.Rule, error) { return nil, ErrUnsupported }
	RuleAdd          = func(*netlink.Rule) error { return ErrUnsupported }
	RuleDel          = func(*netlink.Rule) error { return ErrUnsupported }

	XfrmPolicyFlush = func() error { return ErrUnsupported }
	XfrmStateFlush  = func() error { return ErrUnsupported }

	NeighAdd     = func(*netlink.Neigh) error { return ErrUnsupported }
	NeighReplace = func(*netlink.Neigh) error { return ErrUnsupported }
	NeighList    = func(int, int) ([]netlink.Neigh, error) { return nil, ErrUnsupported }
	NeighDel     = func(*netlink.Neigh) error { return ErrUnsupported }

	LinkByName  = func(string) (netlink.Link, error) { return nil, ErrUnsupported }
	LinkByIndex = func(int) (netlink.Link, error) { return nil, ErrUnsupported }
)
