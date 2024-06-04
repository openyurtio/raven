//go:build linux
// +build linux

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

package ipsetutil

import (
	"fmt"

	"github.com/vishvananda/netlink"
	"k8s.io/klog/v2"
)

type IPSetInterface interface {
	List() (*netlink.IPSetResult, error)
	Name() string
	Add(entry *netlink.IPSetEntry) error
	Del(entry *netlink.IPSetEntry) error
	Flush() error
	Destroy() error
	Key(entry *netlink.IPSetEntry) string
}

var DefaultKeyFunc = EntryKey

type ipSetWrapper struct {
	setName string
	setType string
	keyFunc func(setEntry *netlink.IPSetEntry) string
}

type IpsetWrapperOption struct {
	KeyFunc func(setEntry *netlink.IPSetEntry) string
}

func New(setName, setTypeName string, options IpsetWrapperOption) (IPSetInterface, error) {
	if options.KeyFunc == nil {
		options.KeyFunc = DefaultKeyFunc
	}
	err := netlink.IpsetCreate(setName, setTypeName, netlink.IpsetCreateOptions{
		Replace: true,
	})
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetCreate", "setName", setName)
		return nil, err
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetCreate succeeded", "setName", setName)
	}
	return &ipSetWrapper{setName, setTypeName, options.KeyFunc}, nil
}

func (i *ipSetWrapper) List() (*netlink.IPSetResult, error) {
	info, err := netlink.IpsetList(i.Name())
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetList", "setName", i.Name())
		return nil, err
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetList succeeded", "setName", i.Name())
	}
	return info, nil
}

func (i *ipSetWrapper) Name() string {
	return i.setName
}

func (i *ipSetWrapper) Add(entry *netlink.IPSetEntry) (err error) {
	err = netlink.IpsetAdd(i.Name(), entry)
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetAdd", "setName", i.Name(), "entry", i.Key(entry))
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetAdd succeeded", "setName", i.Name(), "entry", i.Key(entry))
	}
	return
}

func (i *ipSetWrapper) Del(entry *netlink.IPSetEntry) (err error) {
	err = netlink.IpsetDel(i.Name(), entry)
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetDel", "setName", i.Name(), "entry", i.Key)
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetDel succeeded", "setName", i.Name(), "entry", i.Key(entry))
	}
	return
}

func (i *ipSetWrapper) Flush() (err error) {
	err = netlink.IpsetFlush(i.Name())
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetFlush", "setName", i.Name())
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetFlush succeeded", "setName", i.Name())
	}
	return
}

func (i *ipSetWrapper) Destroy() (err error) {
	err = netlink.IpsetDestroy(i.Name())
	if err != nil {
		klog.ErrorS(err, "error on netlink.IpsetDestroy")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("netlink.IpsetDestroy succeeded", "setName", i.Name())
	}
	return
}

func (i *ipSetWrapper) Key(entry *netlink.IPSetEntry) string {
	return i.keyFunc(entry)
}

func EntryKey(setEntry *netlink.IPSetEntry) string {
	return fmt.Sprintf("%s/%d", setEntry.IP.String(), setEntry.CIDR)
}
