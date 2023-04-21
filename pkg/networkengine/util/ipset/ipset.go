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
	"sync"

	"github.com/gonetx/ipset"
	"k8s.io/klog/v2"
)

type IPSetInterface interface {
	List(options ...ipset.Option) (*ipset.Info, error)
	Name() string
	Add(entry string, options ...ipset.Option) error
	Del(entry string, options ...ipset.Option) error
	Flush() error
	Destroy() error
}

type ipSetWrapper struct {
	ipset.IPSet
}

var (
	once sync.Once
)

func check() error {
	if err := ipset.Check(); err != nil {
		klog.ErrorS(err, "error on ipset.Check")
		return err
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Check succeeded")
	}
	return nil
}

func New(setName string) (IPSetInterface, error) {
	var err error
	once.Do(func() {
		err = check()
	})
	if err != nil {
		return nil, err
	}

	set, err := ipset.New(setName, ipset.HashNet, ipset.Exist(true))
	if err != nil {
		klog.ErrorS(err, "error on ipset.Create", "setName", setName)
		return nil, err
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Create succeeded", "setName", setName)
	}
	return &ipSetWrapper{set}, nil
}

func (i *ipSetWrapper) List(options ...ipset.Option) (*ipset.Info, error) {
	info, err := i.IPSet.List(options...)
	if err != nil {
		klog.ErrorS(err, "error on ipset.List", "setName", i.Name())
		return nil, err
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.List succeeded", "setName", i.Name())
	}
	return info, nil
}

func (i *ipSetWrapper) Name() string {
	return i.IPSet.Name()
}

func (i *ipSetWrapper) Add(entry string, options ...ipset.Option) (err error) {
	err = i.IPSet.Add(entry, options...)
	if err != nil {
		klog.ErrorS(err, "error on ipset.Add", "setName", i.Name(), "entry", entry, "opts", options)
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Add succeeded", "setName", i.Name(), "entry", entry, "opts", options)
	}
	return
}

func (i *ipSetWrapper) Del(entry string, options ...ipset.Option) (err error) {
	err = i.IPSet.Del(entry, options...)
	if err != nil {
		klog.ErrorS(err, "error on ipset.Del", "setName", i.Name(), "entry", entry)
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Del succeeded", "setName", i.Name(), "entry", entry)
	}
	return
}

func (i *ipSetWrapper) Flush() (err error) {
	err = i.IPSet.Flush()
	if err != nil {
		klog.ErrorS(err, "error on ipset.Flush", "setName", i.Name())
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Flush succeeded", "setName", i.Name())
	}
	return
}

func (i *ipSetWrapper) Destroy() (err error) {
	err = i.IPSet.Destroy()
	if err != nil {
		klog.ErrorS(err, "error on ipset.Destroy")
		return
	}
	if klog.V(5).Enabled() {
		klog.V(5).InfoS("ipset.Destroy succeeded", "setName", i.Name())
	}
	return
}
