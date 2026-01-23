//go:build linux

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

package iptablesutil

import (
	"fmt"

	"github.com/coreos/go-iptables/iptables"
	"k8s.io/klog/v2"
)

type IPTablesInterface interface {
	NewChainIfNotExist(table, chain string) error
	ClearAndDeleteChain(table, chain string) error
	List(table, chain string) ([]string, error)
	AppendIfNotExists(table, chain string, rulespec ...string) error
	DeleteIfExists(table, chain string, rulespec ...string) error
	InsertIfNotExists(table, chain string, pos int, rulespec ...string) error
}

type iptablesWrapper struct {
	*iptables.IPTables
}

func New() (IPTablesInterface, error) {
	ipt, err := iptables.New(iptables.IPFamily(iptables.ProtocolIPv4), iptables.Timeout(5))
	if err != nil {
		return nil, fmt.Errorf("failed new iptables instance: %v", err)
	}
	klog.InfoS("succeeded to new iptables instance")

	return &iptablesWrapper{ipt}, nil
}

func (ipt *iptablesWrapper) NewChainIfNotExist(table, chain string) error {
	exists, err := ipt.ChainExists(table, chain)
	if err == nil && !exists {
		err = ipt.NewChain(table, chain)
	}
	if err != nil {
		return fmt.Errorf("failed to new iptables chain, table: %s, chain: %s, error: %v", table, chain, err)
	}
	klog.InfoS("succeeded to create iptables chain", "table", table, "chain", chain, "exists", exists)

	return nil
}

func (ipt *iptablesWrapper) ClearAndDeleteChain(table, chain string) error {
	err := ipt.IPTables.ClearAndDeleteChain(table, chain)
	if err != nil {
		return fmt.Errorf("failed to delete iptables chain, table: %s, chain: %s, error: %v", table, chain, err)
	}

	klog.InfoS("iptables.ClearAndDeleteChain succeeded", "table", table, "chain", chain)

	return nil
}

func (ipt *iptablesWrapper) List(table, chain string) ([]string, error) {
	rules, err := ipt.IPTables.List(table, chain)
	if err != nil {
		return nil, fmt.Errorf("failed to list iptables rules, table: %s, chain: %s, error: %v", table, chain, err)
	}

	klog.InfoS("iptables.List succeeded", "table", table, "chain", chain, "rules", rules)

	return rules, nil
}

func (ipt *iptablesWrapper) AppendIfNotExists(table, chain string, rulespec ...string) error {
	exists, err := ipt.Exists(table, chain, rulespec...)
	if err == nil && !exists {
		err = ipt.Append(table, chain, rulespec...)
	}
	if err != nil {
		return fmt.Errorf("failed to append iptables rule, table: %s, chain: %s, rulespec: %v, exists: %v, error: %v", table, chain, rulespec, exists, err)
	}

	klog.InfoS("iptables.Append succeeded", "table", table, "chain", chain, "rulespec", rulespec, "exists", exists)

	return nil
}

func (ipt *iptablesWrapper) DeleteIfExists(table, chain string, rulespec ...string) error {
	err := ipt.IPTables.DeleteIfExists(table, chain, rulespec...)
	if err != nil {
		return fmt.Errorf("failed to delete iptables rule, table: %s, chain: %s, rulespec: %v, error: %v", table, chain, rulespec, err)
	}

	klog.InfoS("iptables.Delete succeeded", "table", table, "chain", chain, "rulespec", rulespec)

	return nil
}

func (ipt *iptablesWrapper) InsertIfNotExists(table, chain string, pos int, rulespec ...string) error {
	exists, err := ipt.Exists(table, chain, rulespec...)
	if err == nil && !exists {
		err = ipt.Insert(table, chain, pos, rulespec...)
	}
	if err != nil {
		return fmt.Errorf("failed to insert iptables rule, table: %s, chain: %s, pos: %d, rulespec: %v, exists: %v, error: %v", table, chain, pos, rulespec, exists, err)
	}

	klog.InfoS("iptables.Insert succeeded", "table", table, "chain", chain, "pos", pos, "rulespec", rulespec, "exists", exists)

	return nil
}
