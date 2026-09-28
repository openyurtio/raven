//go:build linux

/*
Copyright 2026 The OpenYurt Authors.

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

package wireguard

import (
	"context"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
	"time"

	iptablesutil "github.com/openyurtio/raven/pkg/networkengine/util/iptables"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

type peerControl struct {
	fakeControl
	readErr, writeErr error
}

func (c *peerControl) Device(name string) (*wgtypes.Device, error) {
	if c.readErr != nil {
		return nil, c.readErr
	}
	return c.fakeControl.Device(name)
}
func (c *peerControl) ConfigureDevice(name string, cfg wgtypes.Config) error {
	if len(cfg.Peers) > 0 {
		if c.writeErr != nil {
			return c.writeErr
		}
		for _, p := range cfg.Peers {
			if p.Remove {
				c.dev.Peers = nil
				continue
			}
			c.dev.Peers = []wgtypes.Peer{{PublicKey: p.PublicKey, PresharedKey: *p.PresharedKey,
				Endpoint: p.Endpoint, PersistentKeepaliveInterval: *p.PersistentKeepaliveInterval, AllowedIPs: p.AllowedIPs}}
		}
	}
	return c.fakeControl.ConfigureDevice(name, cfg)
}

func TestGatewayApplyRecoveryAndConfigurationPolicy(t *testing.T) {
	for _, stage := range []string{"success", "peer read", "peer write", "rejected", "routes", "nat", "no peers", "health", "start"} {
		t.Run(stage, func(t *testing.T) {
			w, f := recoveryFixture()
			f.addErr = syscall.EOPNOTSUPP
			control := &peerControl{}
			control.dev.Type = wgtypes.Userspace
			f.d.newClient = func() (controlClient, error) { return control, nil }
			w.nodeName = "local"
			key := wgtypes.Key{2}
			network := &types.Network{
				LocalEndpoint: &types.Endpoint{NodeName: "local", Config: map[string]string{PublicKey: w.privateKey.PublicKey().String()}},
				RemoteEndpoints: map[types.GatewayName]*types.Endpoint{"remote": {
					NodeName: "remote", PublicIP: "192.0.2.2", Subnets: []string{"10.2.0.0/16"}, Config: map[string]string{PublicKey: key.String()},
				}},
			}
			routes, nat, withdrawals := 0, 0, 0
			w.withdrawRoutes = func() error { withdrawals++; return nil }
			f.process.onStop = func() {
				f.link = nil
				control.dev.Peers = nil
				control.dev.PrivateKey = wgtypes.Key{}
			}
			w.applyRoutes = func(*types.Network) error {
				routes++
				if stage == "peer read" {
					control.readErr = io.EOF
				}
				if stage == "routes" {
					return syscall.EPERM
				}
				return nil
			}
			w.applyNAT = func(*types.Network) error {
				nat++
				if stage == "nat" {
					return syscall.EPERM
				}
				return nil
			}
			if stage == "peer write" {
				control.writeErr = io.EOF
			}
			if stage == "rejected" {
				control.writeErr = syscall.EINVAL
			}
			if stage == "no peers" {
				network.RemoteEndpoints["remote"].Config = nil
			}
			if stage == "health" {
				f.d.selected = backendUserspace
				w.fault = io.EOF
			}
			if stage == "start" {
				f.process.start = func() error { return syscall.ENOENT }
			}
			t.Cleanup(func() {
				if err := w.Cleanup(); err != nil {
					t.Error(err)
				}
			})
			err := w.Apply(network, func(*types.Network) (int, error) { return 1400, nil })
			if stage == "health" || stage == "start" {
				if err == nil || routes != 0 || nat != 0 || w.configured || w.recovery.err == nil {
					t.Fatalf("startup/health error did not short circuit: %v", err)
				}
				return
			}
			transport := stage == "peer read" || stage == "peer write"
			if stage == "no peers" {
				if err != nil || f.process.starts != 0 || routes != 0 || w.configured {
					t.Fatalf("unneeded device started: %v", err)
				}
				return
			}
			if stage == "success" {
				if err != nil || !w.configured || routes != 1 || nat != 1 || len(control.dev.Peers) != 1 {
					t.Fatalf("incomplete reconciliation: %v", err)
				}
				w.SetNetworkReady(true)
				if !w.ready {
					t.Fatal("completed network not ready")
				}
				configs := len(control.configs)
				if err := w.Apply(network, func(*types.Network) (int, error) { return 1400, nil }); err != nil {
					t.Fatal(err)
				}
				if len(control.configs) != configs || f.process.starts != 1 {
					t.Fatal("unchanged reconciliation reset peers or process")
				}
				return
			}
			if err == nil || w.configured || w.ready {
				t.Fatal("failed reconciliation reported readiness")
			}
			if transport {
				if f.process.running || withdrawals == 0 || w.recovery.err == nil || w.NextReconcile() <= 0 {
					t.Fatal("transport failure did not withdraw and schedule recovery")
				}
				w.recovery.next = time.Now().Add(-time.Second)
				control.readErr, control.writeErr = nil, nil
				stage = "success"
				network.RemoteEndpoints["remote"].Subnets = []string{"10.3.0.0/16"}
				if err := w.Apply(network, func(*types.Network) (int, error) { return 1400, nil }); err != nil {
					t.Fatal(err)
				}
				w.SetNetworkReady(true)
				if !w.ready || f.process.starts != 2 || len(control.dev.Peers) != 1 || control.dev.Peers[0].AllowedIPs[0].String() != "10.3.0.0/16" || control.dev.PrivateKey != w.privateKey || w.recovery.err != nil {
					t.Fatal("recovery failed to restore peers/key/readiness")
				}
			} else if !f.process.running || f.process.starts != 1 || withdrawals != 0 || w.recovery.err != nil {
				t.Fatal("configuration error restarted userspace")
			}
		})
	}
}

type cleanupIPTables struct {
	iptablesutil.IPTablesInterface
	calls []string
	fail  string
	err   error
}

func (c *cleanupIPTables) record(op, table, chain string) error {
	if table != iptablesutil.NatTable {
		return errors.New("wrong table")
	}
	c.calls = append(c.calls, op+":"+chain)
	if c.fail == op {
		return c.err
	}
	return nil
}
func (c *cleanupIPTables) NewChainIfNotExist(table, chain string) error {
	return c.record("ensure", table, chain)
}
func (c *cleanupIPTables) DeleteIfExists(table, chain string, rules ...string) error {
	if strings.Join(rules, " ") != "-m comment --comment raven traffic should skip NAT -o "+DeviceName+" -j "+iptablesutil.RavenPostRoutingChain {
		return errors.New("wrong jump rule")
	}
	return c.record("unlink", table, chain)
}
func (c *cleanupIPTables) ClearAndDeleteChain(table, chain string) error {
	return c.record("delete", table, chain)
}

func TestNATCleanupContinuesAfterErrorsAndRetries(t *testing.T) {
	for _, stage := range []string{"success", "ensure", "unlink", "delete"} {
		t.Run(stage, func(t *testing.T) {
			failure, setFailure := errors.New("iptables failed"), errors.New("ipset busy")
			ipt := &cleanupIPTables{fail: stage, err: failure}
			setCalls := 0
			w := &wireguard{iptables: ipt, cleanupIPSet: func() error { setCalls++; return setFailure }}
			err := w.cleanupRavenNAT()
			if !errors.Is(err, setFailure) || (stage != "success" && !errors.Is(err, failure)) || setCalls != 1 {
				t.Fatalf("lost errors or skipped ipset: %v", err)
			}
			want := "ensure:" + iptablesutil.RavenPostRoutingChain
			if stage != "ensure" {
				want += ",unlink:" + iptablesutil.PostRoutingChain + ",delete:" + iptablesutil.RavenPostRoutingChain
			}
			if strings.Join(ipt.calls, ",") != want {
				t.Fatalf("cleanup order = %v", ipt.calls)
			}
			ipt.fail, ipt.calls = "", nil
			w.cleanupIPSet = func() error { setCalls++; return nil }
			for i := 0; i < 2; i++ {
				if err := w.cleanupRavenNAT(); err != nil {
					t.Fatal(err)
				}
			}
			if setCalls != 3 {
				t.Fatal("cleanup retry skipped ipset")
			}
		})
	}
	if err := (&wireguard{}).cleanupRavenNAT(); err != nil {
		t.Fatal(err)
	}
}

func TestIPSetCleanupOnlyRemovesOwnedSet(t *testing.T) {
	for _, stage := range []string{"absent", "present", "list", "flush", "destroy"} {
		t.Run(stage, func(t *testing.T) {
			failure := errors.New("ipset operation failed")
			var calls []string
			list := func() ([]netlink.IPSetResult, error) {
				if stage == "list" {
					return nil, failure
				}
				sets := []netlink.IPSetResult{{SetName: "unrelated"}}
				if stage != "absent" {
					sets = append(sets, netlink.IPSetResult{SetName: ravenSkipNatSet})
				}
				return sets, nil
			}
			op := func(action string) func(string) error {
				return func(name string) error {
					if name != ravenSkipNatSet {
						t.Fatalf("touched foreign set %q", name)
					}
					calls = append(calls, action)
					if action == stage {
						return failure
					}
					return nil
				}
			}
			err := cleanupIPSet(list, op("flush"), op("destroy"))
			wantErr := stage == "list" || stage == "flush" || stage == "destroy"
			if errors.Is(err, failure) != wantErr {
				t.Fatalf("cleanup error = %v", err)
			}
			want := "flush,destroy"
			if stage == "absent" || stage == "list" {
				want = ""
			}
			if strings.Join(calls, ",") != want {
				t.Fatalf("ipset operations = %v", calls)
			}
		})
	}
}

func TestUserspaceControlRejectsOverlappingCallsAndClosing(t *testing.T) {
	release, entered := make(chan struct{}), make(chan struct{})
	c := &userspaceControl{ctx: context.Background(), timeout: time.Second, process: &fakeProcess{}}
	result := make(chan error, 1)
	go func() { result <- c.call(c.ctx, func() error { close(entered); <-release; return nil }) }()
	<-entered
	err := c.call(c.ctx, func() error { t.Error("overlapping operation started"); return nil })
	close(release)
	if first := <-result; first != nil {
		t.Fatal(first)
	}
	if err == nil {
		t.Fatal("accepted overlapping operation")
	}
	c.closing = make(chan struct{})
	if err := c.call(c.ctx, func() error { t.Error("operation started during Close"); return nil }); err == nil {
		t.Fatal("accepted operation during Close")
	}
}
