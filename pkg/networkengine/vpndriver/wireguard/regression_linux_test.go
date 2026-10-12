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
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/types"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestUserspacePeerReconcilePreservesLearnedEndpoint(t *testing.T) {
	for _, relay := range []bool{false, true} {
		t.Run(fmt.Sprintf("relay=%v", relay), func(t *testing.T) {
			control := &fakeControl{}
			w := &wireguard{wgClient: control, device: &deviceManager{selected: backendUserspace},
				listenPort: 4500, keepaliveInterval: 20, psk: wgtypes.Key{2}}
			key := wgtypes.Key{1}
			endpoint := &types.Endpoint{PublicIP: "192.0.2.1", PublicPort: 4500,
				Subnets: []string{"10.1.0.0/16"}, Config: map[string]string{PublicKey: key.String()}}
			desired := map[string]*vpndriver.Connection{key.String(): {RemoteEndpoint: endpoint}}
			apply := func(current map[string]wgtypes.Peer) error {
				if relay {
					return w.ensureRelayPeers(desired, nil, current)
				}
				return w.ensureEdgePeers(desired, current)
			}
			if err := apply(nil); err != nil {
				t.Fatal(err)
			}
			cfg := control.configs[0].Peers[0]
			// UAPI writes and reads whole seconds: edge's existing 20ns
			// configuration reads back as zero; userspace relay uses 6s.
			keepalive := time.Duration(0)
			if relay {
				keepalive = 6 * time.Second
			}
			peer := wgtypes.Peer{PublicKey: key, PresharedKey: w.psk, AllowedIPs: cfg.AllowedIPs,
				PersistentKeepaliveInterval: keepalive,
				Endpoint:                    &net.UDPAddr{IP: net.ParseIP("192.0.2.100"), Port: 62000}}
			current := map[string]wgtypes.Peer{key.String(): peer}
			for i := 0; i < 3; i++ {
				if err := apply(current); err != nil {
					t.Fatal(err)
				}
			}
			if len(control.configs) != 1 {
				t.Fatal("health reconciliation reconfigured an unchanged peer")
			}

			endpoint.Subnets = []string{"10.2.0.0/16"}
			if err := apply(current); err != nil {
				t.Fatal(err)
			}
			update := control.configs[len(control.configs)-1]
			if len(control.configs) != 2 || update.ReplacePeers || update.Peers[0].Endpoint != nil ||
				update.Peers[0].AllowedIPs[0].String() != "10.2.0.0/16" {
				t.Fatal("subnet update lost or overwrote the learned endpoint")
			}
			peer.AllowedIPs = update.Peers[0].AllowedIPs
			current[key.String()] = peer

			endpoint.PublicIP = "192.0.2.2"
			control.err = syscall.EINVAL
			if err := apply(current); err == nil {
				t.Fatal("configuration rejection was hidden")
			}
			control.err = nil
			if err := apply(current); err != nil {
				t.Fatal(err)
			}
			update = control.configs[len(control.configs)-1]
			if len(control.configs) != 3 || update.Peers[0].Endpoint == nil ||
				update.Peers[0].Endpoint.String() != "192.0.2.2:4500" {
				t.Fatal("retry lost the explicitly changed endpoint")
			}

			// Restore a lost endpoint or a removed peer even with unchanged intent.
			peer.Endpoint = nil
			current[key.String()] = peer
			for _, peers := range []map[string]wgtypes.Peer{current, nil} {
				before := len(control.configs)
				if err := apply(peers); err != nil {
					t.Fatal(err)
				}
				if len(control.configs) != before+1 || control.configs[before].Peers[0].Endpoint == nil {
					t.Fatal("missing peer endpoint was not restored")
				}
			}
		})
	}
}

func TestUserspaceProtocolErrorsKeepConfigurationRetry(t *testing.T) {
	protocolError := func(response string) error {
		return fmt.Errorf("configuration: %w", os.NewSyscallError("read", errors.New("wguser: "+response)))
	}
	for _, tc := range []struct {
		name     string
		err      error
		errno    syscall.Errno
		rejected bool
	}{
		{"negative invalid", protocolError("errno=-22"), syscall.EINVAL, true},
		{"positive invalid", protocolError("errno=22"), syscall.EINVAL, true},
		{"permission", protocolError("errno=-1"), syscall.EPERM, true},
		{"access", protocolError("errno=-13"), syscall.EACCES, true},
		{"typed", syscall.EINVAL, syscall.EINVAL, true},
		{"I/O failure", protocolError("errno=-5"), syscall.EIO, false},
		{"EOF", io.EOF, 0, false},
		{"malformed", protocolError("errno=-22 trailing"), 0, false},
		{"empty", protocolError("errno="), 0, false},
		{"zero", protocolError("errno=0"), 0, false},
		{"overflow", protocolError("errno=99999999999999999999"), 0, false},
		{"unrelated text", errors.New("wguser: errno=-22"), 0, false},
		{"wrong operation", os.NewSyscallError("write", errors.New("wguser: errno=-22")), 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &fakeProcess{running: true}
			raw := &fakeControl{err: tc.err}
			c := &userspaceControl{controlClient: raw, ctx: context.Background(), timeout: time.Second, process: p}
			err := c.ConfigureDevice(DeviceName, wgtypes.Config{})
			if !errors.Is(err, tc.err) || (tc.errno != 0 && !errors.Is(err, tc.errno)) {
				t.Fatalf("lost original or normalized error: %v", err)
			}
			if configurationRejected(err) != tc.rejected || (c.failed == nil) != tc.rejected {
				t.Fatalf("wrong recovery classification: err=%v failed=%v", err, c.failed)
			}
			raw.err = nil
			retryErr := c.ConfigureDevice(DeviceName, wgtypes.Config{})
			if (retryErr == nil) != tc.rejected {
				t.Fatalf("unexpected configuration retry result: %v", retryErr)
			}
		})
	}
}

func TestFreshDriverCleanupReclaimsOnlyKernelWireGuard(t *testing.T) {
	for _, kind := range []string{"wireguard", "dummy", "tuntap", "absent", "lookup failure", "delete failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newDeviceFixture()
			switch kind {
			case "wireguard", "delete failure":
				f.link = &netlink.GenericLink{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}, LinkType: wgLinkType}
			case "dummy":
				f.link = &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}}
			case "tuntap":
				f.link = &netlink.Tuntap{LinkAttrs: netlink.LinkAttrs{Name: DeviceName}}
			case "lookup failure":
				f.getErr = syscall.EPERM
			}
			del := f.d.links.del
			if kind == "delete failure" {
				f.d.links.del = func(netlink.Link) error { return syscall.EPERM }
			}
			w := &wireguard{device: f.d}
			err := w.Apply(nil, nil)
			if kind == "lookup failure" || kind == "delete failure" {
				if !errors.Is(err, syscall.EPERM) {
					t.Fatalf("cleanup failure hidden: %v", err)
				}
				if kind == "delete failure" && !f.d.owned {
					t.Fatal("failed deletion lost ownership")
				}
				f.getErr, f.d.links.del = nil, del
			} else if err != nil {
				t.Fatal(err)
			}
			if err := w.Apply(nil, nil); err != nil {
				t.Fatal(err)
			}
			wantDeletes := 0
			if kind == "wireguard" || kind == "delete failure" {
				wantDeletes = 1
			}
			if f.deletes != wantDeletes || f.d.owned || f.process.starts != 0 || f.adds != 0 {
				t.Fatalf("cleanup did not preserve ownership boundaries: deletes=%d owned=%v", f.deletes, f.d.owned)
			}
		})
	}
}
