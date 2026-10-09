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
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"
)

// Only the reconciliation worker reads or changes this state. The process
// waiter reports a fault under healthMu and enqueues work; it never recovers.
type userspaceRecovery struct {
	wanted bool
	delay  time.Duration
	next   time.Time
	err    error
}

// SetLifecycle supplies runtime dependencies before any background work starts.
func (w *wireguard) SetLifecycle(ctx context.Context, onChange func()) {
	if ctx == nil {
		ctx = context.Background()
	}
	w.ctx, w.onChange = ctx, onChange
}

func (w *wireguard) processExited(err error) {
	w.healthMu.Lock()
	w.fault = err
	w.ready = false
	w.healthMu.Unlock()
	klog.ErrorS(err, "wireguard-go exited; scheduling L3 recovery")
	if w.onChange != nil && (w.ctx == nil || w.ctx.Err() == nil) {
		w.onChange()
	}
}

// SetNetworkReady is called after both VPN and VXLAN configuration complete.
func (w *wireguard) SetNetworkReady(ready bool) {
	if !w.UsesUserspace() {
		return
	}
	w.healthMu.Lock()
	defer w.healthMu.Unlock()
	if ready && w.configured && w.fault == nil && w.device.process.Running() {
		if !w.ready {
			klog.InfoS("WireGuard local configuration ready", "backend", w.device.selected)
		}
		w.ready = true
		w.recovery.delay, w.recovery.next, w.recovery.err = 0, time.Time{}, nil
	} else {
		w.ready = false
	}
}

// CheckHealth handles exit notifications before topology/NAT discovery, so a
// discovery failure cannot leave routes pointing at a dead userspace device.
func (w *wireguard) CheckHealth() error {
	if !w.UsesUserspace() {
		return nil
	}
	// Finish teardown before discovery or starting a newly desired tunnel.
	// This also retries cleanup after role loss when discovery is unavailable.
	if w.cleanupPending {
		return w.Cleanup()
	}
	w.healthMu.Lock()
	fault := w.fault
	w.healthMu.Unlock()
	if fault != nil {
		return w.failUserspace(fmt.Errorf("recovering after wireguard-go exit: %w", fault))
	}
	return nil
}

// UsesUserspace lets TunnelEngine preserve this instance while its teardown
// is incomplete. It remains true after the child or device has been removed.
func (w *wireguard) UsesUserspace() bool {
	return w.device != nil && w.device.selected == backendUserspace
}

// NextReconcile supplies a queue deadline, not a separate recovery loop.
// Kernel probing/configuration errors remain on Engine's normal event retry.
func (w *wireguard) NextReconcile() time.Duration {
	if w.device == nil || w.device.selected != backendUserspace || (w.ctx != nil && w.ctx.Err() != nil) {
		return 0
	}
	if w.cleanupPending {
		return 5 * time.Second
	}
	if w.recovery.err != nil {
		if delay := time.Until(w.recovery.next); delay > 0 {
			return delay
		}
		// Discovery may fail before Apply is reached. Keep recovery queued
		// without increasing the process-start backoff for a configuration error.
		return time.Second
	}
	if w.recovery.wanted && w.device.process.Running() {
		return 5 * time.Second
	}
	return 0
}

func (w *wireguard) deferUserspaceStart() error {
	if w.device.selected == backendUserspace && w.recovery.err != nil && time.Now().Before(w.recovery.next) {
		return fmt.Errorf("waiting to recover wireguard-go: %w", w.recovery.err)
	}
	return nil
}

func (w *wireguard) recordUserspaceFailure(err error) {
	if w.device == nil || w.device.selected != backendUserspace || (w.ctx != nil && w.ctx.Err() != nil) {
		return
	}
	// Duplicate exit notifications and configuration events cannot shorten
	// the deadline or advance the backoff without another recovery attempt.
	if w.recovery.err == nil || !time.Now().Before(w.recovery.next) {
		if w.recovery.delay == 0 {
			w.recovery.delay = time.Second
		} else {
			w.recovery.delay = min(2*w.recovery.delay, 30*time.Second)
		}
		w.recovery.next = time.Now().Add(w.recovery.delay)
	}
	w.recovery.err = err
}

func (w *wireguard) failUserspace(err error) error {
	w.SetNetworkReady(false)
	// Withdraw only the failed VPN resources. Cleanup/restart is serialized
	// with normal configuration by Engine's worker.
	err = errors.Join(err, w.withdrawDevice())
	w.healthMu.Lock()
	w.fault = nil
	w.healthMu.Unlock()
	w.recordUserspaceFailure(err)
	return err
}

func (w *wireguard) userspaceControlFailed() bool {
	control, ok := w.wgClient.(*userspaceControl)
	if !ok {
		return false
	}
	control.mu.Lock()
	defer control.mu.Unlock()
	return control.failed != nil
}

// Avoid resending unchanged peers: wireguard-go flushes staged packets after
// each UAPI update, which can synchronize competing handshake initiations.
// Undesired peers are removed separately; replacing all peers here would also
// tear down relay sessions whenever edge peers are reconciled.
func (w *wireguard) configureChangedPeers(desired []wgtypes.PeerConfig, current map[string]wgtypes.Peer) error {
	var changed []wgtypes.PeerConfig
	for _, cfg := range desired {
		peer, exists := current[cfg.PublicKey.String()]
		// WireGuard learns endpoints from authenticated traffic, including NAT
		// port mappings. Only resend an unchanged requested endpoint when the
		// peer or its endpoint is missing, even if other peer fields changed.
		if exists && peer.Endpoint != nil && cfg.Endpoint != nil {
			if previous, ok := w.peerEndpoints[cfg.PublicKey]; ok && previous == cfg.Endpoint.String() {
				cfg.Endpoint = nil
			}
		}
		if !exists || !peerConfigMatches(peer, cfg) {
			changed = append(changed, cfg)
		}
	}
	if len(changed) != 0 {
		if err := w.wgClient.ConfigureDevice(DeviceName, wgtypes.Config{Peers: changed}); err != nil {
			return err
		}
	}
	// Do not commit desired endpoints on a rejected update: the next retry
	// must still apply the requested address rather than treating it as learned.
	if w.peerEndpoints == nil {
		w.peerEndpoints = make(map[wgtypes.Key]string)
	}
	for _, cfg := range desired {
		if cfg.Endpoint != nil {
			w.peerEndpoints[cfg.PublicKey] = cfg.Endpoint.String()
		}
	}
	return nil
}

func peerConfigMatches(peer wgtypes.Peer, cfg wgtypes.PeerConfig) bool {
	if cfg.PresharedKey != nil && peer.PresharedKey != *cfg.PresharedKey {
		return false
	}
	if cfg.Endpoint != nil && (peer.Endpoint == nil || peer.Endpoint.String() != cfg.Endpoint.String()) {
		return false
	}
	// UAPI encodes keepalive in whole seconds. Compare at that precision so
	// sub-second values do not trigger another update after reading them back.
	if cfg.PersistentKeepaliveInterval != nil && peer.PersistentKeepaliveInterval/time.Second != *cfg.PersistentKeepaliveInterval/time.Second {
		return false
	}
	if len(peer.AllowedIPs) != len(cfg.AllowedIPs) {
		return false
	}
	allowed := make(map[string]bool, len(peer.AllowedIPs))
	for _, ip := range peer.AllowedIPs {
		allowed[ip.String()] = true
	}
	for _, ip := range cfg.AllowedIPs {
		if !allowed[ip.String()] {
			return false
		}
	}
	return true
}
