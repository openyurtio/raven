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
	"syscall"
	"testing"
	"time"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func recoveryFixture() (*wireguard, *deviceFixture) {
	f := newDeviceFixture()
	w := &wireguard{device: f.d, ctx: context.Background(), privateKey: wgtypes.Key{1}, listenPort: 4500}
	return w, f
}

func ensureRecoveryDevice(w *wireguard) error {
	return w.ensureWgLink(&types.Network{}, func(*types.Network) (int, error) { return 1400, nil })
}

func TestKernelErrorsUseOnlyConfigurationRetry(t *testing.T) {
	for _, errno := range []error{syscall.EPERM, syscall.EACCES, syscall.EINVAL, syscall.EEXIST} {
		t.Run(errno.Error(), func(t *testing.T) {
			w, f := recoveryFixture()
			f.addErr = errno
			for i := 0; i < 3; i++ {
				if err := ensureRecoveryDevice(w); !errors.Is(err, errno) {
					t.Fatalf("error = %v", err)
				}
			}
			if f.adds != 3 || f.process.starts != 0 || w.NextReconcile() != 0 || w.recovery.err != nil {
				t.Fatal("kernel probe error entered userspace recovery")
			}
		})
	}
	w, f := recoveryFixture()
	f.control.err = syscall.EOPNOTSUPP
	if err := ensureRecoveryDevice(w); err == nil {
		t.Fatal("kernel configuration error lost")
	}
	if f.d.selected != backendKernel || f.process.starts != 0 || w.NextReconcile() != 0 {
		t.Fatal("error after kernel creation caused fallback or runtime retry")
	}
}

func TestUserspaceStartBackoffSurvivesConfigurationEvents(t *testing.T) {
	w, f := recoveryFixture()
	f.addErr = syscall.EOPNOTSUPP
	start := f.process.start
	f.process.start = func() error { return errors.New("binary unavailable") }
	if err := ensureRecoveryDevice(w); err == nil {
		t.Fatal("startup failure lost")
	}
	deadline := w.recovery.next
	for i := 0; i < 10; i++ {
		if err := ensureRecoveryDevice(w); err == nil {
			t.Fatal("configuration event bypassed backoff")
		}
	}
	if f.adds != 1 || f.process.starts != 1 || w.recovery.delay != time.Second || !w.recovery.next.Equal(deadline) {
		t.Fatal("reprobed kernel or changed start deadline without an attempt")
	}
	for i := 0; i < 8; i++ {
		w.recovery.next = time.Now().Add(-time.Second)
		if err := ensureRecoveryDevice(w); err == nil {
			t.Fatal("startup failure lost")
		}
	}
	if w.recovery.delay != 30*time.Second || f.adds != 1 {
		t.Fatal("userspace backoff was not bounded or kernel was probed again")
	}
	f.process.start = start
	w.recovery.next = time.Now().Add(-time.Second)
	if err := ensureRecoveryDevice(w); err != nil {
		t.Fatal(err)
	}
	w.configured = true
	w.SetNetworkReady(true)
	if w.recovery.err != nil || w.recovery.delay != 0 || w.NextReconcile() != 5*time.Second {
		t.Fatal("successful configuration did not reset startup backoff")
	}
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestPeerReadErrorsKeepBackendRetryBehavior(t *testing.T) {
	for _, backend := range []string{backendKernel, backendUserspace} {
		t.Run(backend, func(t *testing.T) {
			w := &wireguard{
				device:   &deviceManager{selected: backend},
				wgClient: &fakeControl{err: io.EOF},
			}
			peers, err := w.currentPeers()
			if backend == backendUserspace {
				if !errors.Is(err, io.EOF) {
					t.Fatalf("userspace transport failure was hidden: %v", err)
				}
			} else if err != nil || peers == nil || len(peers) != 0 {
				t.Fatalf("kernel peer-read behavior changed: peers=%v, err=%v", peers, err)
			}
		})
	}
}

func TestUserspaceExitQueuesBeforeWorkerRecovery(t *testing.T) {
	w, f := recoveryFixture()
	f.addErr = syscall.EOPNOTSUPP
	if err := ensureRecoveryDevice(w); err != nil {
		t.Fatal(err)
	}
	requests, withdrawn := 0, 0
	w.onChange = func() { requests++ }
	w.withdrawRoutes = func() error { withdrawn++; return nil }
	stops := f.process.stops
	w.processExited(errors.New("killed"))
	if requests != 1 || withdrawn != 0 || f.process.stops != stops || w.recovery.err != nil {
		t.Fatal("background callback performed recovery outside the worker")
	}
	if err := w.CheckHealth(); err == nil {
		t.Fatal("worker lost exit fault")
	}
	if withdrawn != 1 || f.process.running || w.NextReconcile() <= 0 {
		t.Fatal("worker did not withdraw VPN and schedule recovery")
	}
	starts := f.process.starts
	if err := w.Apply(nil, nil); err != nil {
		t.Fatal(err)
	}
	if w.NextReconcile() != 0 || f.process.starts != starts || w.recovery.err != nil {
		t.Fatal("L3 disable did not bypass backoff and cancel recovery")
	}
}

func TestUserspaceConfigurationErrorDoesNotRestartProcess(t *testing.T) {
	w, f := recoveryFixture()
	f.addErr = syscall.EOPNOTSUPP
	if err := ensureRecoveryDevice(w); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Cleanup(); err != nil {
			t.Error(err)
		}
	})
	f.control.err = syscall.EINVAL
	if err := ensureRecoveryDevice(w); !errors.Is(err, syscall.EINVAL) {
		t.Fatalf("error = %v", err)
	}
	if !f.process.running || f.process.starts != 1 || w.recovery.err != nil {
		t.Fatal("rejected configuration was treated as a process failure")
	}
	f.control.err = io.EOF
	if err := ensureRecoveryDevice(w); !errors.Is(err, io.EOF) {
		t.Fatalf("transport error = %v", err)
	}
	if f.process.running || w.recovery.err == nil {
		t.Fatal("transport failure did not trigger userspace recovery")
	}
}

func TestUserspaceRecoveryStopsOnCancellation(t *testing.T) {
	w, f := recoveryFixture()
	ctx, cancel := context.WithCancel(context.Background())
	w.ctx = ctx
	f.addErr = syscall.EOPNOTSUPP
	f.process.start = func() error { return errors.New("start failed") }
	_ = ensureRecoveryDevice(w)
	if w.NextReconcile() <= 0 {
		t.Fatal("missing userspace retry")
	}
	cancel()
	if w.NextReconcile() != 0 {
		t.Fatal("scheduled retry after cancellation")
	}
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestInitialUserspaceConfigurationRejectionKeepsProcess(t *testing.T) {
	for _, errno := range []error{syscall.EINVAL, syscall.EPERM, syscall.EACCES} {
		t.Run(errno.Error(), func(t *testing.T) {
			w, f := recoveryFixture()
			f.addErr, f.control.err = syscall.EOPNOTSUPP, errno
			if err := ensureRecoveryDevice(w); !errors.Is(err, errno) {
				t.Fatalf("configuration error = %v", err)
			}
			if !f.process.running || w.recovery.err != nil {
				t.Fatal("initial configuration rejection became a process failure")
			}
			f.control.err = nil
			if err := ensureRecoveryDevice(w); err != nil {
				t.Fatal(err)
			}
			if f.process.starts != 1 || f.adds != 1 {
				t.Fatal("configuration retry restarted process or reprobed kernel")
			}
			if err := w.Cleanup(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestUserspaceTeardownErrorDoesNotScheduleProcessRecovery(t *testing.T) {
	w, f := recoveryFixture()
	f.addErr = syscall.EOPNOTSUPP
	if err := ensureRecoveryDevice(w); err != nil {
		t.Fatal(err)
	}
	natErr := errors.New("NAT cleanup failed")
	w.cleanupNAT = func() error { return natErr }
	if err := w.Cleanup(); !errors.Is(err, natErr) {
		t.Fatalf("cleanup error = %v", err)
	}
	if w.NextReconcile() != 0 || w.recovery.err != nil || f.process.running {
		t.Fatal("teardown error entered process restart policy")
	}
	w.cleanupNAT = nil
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestBackendSelectionIsScopedToDriverInstance(t *testing.T) {
	w, f := recoveryFixture()
	f.addErr = syscall.EOPNOTSUPP
	if err := ensureRecoveryDevice(w); err != nil {
		t.Fatal(err)
	}
	if !w.UsesUserspace() {
		t.Fatal("userspace selection not reported")
	}
	if err := w.Cleanup(); err != nil {
		t.Fatal(err)
	}
	if !w.UsesUserspace() {
		t.Fatal("selection was lost before TunnelEngine could finish route cleanup")
	}
	driver, err := New(&config.Config{Manager: integrationManager{}, Tunnel: &config.TunnelConfig{VPNPort: "4500"}})
	if err != nil {
		t.Fatal(err)
	}
	fresh := driver.(*wireguard)
	if fresh.UsesUserspace() || fresh.device.selected != "" || fresh.privateKey != (wgtypes.Key{}) {
		t.Fatal("new driver inherited the previous backend or private key")
	}
}

func TestRecoveryDeadlineRemainsScheduledBeforeApply(t *testing.T) {
	w, f := recoveryFixture()
	f.d.selected = backendUserspace
	w.recordUserspaceFailure(errors.New("start failed"))
	w.recovery.next = time.Now().Add(-time.Second)
	deadline, delay := w.recovery.next, w.recovery.delay
	// Discovery can fail before Apply. Merely asking for the next deadline
	// must keep a retry queued without advancing the startup backoff.
	for i := 0; i < 3; i++ {
		if w.NextReconcile() != time.Second || w.recovery.next != deadline || w.recovery.delay != delay {
			t.Fatal("discovery failure lost retry or changed process-start backoff")
		}
	}
}
