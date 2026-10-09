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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestWireGuardProcessHelper(t *testing.T) {
	if os.Getenv("RAVEN_PROCESS_HELPER") != "1" {
		return
	}
	switch os.Getenv("RAVEN_PROCESS_MODE") {
	case "exit":
		os.Exit(7)
	case "clean-exit":
		os.Exit(0)
	case "ignore":
		signal.Ignore(syscall.SIGTERM)
	}
	if path := os.Getenv("RAVEN_PROCESS_READY"); path != "" {
		_ = os.WriteFile(path, []byte("ready"), 0600)
	}
	for {
		time.Sleep(time.Second)
	}
}

func testProcess(t *testing.T, mode string, exited *atomic.Int32) *subprocess {
	t.Helper()
	p := newSubprocess(func(error) { exited.Add(1) })
	p.stopTimeout = 50 * time.Millisecond
	p.socket = filepath.Join(t.TempDir(), "raven-wg0.sock")
	p.newCommand = func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=^TestWireGuardProcessHelper$")
		cmd.Env = append(os.Environ(), "RAVEN_PROCESS_HELPER=1", "RAVEN_PROCESS_MODE="+mode, "RAVEN_PROCESS_READY="+p.socket)
		cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
		return cmd
	}
	t.Cleanup(func() {
		if err := p.Stop(); err != nil {
			t.Error(err)
		}
	})
	return p
}

func waitFor(t *testing.T, pred func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !pred() {
		if time.Now().After(deadline) {
			t.Fatal("condition timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestProcessUnexpectedExitAndRestart(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "exit", &exits)
	for i := 1; i <= 2; i++ {
		if err := p.Start(); err != nil {
			t.Fatal(err)
		}
		waitFor(t, func() bool { return !p.Running() })
		if exits.Load() != int32(i) {
			t.Fatalf("exit notifications=%d", exits.Load())
		}
		if err := p.Stop(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestProcessStopAndForceKill(t *testing.T) {
	for _, mode := range []string{"sleep", "ignore"} {
		t.Run(mode, func(t *testing.T) {
			var exits atomic.Int32
			p := testProcess(t, mode, &exits)
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { _, err := os.Stat(p.socket); return err == nil })
			pid := p.cmd.Process.Pid
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			if p.cmd.Process.Pid != pid {
				t.Fatal("duplicate child")
			}
			if err := p.Stop(); err != nil {
				t.Fatal(err)
			}
			if p.Running() || exits.Load() != 0 {
				t.Fatal("intentional stop reported as failure")
			}
			if _, err := os.Stat(p.socket); !os.IsNotExist(err) {
				t.Fatal("socket not cleaned")
			}
			if err := p.Stop(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProcessStartFailure(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "sleep", &exits)
	p.newCommand = func() *exec.Cmd { return exec.Command(filepath.Join(t.TempDir(), "missing")) }
	if err := p.Start(); err == nil {
		t.Fatal("missing executable accepted")
	}
	if p.Running() || exits.Load() != 0 {
		t.Fatal("failed exec has a running process")
	}
}

func TestProcessRefusesOccupiedSocket(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "sleep", &exits)
	listener, err := net.Listen("unix", p.socket)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := p.Start(); err == nil {
		t.Fatal("occupied UAPI socket accepted")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p.socket); err != nil {
		t.Fatal("foreign socket removed")
	}
}

func TestProcessRefusesRegularUAPIFile(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "sleep", &exits)
	want := []byte("not a socket")
	if err := os.WriteFile(p.socket, want, 0600); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err == nil {
		t.Fatal("regular UAPI file accepted")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(p.socket)
	if err != nil || string(got) != string(want) {
		t.Fatal("foreign file changed or removed")
	}
}

func TestProcessRetainsUnreapedChild(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "sleep", &exits)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { _, err := os.Stat(p.socket); return err == nil })
	// Delay the waiter's completion notification even after the OS child dies.
	// This deterministically models a child that cannot yet be reaped.
	p.mu.Lock()
	actualDone := p.done
	p.done = make(chan struct{})
	p.mu.Unlock()
	if err := p.Stop(); err == nil {
		t.Fatal("unreaped child accepted as stopped")
	}
	if err := p.Start(); err == nil {
		t.Fatal("replacement allowed before reaping")
	}
	p.mu.Lock()
	p.done = actualDone
	p.mu.Unlock()
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
}

func TestStopContextRetainsOwnershipAtDeadline(t *testing.T) {
	for _, phase := range []string{"term", "kill"} {
		t.Run(phase, func(t *testing.T) {
			var exits atomic.Int32
			p := testProcess(t, "ignore", &exits)
			p.stopTimeout = time.Second
			if phase == "kill" {
				p.stopTimeout = 100 * time.Millisecond
			}
			if err := p.Start(); err != nil {
				t.Fatal(err)
			}
			waitFor(t, func() bool { _, err := os.Stat(p.socket); return err == nil })
			p.mu.Lock()
			actualDone := p.done
			p.done = make(chan struct{})
			p.mu.Unlock()
			defer func() { p.mu.Lock(); p.done = actualDone; p.mu.Unlock() }()
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := p.StopContext(ctx); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("expected shared deadline, got %v", err)
			}
			if time.Since(start) > 500*time.Millisecond || p.cmd == nil || !p.owned {
				t.Fatal("deadline ignored or unreaped child ownership lost")
			}
			if err := p.Start(); err == nil {
				t.Fatal("replacement started before old waiter completed")
			}
			select {
			case <-actualDone:
			case <-time.After(time.Second):
				t.Fatal("child was not killed when cleanup budget expired")
			}
		})
	}
}

func TestProcessCleanExitStillRequiresRecoveryAndReaping(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "clean-exit", &exits)
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !p.Running() })
	if exits.Load() != 1 {
		t.Fatal("clean but unexpected exit did not notify recovery")
	}
	if err := p.Start(); err == nil {
		t.Fatal("restarted before reaping")
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if err := p.Start(); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return !p.Running() })
}

func TestProcessSocketCleanupFailureCanBeRetried(t *testing.T) {
	var exits atomic.Int32
	p := testProcess(t, "sleep", &exits)
	p.socket = filepath.Join(t.TempDir(), "occupied")
	if err := os.Mkdir(p.socket, 0700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(p.socket, "child")
	if err := os.WriteFile(child, nil, 0600); err != nil {
		t.Fatal(err)
	}
	p.owned = true
	if err := p.Stop(); err == nil || !p.owned {
		t.Fatal("cleanup failure lost ownership")
	}
	if err := os.Remove(child); err != nil {
		t.Fatal(err)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	if p.owned {
		t.Fatal("successful retry retained ownership")
	}
}
