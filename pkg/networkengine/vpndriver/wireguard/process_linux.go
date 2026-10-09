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
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"
)

const wireguardBinary = "/usr/local/bin/wireguard-go"
const wireguardSocket = "/var/run/wireguard/" + DeviceName + ".sock"

type managedProcess interface {
	Start() error
	Running() bool
	Stop() error
}

// subprocess only reports exits. Device and network mutations are performed by
// the engine's single reconciliation worker, never by the waiter goroutine.
type subprocess struct {
	mu          sync.Mutex
	cmd         *exec.Cmd
	done        chan struct{}
	stopping    bool
	owned       bool
	newCommand  func() *exec.Cmd
	onExit      func(error)
	stopTimeout time.Duration
	socket      string
}

func newSubprocess(onExit func(error)) *subprocess {
	return &subprocess{
		onExit: onExit, stopTimeout: 5 * time.Second, socket: wireguardSocket,
		newCommand: func() *exec.Cmd {
			cmd := exec.Command(wireguardBinary, "-f", DeviceName)
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGTERM}
			// Never log UAPI requests or enable verbose key/configuration logging.
			cmd.Env = append(os.Environ(), "LOG_LEVEL=error", "WG_PROCESS_FOREGROUND=1")
			cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
			return cmd
		},
	}
}

func (p *subprocess) Start() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil {
		if p.stopping {
			return errors.New("previous wireguard-go process is still stopping")
		}
		select {
		case <-p.done:
			return errors.New("previous wireguard-go process must be reaped before restart")
		default:
			return nil
		}
	}
	// Refuse a live or non-socket occupant; allow only an unreachable stale
	// Raven socket to be reclaimed by wireguard-go itself.
	if info, err := os.Lstat(p.socket); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return fmt.Errorf("UAPI path %s is not a socket", p.socket)
		}
		conn, err := net.DialTimeout("unix", p.socket, time.Second)
		if err == nil {
			_ = conn.Close()
			return fmt.Errorf("UAPI socket %s is already in use", p.socket)
		}
		if !errors.Is(err, syscall.ECONNREFUSED) && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect UAPI socket: %w", err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	cmd := p.newCommand()
	done := make(chan struct{})
	started := make(chan error)
	go func() {
		// Pdeathsig is tied to the creating OS thread on Linux. Keep that
		// thread alive until Wait completes, even if Go retires idle threads.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		err := cmd.Start()
		started <- err
		if err != nil {
			return
		}
		err = cmd.Wait()
		p.mu.Lock()
		expected := p.stopping
		p.mu.Unlock()
		if !expected && p.onExit != nil {
			if err == nil {
				err = errors.New("wireguard-go exited unexpectedly")
			}
			p.onExit(err)
		}
		// Stop waits for the notification as well, preventing stale exit events
		// from being attributed to a replacement process.
		close(done)
	}()
	if err := <-started; err != nil {
		return fmt.Errorf("start wireguard-go (requires TUN and NET_ADMIN): %w", err)
	}
	p.cmd, p.done, p.stopping, p.owned = cmd, done, false, true
	return nil
}

func (p *subprocess) Running() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd == nil || p.stopping {
		return false
	}
	select {
	case <-p.done:
		return false
	default:
		return true
	}
}

func (p *subprocess) Stop() error {
	return p.StopContext(context.Background())
}

func (p *subprocess) StopContext(ctx context.Context) error {
	p.mu.Lock()
	cmd, done := p.cmd, p.done
	p.stopping = true
	p.mu.Unlock()
	if cmd != nil {
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return err
		}
		timer := time.NewTimer(p.stopTimeout)
		select {
		case <-done:
			timer.Stop()
		case <-timer.C:
			if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
				return err
			}
			// A task stuck in uninterruptible kernel I/O may not exit after
			// SIGKILL. Retain ownership and let later cleanup retry reaping;
			// never allow a replacement while that child remains outstanding.
			timer.Reset(p.stopTimeout)
			select {
			case <-done:
				timer.Stop()
			case <-timer.C:
				return errors.New("wireguard-go has not exited after SIGKILL")
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			}
		case <-ctx.Done():
			timer.Stop()
			// Escalate once grace time/the shared budget expires, but retain
			// ownership until Wait and its notification have actually finished.
			err := cmd.Process.Kill()
			if errors.Is(err, os.ErrProcessDone) {
				err = nil
			}
			return errors.Join(ctx.Err(), err)
		}
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cmd = nil
	if p.owned {
		if err := os.Remove(p.socket); err != nil && !os.IsNotExist(err) {
			return err
		}
		p.owned = false
	}
	return nil
}
