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
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/klog/v2"
)

const (
	backendKernel             = "kernel"
	backendUserspace          = "userspace"
	userspaceOperationTimeout = 10 * time.Second
)

type controlClient interface {
	Device(string) (*wgtypes.Device, error)
	ConfigureDevice(string, wgtypes.Config) error
	Close() error
}

func configurationRejected(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

// The pinned wgctrl userspace parser wraps protocol errno values as text in
// os.SyscallError. Preserve that diagnostic while restoring errors.Is support.
func normalizeUserspaceError(err error) error {
	var syscallErr *os.SyscallError
	if !errors.As(err, &syscallErr) || syscallErr.Syscall != "read" {
		return err
	}
	value, ok := strings.CutPrefix(syscallErr.Err.Error(), "wguser: errno=")
	if !ok {
		return err
	}
	code, parseErr := strconv.ParseInt(value, 10, 32)
	if parseErr != nil || code == 0 {
		return err
	}
	// wireguard-go returns negative errno values; other UAPI implementations
	// may use positive values as described by the protocol.
	if code < 0 {
		code = -code
	}
	return fmt.Errorf("%w (%w)", err, syscall.Errno(code))
}

// wgctrl's userspace transport has no I/O deadline. Keep at most one
// outstanding operation and retain a timed-out client until it can be closed.
// A stuck operation must not accumulate goroutines on subsequent retries.
type userspaceControl struct {
	controlClient
	ctx      context.Context // Immutable Agent lifetime context.
	timeout  time.Duration
	process  managedProcess
	mu       sync.Mutex
	pending  chan struct{}
	failed   error
	closing  chan struct{}
	closeErr error
}

func (c *userspaceControl) call(parent context.Context, fn func() error) error {
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	if c.failed != nil {
		err := c.failed
		c.mu.Unlock()
		return err
	}
	if c.closing != nil {
		c.mu.Unlock()
		return errors.New("UAPI client is closing")
	}
	if c.pending != nil {
		select {
		case <-c.pending:
		default:
			c.mu.Unlock()
			return errors.New("UAPI operation is still pending")
		}
	}
	done := make(chan struct{})
	c.pending = done
	c.mu.Unlock()
	var result error
	go func() { result = fn(); close(done) }()
	select {
	case <-done:
		result = normalizeUserspaceError(result)
		// A rejected configuration stays on the normal configuration retry.
		// Transport failures make this userspace control connection unusable.
		if result != nil && !configurationRejected(result) && !errors.Is(result, os.ErrNotExist) {
			c.mu.Lock()
			c.failed = result
			c.mu.Unlock()
		}
		return result
	case <-ctx.Done():
		c.mu.Lock()
		c.failed = ctx.Err()
		c.mu.Unlock()
		return errors.Join(ctx.Err(), c.process.Stop())
	}
}

func (c *userspaceControl) Device(name string) (*wgtypes.Device, error) {
	return c.device(c.ctx, name)
}

func (c *userspaceControl) device(ctx context.Context, name string) (*wgtypes.Device, error) {
	result := make(chan *wgtypes.Device, 1)
	err := c.call(ctx, func() error {
		dev, err := c.controlClient.Device(name)
		result <- dev
		return err
	})
	if err != nil {
		return nil, err
	}
	return <-result, nil
}

func (c *userspaceControl) ConfigureDevice(name string, cfg wgtypes.Config) error {
	return c.configure(c.ctx, name, cfg)
}

func (c *userspaceControl) configure(ctx context.Context, name string, cfg wgtypes.Config) error {
	return c.call(ctx, func() error { return c.controlClient.ConfigureDevice(name, cfg) })
}

func (c *userspaceControl) Close() error {
	return c.closeContext(context.Background())
}

func (c *userspaceControl) closeContext(parent context.Context) error {
	// Cleanup must still work after the Agent context has been cancelled.
	ctx, cancel := context.WithTimeout(parent, c.timeout)
	defer cancel()
	c.mu.Lock()
	c.failed = errors.New("UAPI client is closing")
	pending := c.pending
	c.mu.Unlock()
	if pending != nil {
		select {
		case <-pending:
		case <-ctx.Done():
			return fmt.Errorf("waiting for UAPI operation: %w", ctx.Err())
		}
	}
	c.mu.Lock()
	if c.closing == nil {
		c.closing = make(chan struct{})
		go func() {
			err := c.controlClient.Close()
			c.mu.Lock()
			c.closeErr = err
			close(c.closing)
			c.mu.Unlock()
		}()
	}
	done := c.closing
	c.mu.Unlock()
	select {
	case <-done:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.closeErr
	case <-ctx.Done():
		return fmt.Errorf("closing UAPI client: %w", ctx.Err())
	}
}

type linkOperations struct {
	get    func(string) (netlink.Link, error)
	add    func(netlink.Link) error
	del    func(netlink.Link) error
	setMTU func(netlink.Link, int) error
	setUp  func(netlink.Link) error
}

// selected belongs to this driver instance and survives child-process recovery.
// L3 disable/enable creates a new driver and probes the backend again.
type deviceManager struct {
	selected     string
	owned        bool
	links        linkOperations
	process      managedProcess
	client       controlClient
	newClient    func() (controlClient, error)
	startTimeout time.Duration
}

type deviceError struct {
	stage string
	err   error
}

func (e *deviceError) Error() string { return e.stage + ": " + e.err.Error() }
func (e *deviceError) Unwrap() error { return e.err }

func newDeviceManager(onExit func(error)) *deviceManager {
	return &deviceManager{
		links:        linkOperations{netlink.LinkByName, netlink.LinkAdd, netlink.LinkDel, netlink.LinkSetMTU, netlink.LinkSetUp},
		process:      newSubprocess(onExit),
		newClient:    func() (controlClient, error) { return wgctrl.New() },
		startTimeout: 10 * time.Second,
	}
}

func linkMissing(err error) bool {
	var missing netlink.LinkNotFoundError
	return errors.As(err, &missing)
}

func (d *deviceManager) selectBackend(mtu int) error {
	link, err := d.links.get(DeviceName)
	if err == nil {
		if link.Type() != wgLinkType {
			return fmt.Errorf("device %s already exists with type %s", DeviceName, link.Type())
		}
		// A Raven kernel device left by an earlier agent can be reconciled in place.
		d.owned = true
	} else {
		if !linkMissing(err) {
			return err
		}
		attrs := netlink.NewLinkAttrs()
		attrs.Name, attrs.MTU = DeviceName, mtu
		err = d.links.add(&netlink.GenericLink{LinkAttrs: attrs, LinkType: wgLinkType})
		if err != nil {
			// ENOTSUP is an alias of EOPNOTSUPP on Linux. Other errno values
			// (especially EPERM/EINVAL) must not silently change implementations.
			if !errors.Is(err, syscall.EOPNOTSUPP) {
				return err
			}
			d.selected = backendUserspace
			klog.InfoS("kernel WireGuard is unsupported; using wireguard-go", "reason", err)
		} else {
			d.owned = true
		}
	}
	if d.selected == "" {
		d.selected = backendKernel
	}
	klog.InfoS("selected WireGuard implementation", "backend", d.selected)
	return nil
}

func (d *deviceManager) ensure(ctx context.Context, mtu int, key wgtypes.Key, port int) (netlink.Link, error) {
	if err := ctx.Err(); err != nil {
		return nil, &deviceError{"start", err}
	}
	if d.selected == "" {
		if err := d.selectBackend(mtu); err != nil {
			return nil, &deviceError{"probe", err}
		}
	}
	starting := d.selected == backendUserspace && !d.process.Running()
	if d.selected == backendUserspace {
		if starting {
			if err := d.process.Stop(); err != nil {
				return nil, &deviceError{"cleanup", err}
			}
			if d.client != nil {
				if err := d.client.Close(); err != nil {
					return nil, &deviceError{"cleanup", err}
				}
				d.client = nil
			}
			if link, err := d.links.get(DeviceName); err == nil {
				return nil, &deviceError{"start", fmt.Errorf("device %s already exists with type %s", DeviceName, link.Type())}
			} else if !linkMissing(err) {
				return nil, &deviceError{"start", err}
			}
			if err := d.process.Start(); err != nil {
				return nil, &deviceError{"start", err}
			}
			d.owned = true
		}
	} else {
		if _, err := d.links.get(DeviceName); linkMissing(err) {
			attrs := netlink.NewLinkAttrs()
			attrs.Name, attrs.MTU = DeviceName, mtu
			if err := d.links.add(&netlink.GenericLink{LinkAttrs: attrs, LinkType: wgLinkType}); err != nil {
				return nil, &deviceError{"configure", err}
			}
			d.owned = true
			if d.client != nil {
				if err := d.client.Close(); err != nil {
					return nil, &deviceError{"cleanup", err}
				}
				d.client = nil
			}
		} else if err != nil {
			return nil, &deviceError{"configure", err}
		}
	}
	deadline, cancel := context.WithTimeout(ctx, d.startTimeout)
	defer cancel()
	// Construct the client after LinkAdd has had an opportunity to autoload
	// the kernel module. wgctrl also discovers userspace UAPI sockets.
	if d.client == nil {
		var err error
		d.client, err = d.newClient()
		if err != nil {
			return nil, &deviceError{"configure", err}
		}
		if d.selected == backendUserspace {
			d.client = &userspaceControl{controlClient: d.client, ctx: ctx, timeout: userspaceOperationTimeout, process: d.process}
		}
	}
	var link netlink.Link
	var dev *wgtypes.Device
	for {
		var err error
		link, err = d.links.get(DeviceName)
		if err == nil {
			if c, ok := d.client.(*userspaceControl); ok {
				dev, err = c.device(deadline, DeviceName)
			} else {
				dev, err = d.client.Device(DeviceName)
			}
			if err == nil {
				if (d.selected == backendKernel && (link.Type() != wgLinkType || dev.Type != wgtypes.LinuxKernel)) ||
					(d.selected == backendUserspace && (link.Type() != "tuntap" || dev.Type != wgtypes.Userspace)) {
					return nil, &deviceError{"configure", fmt.Errorf("unexpected device type for %s backend", d.selected)}
				}
				break
			}
		}
		if !starting || configurationRejected(err) {
			return nil, &deviceError{"configure", err}
		}
		if !d.process.Running() {
			return nil, &deviceError{"start", errors.New("wireguard-go exited before UAPI became ready")}
		}
		select {
		case <-deadline.Done():
			return nil, &deviceError{"start", fmt.Errorf("waiting for TUN/UAPI: %w (last error: %v)", deadline.Err(), err)}
		case <-time.After(50 * time.Millisecond):
		}
	}
	// Re-sending ListenPort makes wireguard-go rebind its UDP sockets. Only
	// configure changed parameters so periodic health checks preserve sessions.
	if dev.PrivateKey != key || dev.ListenPort != port {
		cfg := wgtypes.Config{PrivateKey: &key, ListenPort: &port}
		var err error
		if c, ok := d.client.(*userspaceControl); ok {
			err = c.configure(deadline, DeviceName, cfg)
		} else {
			err = d.client.ConfigureDevice(DeviceName, cfg)
		}
		if err != nil {
			return nil, &deviceError{"configure", err}
		}
	}
	if link.Attrs().MTU != mtu {
		if err := d.links.setMTU(link, mtu); err != nil {
			return nil, &deviceError{"configure", err}
		}
		link.Attrs().MTU = mtu
	}
	if err := d.links.setUp(link); err != nil {
		return nil, &deviceError{"configure", err}
	}
	return link, nil
}

func (d *deviceManager) close() error {
	return d.closeContext(context.Background())
}

func (d *deviceManager) closeContext(ctx context.Context) error {
	var errs []error
	// Always stop/wait, even if the TUN device or socket has disappeared.
	var stopErr error
	if p, ok := d.process.(interface{ StopContext(context.Context) error }); ok {
		stopErr = p.StopContext(ctx)
	} else {
		stopErr = d.process.Stop()
	}
	if stopErr != nil {
		errs = append(errs, stopErr)
	}
	if err := ctx.Err(); err != nil {
		return errors.Join(append(errs, err)...)
	}
	if d.client != nil {
		var err error
		if client, ok := d.client.(*userspaceControl); ok {
			err = client.closeContext(ctx)
		} else {
			err = d.client.Close()
		}
		if err != nil {
			errs = append(errs, err)
		} else {
			d.client = nil
		}
	}
	if err := ctx.Err(); err != nil {
		errs = append(errs, err)
		return errors.Join(errs...)
	}
	if d.owned || d.selected == "" {
		link, err := d.links.get(DeviceName)
		// A fresh instance may be asked to clean up before ensure ever runs
		// (for example after losing the gateway role during an Agent restart).
		// Only adopt the reserved-name kernel device; never adopt a foreign TUN.
		if err == nil && !d.owned && link.Type() == wgLinkType {
			d.selected, d.owned = backendKernel, true
		}
		if err == nil && d.owned {
			if (d.selected == backendKernel && link.Type() != wgLinkType) || (d.selected == backendUserspace && link.Type() != "tuntap") {
				err = fmt.Errorf("refusing to delete unexpected device %s (%s)", DeviceName, link.Type())
			} else {
				err = d.links.del(link)
			}
		}
		if err != nil && !linkMissing(err) {
			errs = append(errs, err)
		} else {
			d.owned = false
		}
	}
	return errors.Join(errs...)
}
