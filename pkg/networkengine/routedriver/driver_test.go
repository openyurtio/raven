/*
Copyright 2023 The OpenYurt Authors.

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

package routedriver

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/types"
)

const (
	failed  = "\u2717"
	succeed = "\u2713"
)

type TestRouteDriver struct {
	name string
}

func (d *TestRouteDriver) Init() error {
	return nil
}

func (d *TestRouteDriver) Apply(network *types.Network, vpnDriverMTUFn func() (int, error)) error {
	_, _ = network, vpnDriverMTUFn
	return nil
}

func (d *TestRouteDriver) MTU(network *types.Network) (int, error) {
	_ = network
	return 1500, nil
}

func (d *TestRouteDriver) Cleanup() error {
	return nil
}

func TestRegisterRouteDriver(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory1 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver1"}, nil
	}

	var factory2 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver2"}, nil
	}

	tests := []struct {
		name       string
		driverName string
		factory    Factory
		wantErr    bool
	}{
		{
			name:       "register first driver",
			driverName: "test-driver-1",
			factory:    factory1,
			wantErr:    false,
		},
		{
			name:       "register second driver",
			driverName: "test-driver-2",
			factory:    factory2,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("\tTestCase: %s", tt.name)

			RegisterRouteDriver(tt.driverName, tt.factory)

			// Verify the driver is registered
			driversMutex.Lock()
			registeredFactory, found := drivers[tt.driverName]
			driversMutex.Unlock()

			if !found {
				t.Fatalf("\t%s\texpect driver %s to be registered, but not found", failed, tt.driverName)
			}

			// Verify the factory function works
			driver, err := registeredFactory(&config.Config{})
			if err != nil {
				t.Fatalf("\t%s\texpect no error, but got %v", failed, err)
			}

			if driver == nil {
				t.Fatalf("\t%s\texpect driver to be created, but got nil", failed)
			}

			t.Logf("\t%s\tdriver %s registered successfully", succeed, tt.driverName)
		})
	}
}

func TestRegisterRouteDriver_MultipleDrivers(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory1 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver1"}, nil
	}

	var factory2 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver2"}, nil
	}

	var factory3 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver3"}, nil
	}

	t.Logf("\tTestCase: register multiple drivers")

	RegisterRouteDriver("driver-a", factory1)
	RegisterRouteDriver("driver-b", factory2)
	RegisterRouteDriver("driver-c", factory3)

	driversMutex.Lock()
	driverCount := len(drivers)
	driversMutex.Unlock()

	if driverCount != 3 {
		t.Fatalf("\t%s\texpect 3 drivers registered, but got %d", failed, driverCount)
	}

	// Verify all drivers can be retrieved
	expectedDrivers := []string{"driver-a", "driver-b", "driver-c"}
	for _, name := range expectedDrivers {
		driversMutex.Lock()
		_, found := drivers[name]
		driversMutex.Unlock()

		if !found {
			t.Fatalf("\t%s\texpect driver %s to be registered, but not found", failed, name)
		}
	}

	t.Logf("\t%s\tall 3 drivers registered successfully", succeed)
}

func TestRegisterRouteDriver_VerifyFactoryFunction(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		if cfg == nil {
			return nil, nil
		}
		return &TestRouteDriver{name: "test"}, nil
	}

	t.Logf("\tTestCase: verify factory function")

	RegisterRouteDriver("test-factory", factory)

	// Test that New can use the registered factory
	driver, err := New("test-factory", &config.Config{})
	if err != nil {
		t.Fatalf("\t%s\texpect no error from New, but got %v", failed, err)
	}

	if driver == nil {
		t.Fatalf("\t%s\texpect driver to be created, but got nil", failed)
	}

	// Verify the driver is not nil (already checked above, but keeping for clarity)
	if driver == nil {
		t.Fatalf("\t%s\texpect driver to be non-nil", failed)
	}

	t.Logf("\t%s\tfactory function works correctly", succeed)
}

func TestRegisterRouteDriver_ConcurrentRegistration(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "concurrent"}, nil
	}

	t.Logf("\tTestCase: concurrent registration")

	// Register multiple drivers concurrently
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			RegisterRouteDriver("concurrent-driver-"+strconv.Itoa(idx), factory)
			done <- true
		}(i)
	}

	// Wait for all registrations to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	driversMutex.Lock()
	driverCount := len(drivers)
	driversMutex.Unlock()

	if driverCount != 10 {
		t.Fatalf("\t%s\texpect 10 drivers registered, but got %d", failed, driverCount)
	}

	t.Logf("\t%s\tconcurrent registration works correctly", succeed)
}

func TestRegisterRouteDriver_VerifyDriversMap(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory1 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver1"}, nil
	}

	var factory2 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver2"}, nil
	}

	t.Logf("\tTestCase: verify drivers map content")

	RegisterRouteDriver("verify-driver-1", factory1)
	RegisterRouteDriver("verify-driver-2", factory2)

	driversMutex.Lock()
	registeredFactory1, found1 := drivers["verify-driver-1"]
	registeredFactory2, found2 := drivers["verify-driver-2"]
	driversMutex.Unlock()

	if !found1 || !found2 {
		t.Fatalf("\t%s\texpect both drivers to be registered", failed)
	}

	// Verify factory functions are stored correctly
	driver1, err1 := registeredFactory1(&config.Config{})
	driver2, err2 := registeredFactory2(&config.Config{})

	if err1 != nil || err2 != nil {
		t.Fatalf("\t%s\texpect no errors, but got err1=%v, err2=%v", failed, err1, err2)
	}

	if driver1 == nil || driver2 == nil {
		t.Fatalf("\t%s\texpect both drivers to be created", failed)
	}

	// Verify they are different instances
	if reflect.DeepEqual(driver1, driver2) {
		t.Fatalf("\t%s\texpect different driver instances", failed)
	}

	t.Logf("\t%s\tdrivers map content verified", succeed)
}

func TestNew(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "test-driver"}, nil
	}

	RegisterRouteDriver("test-new-driver", factory)

	tests := []struct {
		name       string
		driverName string
		cfg        *config.Config
		wantErr    bool
		wantNil    bool
	}{
		{
			name:       "create driver with valid name",
			driverName: "test-new-driver",
			cfg:        &config.Config{},
			wantErr:    false,
			wantNil:    false,
		},
		{
			name:       "create driver with nil config",
			driverName: "test-new-driver",
			cfg:        nil,
			wantErr:    false,
			wantNil:    false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("\tTestCase: %s", tt.name)

			driver, err := New(tt.driverName, tt.cfg)

			if tt.wantErr && err == nil {
				t.Fatalf("\t%s\texpect error, but got nil", failed)
			}

			if !tt.wantErr && err != nil {
				t.Fatalf("\t%s\texpect no error, but got %v", failed, err)
			}

			if tt.wantNil && driver != nil {
				t.Fatalf("\t%s\texpect nil driver, but got non-nil", failed)
			}

			if !tt.wantNil && driver == nil {
				t.Fatalf("\t%s\texpect non-nil driver, but got nil", failed)
			}

			if driver != nil {
				// Verify the driver is not nil (already checked above, but keeping for clarity)
				_ = driver
			}

			t.Logf("\t%s\tdriver created successfully", succeed)
		})
	}
}

func TestNew_MultipleInstances(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "multi-instance"}, nil
	}

	RegisterRouteDriver("multi-instance-driver", factory)

	t.Logf("\tTestCase: create multiple instances")

	// Create multiple instances
	driver1, err1 := New("multi-instance-driver", &config.Config{})
	driver2, err2 := New("multi-instance-driver", &config.Config{})
	driver3, err3 := New("multi-instance-driver", &config.Config{})

	if err1 != nil || err2 != nil || err3 != nil {
		t.Fatalf("\t%s\texpect no errors, but got err1=%v, err2=%v, err3=%v", failed, err1, err2, err3)
	}

	if driver1 == nil || driver2 == nil || driver3 == nil {
		t.Fatalf("\t%s\texpect all drivers to be created", failed)
	}

	// Verify they are different instances (factory creates new instance each time)
	if driver1 == driver2 || driver1 == driver3 || driver2 == driver3 {
		t.Fatalf("\t%s\texpect different driver instances", failed)
	}

	t.Logf("\t%s\tmultiple instances created successfully", succeed)
}

func TestNew_DifferentDrivers(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory1 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver-a"}, nil
	}

	var factory2 Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "driver-b"}, nil
	}

	RegisterRouteDriver("driver-a", factory1)
	RegisterRouteDriver("driver-b", factory2)

	t.Logf("\tTestCase: create different drivers")

	driverA, errA := New("driver-a", &config.Config{})
	driverB, errB := New("driver-b", &config.Config{})

	if errA != nil || errB != nil {
		t.Fatalf("\t%s\texpect no errors, but got errA=%v, errB=%v", failed, errA, errB)
	}

	if driverA == nil || driverB == nil {
		t.Fatalf("\t%s\texpect both drivers to be created", failed)
	}

	// Verify they are different instances
	if reflect.DeepEqual(driverA, driverB) {
		t.Fatalf("\t%s\texpect different driver instances", failed)
	}

	t.Logf("\t%s\tdifferent drivers created successfully", succeed)
}

func TestNew_FactoryReturnsError(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	testError := "factory error"
	var factory Factory = func(cfg *config.Config) (Driver, error) {
		return nil, &testFactoryError{msg: testError}
	}

	RegisterRouteDriver("error-driver", factory)

	t.Logf("\tTestCase: factory returns error")

	driver, err := New("error-driver", &config.Config{})

	if err == nil {
		t.Fatalf("\t%s\texpect error from factory, but got nil", failed)
	}

	if driver != nil {
		t.Fatalf("\t%s\texpect nil driver when factory returns error, but got non-nil", failed)
	}

	t.Logf("\t%s\tfactory error handled correctly", succeed)
}

func TestNew_ConcurrentAccess(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		return &TestRouteDriver{name: "concurrent"}, nil
	}

	RegisterRouteDriver("concurrent-driver", factory)

	t.Logf("\tTestCase: concurrent access to New")

	// Create multiple instances concurrently
	done := make(chan bool, 10)
	driverInstances := make([]Driver, 10)
	driverErrors := make([]error, 10)

	for i := 0; i < 10; i++ {
		go func(idx int) {
			driverInstances[idx], driverErrors[idx] = New("concurrent-driver", &config.Config{})
			done <- true
		}(i)
	}

	// Wait for all creations to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Verify all instances were created successfully
	for i := 0; i < 10; i++ {
		if driverErrors[i] != nil {
			t.Fatalf("\t%s\texpect no error for instance %d, but got %v", failed, i, driverErrors[i])
		}

		if driverInstances[i] == nil {
			t.Fatalf("\t%s\texpect non-nil driver for instance %d", failed, i)
		}
	}

	t.Logf("\t%s\tconcurrent access works correctly", succeed)
}

func TestNew_WithConfig(t *testing.T) {
	// Reset drivers map before each test
	driversMutex.Lock()
	drivers = make(map[string]Factory)
	driversMutex.Unlock()

	var factory Factory = func(cfg *config.Config) (Driver, error) {
		if cfg == nil {
			return &TestRouteDriver{name: "nil-config"}, nil
		}
		return &TestRouteDriver{name: "with-config"}, nil
	}

	RegisterRouteDriver("config-driver", factory)

	tests := []struct {
		name string
		cfg  *config.Config
	}{
		{
			name: "with nil config",
			cfg:  nil,
		},
		{
			name: "with empty config",
			cfg:  &config.Config{},
		},
		{
			name: "with config containing node name",
			cfg:  &config.Config{NodeName: "test-node"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("\tTestCase: %s", tt.name)

			driver, err := New("config-driver", tt.cfg)

			if err != nil {
				t.Fatalf("\t%s\texpect no error, but got %v", failed, err)
			}

			if driver == nil {
				t.Fatalf("\t%s\texpect non-nil driver", failed)
			}

			t.Logf("\t%s\tdriver created with config successfully", succeed)
		})
	}
}

// testFactoryError is a simple error type for testing
type testFactoryError struct {
	msg string
}

func (e *testFactoryError) Error() string {
	return e.msg
}
