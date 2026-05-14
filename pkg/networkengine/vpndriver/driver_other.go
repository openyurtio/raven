//go:build !linux

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

package vpndriver

import "errors"

// Production raven only runs on linux. This stub keeps the package buildable
// on other platforms so logic-only unit tests in dependent packages (e.g.
// pkg/engine) can run on macOS during development.
func DefaultMTU() (int, error) {
	return 0, errors.New("vpndriver.DefaultMTU: not supported on this platform")
}
