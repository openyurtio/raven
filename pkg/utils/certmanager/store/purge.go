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

package store

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PurgeCert removes cert/key files associated with pairNamePrefix in
// certDirectory. The k8s certificate.FileStore writes files of the form
// "<pairNamePrefix>-<qualifier>.pem" (qualifier is "current", "updated",
// or a unix timestamp), so the glob "<pairNamePrefix>-*" covers them.
//
// After purge, the next certificate.Manager loading from this directory
// will see a missing certificate; combined with fileStoreWrapper.Current
// translating any load error into NoCertKeyError, the manager will then
// trigger a fresh CSR using its current GetTemplate.
//
// Returns nil if the directory does not exist or no matching files exist.
func PurgeCert(certDirectory, pairNamePrefix string) error {
	if certDirectory == "" || pairNamePrefix == "" {
		return nil
	}

	pattern := filepath.Join(certDirectory, pairNamePrefix+"-*")
	matches, err := filepath.Glob(pattern)
	if err != nil {
		return fmt.Errorf("glob cert files for %q in %q: %w", pairNamePrefix, certDirectory, err)
	}

	for _, p := range matches {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove %q: %w", p, err)
		}
	}
	return nil
}
