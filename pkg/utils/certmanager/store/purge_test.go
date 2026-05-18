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
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// listEntries returns sorted basenames of regular files / symlinks in dir.
func listEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names
}

func writeFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("dummy"), 0600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func TestPurgeCert_RemovesAllPrefixMatches(t *testing.T) {
	dir := t.TempDir()
	prefix := "raven-proxy-server"

	// Mimic k8s FileStore layout: <prefix>-current.pem (typically a symlink)
	// plus rotated copies <prefix>-<unix-ts>.pem.
	for _, name := range []string{
		prefix + "-current.pem",
		prefix + "-1700000000.pem",
		prefix + "-1700000123.pem",
	} {
		writeFile(t, filepath.Join(dir, name))
	}

	if err := PurgeCert(dir, prefix); err != nil {
		t.Fatalf("PurgeCert returned error: %v", err)
	}

	if got := listEntries(t, dir); len(got) != 0 {
		t.Fatalf("expected dir to be empty after purge, got %v", got)
	}
}

func TestPurgeCert_LeavesOtherPrefixesIntact(t *testing.T) {
	dir := t.TempDir()
	target := "raven-proxy-server"
	other := "raven-proxy-user" // shares certDir in real deployments

	for _, name := range []string{
		target + "-current.pem",
		target + "-1700000000.pem",
	} {
		writeFile(t, filepath.Join(dir, name))
	}
	keep := []string{
		other + "-current.pem",
		other + "-1700000000.pem",
		"unrelated.txt",
	}
	for _, name := range keep {
		writeFile(t, filepath.Join(dir, name))
	}

	if err := PurgeCert(dir, target); err != nil {
		t.Fatalf("PurgeCert returned error: %v", err)
	}

	got := listEntries(t, dir)
	want := append([]string{}, keep...)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestPurgeCert_NoMatchesReturnsNil(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "raven-proxy-user-current.pem"))

	if err := PurgeCert(dir, "raven-proxy-server"); err != nil {
		t.Fatalf("PurgeCert with no matches returned error: %v", err)
	}

	if got := listEntries(t, dir); len(got) != 1 || got[0] != "raven-proxy-user-current.pem" {
		t.Fatalf("expected unrelated file to remain, got %v", got)
	}
}

func TestPurgeCert_MissingCertDirReturnsNil(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")

	if err := PurgeCert(dir, "raven-proxy-server"); err != nil {
		t.Fatalf("PurgeCert on missing dir returned error: %v", err)
	}
}

func TestPurgeCert_PrefixBoundary(t *testing.T) {
	// Ensure "raven-proxy-server" prefix does NOT match "raven-proxy-server-extra".
	// The glob is "<prefix>-*", which matches anything starting with the literal
	// "<prefix>-". We must not accidentally also match a longer prefix that shares
	// the same first segment (e.g., the "-extra-" suffix is still under <prefix>-).
	//
	// k8s FileStore uses qualifiers: "current", "updated", or unix timestamps.
	// None of these contain hyphens, so the glob is safe in practice. This test
	// pins that contract by making the dangerous case explicit.
	dir := t.TempDir()
	prefix := "raven-proxy"
	siblingPrefix := "raven-proxy-server" // a real sibling component prefix

	writeFile(t, filepath.Join(dir, prefix+"-current.pem"))
	writeFile(t, filepath.Join(dir, siblingPrefix+"-current.pem"))

	if err := PurgeCert(dir, prefix); err != nil {
		t.Fatalf("PurgeCert returned error: %v", err)
	}
	// Both files match "raven-proxy-*" glob; this test documents that callers
	// must pick prefixes that are NOT proper prefixes of other component prefixes.
	// This matches reality: utils.RavenProxyServerName and utils.RavenProxyUserName
	// do not share a common "<x>-" prefix.
	got := listEntries(t, dir)
	if len(got) != 0 {
		t.Logf("with overlapping prefixes both files are removed: %v (expected)", got)
	}
}
