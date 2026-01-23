//go:build linux

/*
 * Copyright 2026 The OpenYurt Authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package vxlan

import (
	"fmt"
	"testing"

	"github.com/vishvananda/netlink"
)

func Test_createVxLanLink(t *testing.T) {
	// Save original functions
	originalLinkByName := linkByName
	originalLinkAdd := linkAdd

	originalLinkDel := linkDel

	// Restore original functions after test
	defer func() {
		linkByName = originalLinkByName
		linkAdd = originalLinkAdd
		linkDel = originalLinkDel
	}()

	tests := []struct {
		name              string
		expectedVxLanLink netlink.Link
		mockLinkByName    func(name string) (netlink.Link, error)
		mockLinkAdd       func(link netlink.Link) error
		mockLinkDel       func(link netlink.Link) error
		wantErr           bool
		errMsg            string
		validateResult    func(t *testing.T, result netlink.Link)
	}{
		{
			name: "link does not exist - create new link",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func() func(string) (netlink.Link, error) {
				callCount := 0
				return func(name string) (netlink.Link, error) {
					callCount++
					if callCount == 1 {
						// First call: link not found
						return nil, netlink.LinkNotFoundError{}
					}
					// Second call: return created link
					return &netlink.Vxlan{
						LinkAttrs: netlink.LinkAttrs{
							Name: vxlanLinkName,
							MTU:  1500,
						},
						VxlanId: 200,
						Port:    4472,
					}, nil
				}
			}(),
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: false,
			validateResult: func(t *testing.T, result netlink.Link) {
				if result == nil {
					t.Error("expected non-nil link, got nil")
				}
				if result.Attrs().Name != vxlanLinkName {
					t.Errorf("expected link name %s, got %s", vxlanLinkName, result.Attrs().Name)
				}
			},
		},
		{
			name: "link exists with same config - no change needed",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func() func(string) (netlink.Link, error) {
				callCount := 0
				return func(name string) (netlink.Link, error) {
					callCount++
					if name == vxlanLinkName {
						// Return existing link with same config (first call)
						// or return after LinkAdd (second call)
						return &netlink.Vxlan{
							LinkAttrs: netlink.LinkAttrs{
								Name: vxlanLinkName,
								MTU:  1500,
							},
							VxlanId: 200,
							Port:    4472,
						}, nil
					}
					return nil, netlink.LinkNotFoundError{}
				}
			}(),
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: false,
			validateResult: func(t *testing.T, result netlink.Link) {
				if result == nil {
					t.Error("expected non-nil link, got nil")
				}
			},
		},
		{
			name: "link exists with different config - delete and recreate",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func() func(string) (netlink.Link, error) {
				callCount := 0
				return func(name string) (netlink.Link, error) {
					callCount++
					if callCount == 1 {
						// First call: return existing link with different config
						return &netlink.Vxlan{
							LinkAttrs: netlink.LinkAttrs{
								Name: vxlanLinkName,
								MTU:  1400, // Different MTU
							},
							VxlanId: 200,
							Port:    4472,
						}, nil
					}
					// Second call: return newly created link
					return &netlink.Vxlan{
						LinkAttrs: netlink.LinkAttrs{
							Name: vxlanLinkName,
							MTU:  1500,
						},
						VxlanId: 200,
						Port:    4472,
					}, nil
				}
			}(),
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: false,
			validateResult: func(t *testing.T, result netlink.Link) {
				if result == nil {
					t.Error("expected non-nil link, got nil")
				}
			},
		},
		{
			name: "LinkByName returns non-NotFound error",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func(name string) (netlink.Link, error) {
				return nil, fmt.Errorf("permission denied")
			},
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: true,
			errMsg:  "failed to get link",
		},
		{
			name: "LinkDel fails when deleting old link",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func() func(string) (netlink.Link, error) {
				return func(name string) (netlink.Link, error) {
					if name == vxlanLinkName {
						// Return existing link with different config
						return &netlink.Vxlan{
							LinkAttrs: netlink.LinkAttrs{
								Name: vxlanLinkName,
								MTU:  1400, // Different MTU
							},
							VxlanId: 200,
							Port:    4472,
						}, nil
					}
					return nil, netlink.LinkNotFoundError{}
				}
			}(),
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return fmt.Errorf("cannot delete link")
			},
			wantErr: true,
			errMsg:  "failed to del old vxlan link",
		},
		{
			name: "LinkAdd fails",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func(name string) (netlink.Link, error) {
				return nil, netlink.LinkNotFoundError{}
			},
			mockLinkAdd: func(link netlink.Link) error {
				return fmt.Errorf("device already exists")
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: true,
			errMsg:  "failed to add vxlan link",
		},
		{
			name: "LinkByName fails after LinkAdd",
			expectedVxLanLink: &netlink.Vxlan{
				LinkAttrs: netlink.LinkAttrs{
					Name: vxlanLinkName,
					MTU:  1500,
				},
				VxlanId: 200,
				Port:    4472,
			},
			mockLinkByName: func() func(string) (netlink.Link, error) {
				callCount := 0
				return func(name string) (netlink.Link, error) {
					callCount++
					if callCount == 1 {
						// First call: link not found
						return nil, netlink.LinkNotFoundError{}
					}
					// Second call: return error
					return nil, fmt.Errorf("link not accessible")
				}
			}(),
			mockLinkAdd: func(link netlink.Link) error {
				return nil
			},
			mockLinkDel: func(link netlink.Link) error {
				return nil
			},
			wantErr: true,
			errMsg:  "link not accessible",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set up mocks
			linkByName = tt.mockLinkByName
			linkAdd = tt.mockLinkAdd
			linkDel = tt.mockLinkDel

			// Call the function
			result, err := createVxLanLink(tt.expectedVxLanLink)

			// Verify error
			if (err != nil) != tt.wantErr {
				t.Errorf("createVxLanLink() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil && tt.errMsg != "" {
				if !contains(err.Error(), tt.errMsg) {
					t.Errorf("createVxLanLink() error = %v, want error containing %v", err, tt.errMsg)
				}
			}

			// Validate result if validation function is provided
			if !tt.wantErr && tt.validateResult != nil {
				tt.validateResult(t, result)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
