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

package iptablesutil

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewChainIfNotExist(t *testing.T) {
	tests := []struct {
		name          string
		table         string
		chain         string
		chainExists   func(table, chain string) (bool, error)
		newChain      func(table, chain string) error
		expectedError bool
		errorMsg      string
	}{
		{
			name:  "chain does not exist, create successfully",
			table: "filter",
			chain: "TEST-CHAIN",
			chainExists: func(table, chain string) (bool, error) {
				return false, nil
			},
			newChain: func(table, chain string) error {
				return nil
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, _ := New()
			err := wrapper.NewChainIfNotExist(tt.table, tt.chain)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestClearAndDeleteChain(t *testing.T) {
	tests := []struct {
		name                string
		table               string
		chain               string
		clearAndDeleteChain func(table, chain string) error
		expectedError       bool
		errorMsg            string
	}{
		{
			name:  "clear and delete chain successfully",
			table: "filter",
			chain: "TEST-CHAIN",
			clearAndDeleteChain: func(table, chain string) error {
				return nil
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, _ := New()
			err := wrapper.ClearAndDeleteChain(tt.table, tt.chain)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
					assert.Contains(t, err.Error(), tt.table)
					assert.Contains(t, err.Error(), tt.chain)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestList(t *testing.T) {
	wrapper, _ := New()
	_, err := wrapper.List("filter", "INPUT")

	assert.NoError(t, err)
}

func TestAppendIfNotExists(t *testing.T) {
	tests := []struct {
		name          string
		table         string
		chain         string
		rulespec      []string
		existsFunc    func(table, chain string, rulespec ...string) (bool, error)
		appendFunc    func(table, chain string, rulespec ...string) error
		expectedError bool
		errorMsg      string
	}{
		{
			name:     "rule does not exist, append successfully",
			table:    "filter",
			chain:    "INPUT",
			rulespec: []string{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
			existsFunc: func(table, chain string, rulespec ...string) (bool, error) {
				return false, nil
			},
			appendFunc: func(table, chain string, rulespec ...string) error {
				return nil
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, _ := New()

			err := wrapper.AppendIfNotExists(tt.table, tt.chain, tt.rulespec...)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
					assert.Contains(t, err.Error(), tt.table)
					assert.Contains(t, err.Error(), tt.chain)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDeleteIfExists(t *testing.T) {
	tests := []struct {
		name           string
		table          string
		chain          string
		rulespec       []string
		deleteIfExists func(table, chain string, rulespec ...string) error
		expectedError  bool
		errorMsg       string
	}{
		{
			name:     "delete rule successfully when rule exists",
			table:    "filter",
			chain:    "INPUT",
			rulespec: []string{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
			deleteIfExists: func(table, chain string, rulespec ...string) error {
				return nil
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, _ := New()

			err := wrapper.DeleteIfExists(tt.table, tt.chain, tt.rulespec...)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
					assert.Contains(t, err.Error(), tt.table)
					assert.Contains(t, err.Error(), tt.chain)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestInsertIfNotExists(t *testing.T) {
	tests := []struct {
		name          string
		table         string
		chain         string
		pos           int
		rulespec      []string
		existsFunc    func(table, chain string, rulespec ...string) (bool, error)
		insertFunc    func(table, chain string, pos int, rulespec ...string) error
		expectedError bool
		errorMsg      string
	}{
		{
			name:     "rule does not exist, insert successfully at position 1",
			table:    "filter",
			chain:    "INPUT",
			pos:      1,
			rulespec: []string{"-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
			existsFunc: func(table, chain string, rulespec ...string) (bool, error) {
				return false, nil
			},
			insertFunc: func(table, chain string, pos int, rulespec ...string) error {
				return nil
			},
			expectedError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wrapper, _ := New()

			err := wrapper.InsertIfNotExists(tt.table, tt.chain, tt.pos, tt.rulespec...)

			if tt.expectedError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
					assert.Contains(t, err.Error(), tt.table)
					assert.Contains(t, err.Error(), tt.chain)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
