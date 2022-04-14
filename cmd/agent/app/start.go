/*
 * Copyright 2022 The OpenYurt Authors.
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

package app

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/cmd/agent/app/options"
	"github.com/openyurtio/raven/pkg/k8s"
	"github.com/openyurtio/raven/pkg/networkengine"
)

// NewRavenAgentCommand creates a new raven agent command
func NewRavenAgentCommand(stopCh <-chan struct{}) *cobra.Command {
	agentOptions := &options.AgentOptions{}
	cmd := &cobra.Command{
		Short: fmt.Sprintf("Launch %s", "raven-agent"),
		RunE: func(c *cobra.Command, args []string) error {
			if err := agentOptions.Validate(); err != nil {
				return err
			}
			cfg, err := agentOptions.Config()
			if err != nil {
				return err
			}
			if err := Run(cfg.Complete(), stopCh); err != nil {
				return err
			}
			return nil
		},
		Args: cobra.NoArgs,
	}

	agentOptions.AddFlags(cmd.Flags())
	return cmd
}

// Run starts the raven-agent
func Run(cfg *config.CompletedConfig, stopCh <-chan struct{}) error {
	// start the network engine
	engine := networkengine.NewNetworkEngine()
	engine.Start()

	// start network engine controller
	ec, err := k8s.NewEngineController(cfg.NodeName, cfg.RavenClient, engine)
	if err != nil {
		return fmt.Errorf("could not create network engine controller: %s", err)
	}
	ec.Start(stopCh)
	<-stopCh
	return nil
}
