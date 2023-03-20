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
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"k8s.io/klog/v2"

	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/cmd/agent/app/options"
	"github.com/openyurtio/raven/pkg/k8s"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
)

// NewRavenAgentCommand creates a new raven agent command
func NewRavenAgentCommand(ctx context.Context) *cobra.Command {
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
			if err := Run(ctx, cfg.Complete()); err != nil {
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
func Run(ctx context.Context, cfg *config.CompletedConfig) error {
	routeDriver, err := routedriver.New(cfg.RouteDriver, cfg.Config)
	if err != nil {
		return fmt.Errorf("fail to create route driver: %s, %s", cfg.RouteDriver, err)
	}
	err = routeDriver.Init()
	if err != nil {
		return fmt.Errorf("fail to initialize route driver: %s, %s", cfg.RouteDriver, err)
	}
	klog.Infof("route driver %s initialized", cfg.RouteDriver)
	vpnDriver, err := vpndriver.New(cfg.VPNDriver, cfg.Config)
	if err != nil {
		return fmt.Errorf("fail to create vpn driver: %s, %s", cfg.VPNDriver, err)
	}
	err = vpnDriver.Init()
	if err != nil {
		return fmt.Errorf("fail to initialize vpn driver: %s, %s", cfg.VPNDriver, err)
	}
	klog.Infof("VPN driver %s initialized", cfg.VPNDriver)
	// start network engine controller
	ec, err := k8s.NewEngineController(cfg.NodeName, cfg.ForwardNodeIP, routeDriver, cfg.Manager, vpnDriver)
	if err != nil {
		return fmt.Errorf("could not create network engine controller: %s", err)
	}
	ec.Start(ctx)
	<-ctx.Done()
	err = routeDriver.Cleanup()
	if err != nil {
		klog.Errorf("route driver fail to cleanup: %s", err)
	}
	err = vpnDriver.Cleanup()
	if err != nil {
		klog.Errorf("vpn driver fail to cleanup: %s", err)
	}
	return nil
}
