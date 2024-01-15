package engine

import (
	"fmt"
	"strings"

	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/networkengine/routedriver"
	"github.com/openyurtio/raven/pkg/networkengine/vpndriver"
	"github.com/openyurtio/raven/pkg/tunnelengine"
	"github.com/openyurtio/raven/pkg/utils"
)

type TunnelEngine struct {
	nodeName      string
	config        *config.Config
	client        client.Client
	option        *Option
	queue         workqueue.RateLimitingInterface
	routeDriver   routedriver.Driver
	vpnDriver     vpndriver.Driver
	tunnelHandler *tunnelengine.TunnelHandler
}

func newTunnelEngine(cfg *config.Config, client client.Client, opt *Option, queue workqueue.RateLimitingInterface) *TunnelEngine {
	return &TunnelEngine{nodeName: cfg.NodeName, config: cfg, client: client, option: opt, queue: queue}
}

func (t *TunnelEngine) worker() {
	for t.processNextWorkItem() {
	}
}

func (t *TunnelEngine) processNextWorkItem() bool {
	obj, quit := t.queue.Get()
	if quit {
		return false
	}
	gw, ok := obj.(*v1beta1.Gateway)
	if !ok {
		return false
	}
	defer t.queue.Done(gw)
	err := t.handler(gw)
	t.handleEventErr(err, gw)
	return true
}

func (t *TunnelEngine) handler(gw *v1beta1.Gateway) error {
	klog.Info(utils.FormatRavenEngine("update raven l3 tunnel config for gateway %s", gw.GetName()))
	if err := t.checkNatCapability(); err != nil {
		return err
	}

	err := t.initDriver()
	if err != nil {
		klog.Errorf(utils.FormatRavenEngine("failed to init raven l3 tunnel engine"))
	}

	err = t.tunnelHandler.Handler()
	if err != nil {
		return err
	}
	t.option.SetTunnelStatus(enableTunnel(gw))
	return nil
}

func (t *TunnelEngine) initDriver() error {
	var err error
	if t.routeDriver == nil {
		t.routeDriver, err = routedriver.New(t.config.Tunnel.RouteDriver, t.config)
		if err != nil {
			return fmt.Errorf("fail to create route driver: %s, %s", t.config.Tunnel.RouteDriver, err)
		}
		err = t.routeDriver.Init()
		if err != nil {
			return fmt.Errorf("fail to initialize route driver: %s, %s", t.config.Tunnel.RouteDriver, err)
		}
		klog.Info(utils.FormatRavenEngine("route driver %s initialized", t.config.Tunnel.RouteDriver))
	}

	if t.vpnDriver == nil {
		t.vpnDriver, err = vpndriver.New(t.config.Tunnel.VPNDriver, t.config)
		if err != nil {
			return fmt.Errorf("fail to create vpn driver: %s, %s", t.config.Tunnel.VPNDriver, err)
		}
		err = t.vpnDriver.Init()
		if err != nil {
			return fmt.Errorf("fail to initialize vpn driver: %s, %s", t.config.Tunnel.VPNDriver, err)
		}
		klog.Info(utils.FormatRavenEngine("VPN driver %s initialized", t.config.Tunnel.VPNDriver))
	}

	if t.tunnelHandler == nil {
		t.tunnelHandler = tunnelengine.NewTunnelHandler(t.nodeName, t.config.Tunnel.ForwardNodeIP, t.client, t.routeDriver, t.vpnDriver)
	}
	return nil
}

func (t *TunnelEngine) clearDriver() error {
	err := t.routeDriver.Cleanup()
	if err != nil {
		klog.Errorf(utils.FormatRavenEngine("fail to cleanup route driver: %s", err.Error()))
	}
	err = t.vpnDriver.Cleanup()
	if err != nil {
		klog.Errorf(utils.FormatRavenEngine("fail to cleanup vpn driver: %s", err.Error()))
	}
	return nil
}

func (t *TunnelEngine) checkNatCapability() error {
	natType, err := utils.GetNATType()
	if err != nil {
		return err
	}

	if natType == utils.NATSymmetric {
		return nil
	}

	_, err = utils.GetPublicPort()
	if err != nil {
		return err
	}

	return nil
}

func (t *TunnelEngine) handleEventErr(err error, event interface{}) {
	if err == nil {
		t.queue.Forget(event)
		return
	}
	if t.queue.NumRequeues(event) < utils.MaxRetries {
		klog.Info(utils.FormatRavenEngine("error syncing event %v: %v", event, err))
		t.queue.AddRateLimited(event)
		return
	}
	klog.Info(utils.FormatRavenEngine("dropping event %q out of the queue: %v", event, err))
	t.queue.Forget(event)
}

func enableTunnel(gw *v1beta1.Gateway) (enable bool) {
	enable = false
	for _, aep := range gw.Status.ActiveEndpoints {
		if aep.Type == v1beta1.Tunnel {
			if aep.Config == nil {
				enable = false
				return
			}
			start, ok := aep.Config[utils.RavenEnableTunnel]
			if !ok {
				enable = false
				return
			}
			if strings.ToLower(start) == "true" {
				enable = true
			}
		}
	}
	return
}
