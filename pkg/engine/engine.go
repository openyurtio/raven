package engine

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/utils"
)

type Engine struct {
	nodeName   string
	nodeIP     string
	syncRules  bool
	syncPeriod metav1.Duration

	context context.Context
	manager manager.Manager
	client  client.Client
	option  *Option
	queue   workqueue.RateLimitingInterface

	tunnel *TunnelEngine
	proxy  *ProxyEngine
}

func NewEngine(ctx context.Context, cfg *config.Config) (*Engine, error) {
	engine := &Engine{
		nodeName:   cfg.NodeName,
		nodeIP:     cfg.NodeIP,
		syncRules:  cfg.SyncRules,
		syncPeriod: cfg.SyncPeriod,
		manager:    cfg.Manager,
		context:    ctx,
		option:     NewEngineOption(),
		queue:      workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "raven"),
	}
	err := ctrl.NewControllerManagedBy(engine.manager).
		For(&v1beta1.Gateway{}, builder.WithPredicates(predicate.Funcs{
			CreateFunc: engine.addGateway,
			UpdateFunc: engine.updateGateway,
			DeleteFunc: engine.deleteGateway,
		})).
		Complete(reconcile.Func(func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
			return reconcile.Result{}, nil
		}))
	if err != nil {
		klog.Errorf("fail to new controller with manager, error %s", err.Error())
		return engine, err
	}
	engine.client = engine.manager.GetClient()
	engine.tunnel = &TunnelEngine{
		nodeName:      engine.nodeName,
		forwardNodeIP: cfg.Tunnel.ForwardNodeIP,
		natTraversal:  cfg.Tunnel.NATTraversal,
		config:        cfg,
		ravenClient:   engine.client,
	}
	err = engine.tunnel.InitDriver()
	if err != nil {
		klog.Errorf("fail to init tunnel driver, error %s", err.Error())
		return engine, err
	}

	engine.proxy = &ProxyEngine{
		nodeName:    engine.nodeName,
		nodeIP:      engine.nodeIP,
		config:      cfg,
		client:      engine.client,
		option:      engine.option,
		ctx:         engine.context,
		proxyOption: newProxyOption(),
		proxyCtx:    newProxyContext(ctx),
	}
	return engine, nil
}

func (e *Engine) Start() {
	defer utilruntime.HandleCrash()
	go func() {
		if err := e.manager.Start(e.context); err != nil {
			klog.ErrorS(err, "failed to start engine controller")
		}
	}()

	go wait.Until(e.worker, time.Second, e.context.Done())

	if e.syncRules {
		go wait.Until(e.regularSync, e.syncPeriod.Duration, e.context.Done())
	}
}

func (e *Engine) worker() {
	for e.processNextWorkItem() {
	}
}

func (e *Engine) processNextWorkItem() bool {
	obj, quit := e.queue.Get()
	if quit {
		return false
	}
	gw, ok := obj.(*v1beta1.Gateway)
	if !ok {
		return false
	}
	defer e.queue.Done(gw)
	err := e.sync()
	if err != nil {
		e.handleEventErr(err, gw)
	}
	return true
}

func (e *Engine) sync() error {
	e.findLocalGateway()
	err := e.proxy.Handler()
	if err != nil {
		return err
	}
	err = e.tunnel.Handler()
	if err != nil {
		return err
	}
	e.option.SetTunnelStatus(e.tunnel.Status())
	return nil
}

func (e *Engine) regularSync() {
	e.queue.Add(&v1beta1.Gateway{ObjectMeta: metav1.ObjectMeta{Name: "gw-sync"}})
}

func (e *Engine) findLocalGateway() {
	e.tunnel.localGateway = nil
	e.proxy.localGateway = nil
	var gwList v1beta1.GatewayList
	err := e.client.List(context.TODO(), &gwList)
	if err != nil {
		return
	}
	for _, gw := range gwList.Items {
		for _, node := range gw.Status.Nodes {
			if node.NodeName == e.nodeName {
				e.tunnel.localGateway = gw.DeepCopy()
				e.proxy.localGateway = gw.DeepCopy()
				return
			}
		}
	}
}

func (e *Engine) Cleanup() {
	if e.option.GetTunnelStatus() {
		e.tunnel.CleanupDriver()
	}
	if e.option.GetProxyStatus() {
		e.proxy.stop()
	}
}

func (e *Engine) handleEventErr(err error, gw *v1beta1.Gateway) {
	if err == nil {
		e.queue.Forget(gw)
		return
	}

	if e.queue.NumRequeues(gw) < utils.MaxRetries {
		klog.Infof("error syncing event %s: %s", gw.GetName(), err.Error())
		e.queue.AddRateLimited(gw)
		return
	}
	klog.Infof("dropping event %s out of the queue: %s", gw.GetName(), err.Error())
	e.queue.Forget(gw)
}

func (e *Engine) addGateway(evt event.CreateEvent) bool {
	gw, ok := evt.Object.(*v1beta1.Gateway)
	if ok {
		klog.Infof("adding gateway %s", gw.GetName())
		e.queue.Add(gw.DeepCopy())
	}
	return ok
}

func (e *Engine) updateGateway(evt event.UpdateEvent) bool {
	oldGw, ok1 := evt.ObjectOld.(*v1beta1.Gateway)
	newGw, ok2 := evt.ObjectNew.(*v1beta1.Gateway)
	update := false
	if ok1 && ok2 {
		if oldGw.ResourceVersion != newGw.ResourceVersion {
			update = true
			klog.Infof("updating gateway, %s", newGw.GetName())
			e.queue.Add(newGw.DeepCopy())
		}
	}
	return update
}

func (e *Engine) deleteGateway(evt event.DeleteEvent) bool {
	gw, ok := evt.Object.(*v1beta1.Gateway)
	if ok {
		klog.Infof("deleting gateway, %s", gw.GetName())
		e.queue.Add(gw.DeepCopy())
	}
	return ok
}
