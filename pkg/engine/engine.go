package engine

import (
	"context"
	"time"

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

	"github.com/openyurtio/openyurt/pkg/apis/raven/v1beta1"
	"github.com/openyurtio/raven/cmd/agent/app/config"
	"github.com/openyurtio/raven/pkg/utils"
)

type Engine struct {
	nodeName string
	nodeIP   string
	context  context.Context
	manager  manager.Manager
	client   client.Client
	option   StatusOption

	tunnelQueue  workqueue.RateLimitingInterface
	tunnelEngine *TunnelEngine

	proxyQueue  workqueue.RateLimitingInterface
	proxyEngine *ProxyEngine
}

func NewEngine(ctx context.Context, cfg *config.Config) *Engine {
	engine := &Engine{
		nodeName:    cfg.NodeName,
		nodeIP:      cfg.NodeIP,
		manager:     cfg.Manager,
		context:     ctx,
		option:      NewEngineOption(),
		tunnelQueue: workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Tunnel"),
		proxyQueue:  workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "Proxy"),
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
		klog.ErrorS(err, utils.FormatRavenEngine("failed to new raven agent controller with manager"))
	}
	engine.client = engine.manager.GetClient()
	engine.tunnelEngine = newTunnelEngine(cfg, engine.client, engine.option, engine.tunnelQueue)
	engine.proxyEngine = newProxyEngine(engine.context, cfg, engine.client, engine.option, engine.proxyQueue)
	return engine
}

func (e *Engine) Start() {
	defer utilruntime.HandleCrash()
	klog.Info(utils.FormatRavenEngine("engine successfully start"))
	go func() {
		if err := e.manager.Start(e.context); err != nil {
			klog.ErrorS(err, utils.FormatRavenEngine("failed to start engine controller"))
		}
	}()
	go wait.Until(e.tunnelEngine.worker, time.Second, e.context.Done())
	go wait.Until(e.proxyEngine.worker, time.Second, e.context.Done())
	<-e.context.Done()
	e.cleanup()
	klog.Info(utils.FormatRavenEngine("engine successfully stop"))
}

func (e *Engine) cleanup() {
	if e.option.GetTunnelStatus() {
		err := e.tunnelEngine.clearDriver()
		if err != nil {
			klog.Errorf(utils.FormatRavenEngine("failed to cleanup tunnel driver, error %s", err.Error()))
		}
	}
	if e.option.GetProxyStatus() {
		e.proxyEngine.stopServers()
	}
}

func (e *Engine) enqueueTunnel(obj *v1beta1.Gateway) {
	klog.Info(utils.FormatRavenEngine("enqueue gateway %s to tunnel queue", obj.Name))
	e.tunnelQueue.Add(obj)
}

func (e *Engine) enqueueProxy(obj *v1beta1.Gateway) {
	klog.Info(utils.FormatRavenEngine("enqueue gateway %s to proxy queue", obj.Name))
	e.proxyQueue.Add(obj)
}

func (e *Engine) addGateway(evt event.CreateEvent) bool {
	gw, ok := evt.Object.(*v1beta1.Gateway)
	if ok {
		klog.InfoS(utils.FormatRavenEngine("adding gateway %s", gw.GetName()))
		e.enqueueTunnel(gw.DeepCopy())
		e.enqueueProxy(gw.DeepCopy())
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
			klog.InfoS(utils.FormatRavenEngine("updating gateway, %s", newGw.GetName()))
			e.enqueueTunnel(newGw.DeepCopy())
			e.enqueueProxy(newGw.DeepCopy())
		} else {
			klog.InfoS(utils.FormatRavenEngine("skip handle update gateway"), klog.KObj(newGw))
		}
	}
	return update
}

func (e *Engine) deleteGateway(evt event.DeleteEvent) bool {
	gw, ok := evt.Object.(*v1beta1.Gateway)
	if ok {
		klog.InfoS(utils.FormatRavenEngine("deleting gateway, %s", gw.GetName()))
		e.enqueueTunnel(gw.DeepCopy())
		e.enqueueProxy(gw.DeepCopy())
	}
	return ok
}
