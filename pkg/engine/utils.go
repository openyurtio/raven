package engine

import (
	"context"
	"sync"

	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/openyurtio/api/raven/v1beta1"
)

type Option struct {
	mu           sync.Mutex
	enableProxy  bool
	enableTunnel bool
}

func NewEngineOption() *Option {
	return &Option{enableTunnel: false, enableProxy: false}
}

func (s *Option) GetProxyStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enableProxy
}

func (s *Option) GetTunnelStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enableTunnel
}

func (s *Option) SetProxyStatus(status bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableProxy = status
}

func (s *Option) SetTunnelStatus(status bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableTunnel = status
}

type proxyOption struct {
	mu           sync.Mutex
	enableClient bool
	enableServer bool
}

func newProxyOption() *proxyOption {
	return &proxyOption{enableClient: false, enableServer: false}
}

func (s *proxyOption) GetClientStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enableClient
}

func (s *proxyOption) GetServerStatus() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enableServer
}

func (s *proxyOption) SetClientStatus(enable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableClient = enable
}

func (s *proxyOption) SetServerStatus(enable bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enableServer = enable
}

type ProxyContext interface {
	ReloadClientContext(ctx context.Context)
	ReloadServerContext(ctx context.Context)
	GetClientContext() context.Context
	GetServerContext() context.Context
	GetClientCancelFunc() context.CancelFunc
	GetServerCancelFunc() context.CancelFunc
}

type proxyContexts struct {
	mu            sync.Mutex
	clientContext context.Context
	serverContext context.Context
	clientCancel  context.CancelFunc
	serverCancel  context.CancelFunc
}

func newProxyContext(ctx context.Context) ProxyContext {
	clientCtx, clientCanc := context.WithCancel(ctx)
	serverCtx, serverCanc := context.WithCancel(ctx)
	return &proxyContexts{clientContext: clientCtx, clientCancel: clientCanc, serverContext: serverCtx, serverCancel: serverCanc}
}

func (r *proxyContexts) ReloadClientContext(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.clientContext, r.clientCancel = context.WithCancel(ctx)
}

func (r *proxyContexts) ReloadServerContext(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.serverContext, r.serverCancel = context.WithCancel(ctx)
}

func (r *proxyContexts) GetClientContext() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientContext
}

func (r *proxyContexts) GetServerContext() context.Context {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.serverContext
}

func (r *proxyContexts) GetClientCancelFunc() context.CancelFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clientCancel
}

func (r *proxyContexts) GetServerCancelFunc() context.CancelFunc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.serverCancel
}

func findCentreGateway(client client.Client) *v1beta1.Gateway {
	var gwList v1beta1.GatewayList
	err := client.List(context.TODO(), &gwList)
	if err != nil {
		return nil
	}
	for _, gw := range gwList.Items {
		if gw.Spec.ExposeType != "" {
			return gw.DeepCopy()
		}
	}
	return nil
}

func getActiveEndpoints(gw *v1beta1.Gateway, aepType string) *v1beta1.Endpoint {
	if gw == nil || gw.Status.ActiveEndpoints == nil {
		return nil
	}
	for _, aep := range gw.Status.ActiveEndpoints {
		if aep.Type == aepType {
			return aep.DeepCopy()
		}
	}
	return nil
}
