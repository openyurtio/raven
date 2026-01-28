package proxyserver

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
	"github.com/openyurtio/raven/pkg/utils"
)

func NewFakeClient(objs ...runtime.Object) client.Client {
	scheme := runtime.NewScheme()
	_ = v1.AddToScheme(scheme)
	_ = v1beta1.AddToScheme(scheme)
	return fake.NewClientBuilder().WithScheme(scheme).WithRuntimeObjects(objs...).Build()
}

var node1 = &v1.Node{
	ObjectMeta: metav1.ObjectMeta{
		Name: "node1",
		Labels: map[string]string{
			raven.LabelCurrentGateway: "gw-fake",
		},
	},
	Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{
			{
				Type:    v1.NodeInternalIP,
				Address: "192.168.1.1",
			},
		},
		DaemonEndpoints: v1.NodeDaemonEndpoints{
			KubeletEndpoint: v1.DaemonEndpoint{
				Port: 10250,
			},
		},
	},
}

var node2 = &v1.Node{
	ObjectMeta: metav1.ObjectMeta{
		Name: "node2",
		Labels: map[string]string{
			raven.LabelCurrentGateway: "gw-fake",
		},
	},
	Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{
			{
				Type:    v1.NodeInternalIP,
				Address: "192.168.1.2",
			},
		},
		DaemonEndpoints: v1.NodeDaemonEndpoints{
			KubeletEndpoint: v1.DaemonEndpoint{
				Port: 10250,
			},
		},
	},
}

var node3 = &v1.Node{
	ObjectMeta: metav1.ObjectMeta{
		Name: "node3",
	},
	Status: v1.NodeStatus{
		Addresses: []v1.NodeAddress{
			{
				Type:    v1.NodeInternalIP,
				Address: "192.168.1.3",
			},
		},
	},
}

var pod1 = &v1.Pod{
	ObjectMeta: metav1.ObjectMeta{
		Name:      "pod1",
		Namespace: "default",
	},
	Spec: v1.PodSpec{
		NodeName: "node1",
	},
}

var gw = &v1beta1.Gateway{
	ObjectMeta: metav1.ObjectMeta{
		Name: "gw-fake",
	},
	Spec: v1beta1.GatewaySpec{
		NodeSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				raven.LabelCurrentGateway: "gw-fake",
			},
		},
		Endpoints: []v1beta1.Endpoint{
			{
				NodeName: "node1",
			},
			{
				NodeName: "node2",
			},
		},
	},
	Status: v1beta1.GatewayStatus{
		Nodes: []v1beta1.NodeInfo{
			{
				NodeName: "node1",
			},
			{
				NodeName: "node2",
			},
		},
		ActiveEndpoints: []*v1beta1.Endpoint{
			{
				NodeName: "node1",
				Type:     v1beta1.Proxy,
			},
			{
				NodeName: "node1",
				Type:     v1beta1.Tunnel,
			},
		},
	},
}

func Test_GetGatewayNodeName(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, node2, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}
	result, err := hm.getGatewayNodeName(node1)
	if err != nil {
		t.Errorf("get gateway node name failed: %v", err)
	}
	if node1.Name != result {
		t.Errorf("get gateway node name failed: %v", err)
	}
}

func Test_GetGatewayNodeName_NoGatewayLabel(t *testing.T) {
	nodeWithoutLabel := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-no-label",
		},
	}
	hm := &headerManger{
		client:      NewFakeClient(nodeWithoutLabel),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}
	result, err := hm.getGatewayNodeName(nodeWithoutLabel)
	if err != nil {
		t.Errorf("get gateway node name failed: %v", err)
	}
	if result != "node-no-label" {
		t.Errorf("expected node name to be 'node-no-label', got %s", result)
	}
}

func Test_GetGatewayNodeName_GatewayNotFound(t *testing.T) {
	nodeWithNonExistentGw := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-nonexistent-gw",
			Labels: map[string]string{
				raven.LabelCurrentGateway: "gw-nonexistent",
			},
		},
	}
	hm := &headerManger{
		client:      NewFakeClient(nodeWithNonExistentGw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}
	result, err := hm.getGatewayNodeName(nodeWithNonExistentGw)
	if err != nil {
		t.Errorf("expected no error when gateway not found, got: %v", err)
	}
	if result != "node-nonexistent-gw" {
		t.Errorf("expected node name to be 'node-nonexistent-gw', got %s", result)
	}
}

func Test_GetGatewayNodeName_NoActiveEndpoints(t *testing.T) {
	gwNoEndpoints := &v1beta1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name: "gw-no-endpoints",
		},
		Status: v1beta1.GatewayStatus{
			ActiveEndpoints: nil,
		},
	}
	nodeWithGw := &v1.Node{
		ObjectMeta: metav1.ObjectMeta{
			Name: "node-with-gw",
			Labels: map[string]string{
				raven.LabelCurrentGateway: "gw-no-endpoints",
			},
		},
	}
	hm := &headerManger{
		client:      NewFakeClient(nodeWithGw, gwNoEndpoints),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}
	_, err := hm.getGatewayNodeName(nodeWithGw)
	if err == nil {
		t.Errorf("expected error when gateway has no active endpoints")
	}
}

func Test_isAPIServerRequest(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "exec request",
			path:     "/exec/default/pod1/container1",
			expected: true,
		},
		{
			name:     "attach request",
			path:     "/attach/default/pod1/container1",
			expected: true,
		},
		{
			name:     "portForward request",
			path:     "/portForward/default/pod1/container1",
			expected: true,
		},
		{
			name:     "containerLogs request",
			path:     "/containerLogs/default/pod1/container1",
			expected: true,
		},
		{
			name:     "normal request with short path",
			path:     "/api/v1",
			expected: false,
		},
		{
			name:     "normal request",
			path:     "/api/v1/nodes",
			expected: false,
		},
		{
			name:     "metrics request",
			path:     "/metrics",
			expected: false,
		},
		{
			name:     "root request",
			path:     "/",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL: &url.URL{Path: tt.path},
			}
			result := isAPIServerRequest(req)
			if result != tt.expected {
				t.Errorf("isAPIServerRequest(%s) = %v, expected %v", tt.path, result, tt.expected)
			}
		})
	}
}

func Test_getNodeIP(t *testing.T) {
	tests := []struct {
		name     string
		node     *v1.Node
		expected string
	}{
		{
			name:     "node with internal IP",
			node:     node1,
			expected: "192.168.1.1",
		},
		{
			name:     "nil node",
			node:     nil,
			expected: "",
		},
		{
			name: "node with no addresses",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-no-addr"},
				Status:     v1.NodeStatus{Addresses: nil},
			},
			expected: "",
		},
		{
			name: "node with only external IP",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-external-only"},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
					},
				},
			},
			expected: "",
		},
		{
			name: "node with multiple addresses",
			node: &v1.Node{
				ObjectMeta: metav1.ObjectMeta{Name: "node-multi-addr"},
				Status: v1.NodeStatus{
					Addresses: []v1.NodeAddress{
						{Type: v1.NodeExternalIP, Address: "1.2.3.4"},
						{Type: v1.NodeInternalIP, Address: "10.0.0.1"},
						{Type: v1.NodeHostName, Address: "node-multi-addr"},
					},
				},
			},
			expected: "10.0.0.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getNodeIP(tt.node)
			if result != tt.expected {
				t.Errorf("getNodeIP() = %v, expected %v", result, tt.expected)
			}
		})
	}
}

func Test_getProxyMode(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, node2, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	tests := []struct {
		name         string
		nodeName     string
		expectedMode string
		expectError  bool
	}{
		{
			name:         "local node",
			nodeName:     "node1",
			expectedMode: utils.RavenProxyServerForwardLocalMode,
			expectError:  false,
		},
		{
			name:         "local node2",
			nodeName:     "node2",
			expectedMode: utils.RavenProxyServerForwardLocalMode,
			expectError:  false,
		},
		{
			name:         "remote node",
			nodeName:     "node-remote",
			expectedMode: utils.RavenProxyServerForwardRemoteMode,
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mode, err := hm.getProxyMode(tt.nodeName)
			if tt.expectError && err == nil {
				t.Errorf("expected error but got none")
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if mode != tt.expectedMode {
				t.Errorf("getProxyMode(%s) = %v, expected %v", tt.nodeName, mode, tt.expectedMode)
			}
		})
	}
}

func Test_getProxyMode_GatewayNotFound(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(),
		gatewayName: "gw-nonexistent",
		isIPv4:      true,
	}
	_, err := hm.getProxyMode("node1")
	if err == nil {
		t.Errorf("expected error when gateway not found")
	}
}

func Test_getNormalRequestDestAddress(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, node2, node3, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	tests := []struct {
		name         string
		host         string
		headers      map[string]string
		query        string
		expectedName string
		expectedIP   string
		expectedPort string
		expectError  bool
	}{
		{
			name:         "normal request with host",
			host:         "node1:10250",
			headers:      map[string]string{},
			expectedName: "node1",
			expectedIP:   "192.168.1.1",
			expectedPort: "10250",
			expectError:  false,
		},
		{
			name: "request with headers",
			host: "node2:10250",
			headers: map[string]string{
				utils.RavenProxyHostHeaderKey: "node2",
				utils.RavenProxyDestHeaderKey: "192.168.1.2:10250",
			},
			expectedName: "node1",
			expectedIP:   "192.168.1.2",
			expectedPort: "10250",
			expectError:  false,
		},
		{
			name:         "request with nodeName query param",
			host:         "node1:10250",
			headers:      map[string]string{},
			query:        "nodeName=node2",
			expectedName: "node1",
			expectedIP:   "192.168.1.2",
			expectedPort: "10250",
			expectError:  false,
		},
		{
			name:         "node not found",
			host:         "node-nonexistent:10250",
			headers:      map[string]string{},
			expectedName: "",
			expectedIP:   "",
			expectedPort: "",
			expectError:  true,
		},
		{
			name:         "invalid host format",
			host:         "invalid-host-no-port",
			headers:      map[string]string{},
			expectedName: "",
			expectedIP:   "",
			expectedPort: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqURL := &url.URL{Path: "/metrics"}
			if tt.query != "" {
				reqURL.RawQuery = tt.query
			}
			req := &http.Request{
				Host:   tt.host,
				URL:    reqURL,
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			name, ip, port, err := hm.getNormalRequestDestAddress(req)
			if tt.expectError {
				if err == nil && (name != "" || ip != "" || port != "") {
					t.Errorf("expected error or empty result")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if ip != tt.expectedIP {
				t.Errorf("expected IP %s, got %s", tt.expectedIP, ip)
			}
			if port != tt.expectedPort {
				t.Errorf("expected port %s, got %s", tt.expectedPort, port)
			}
		})
	}
}

func Test_getNormalRequestDestAddress_IPAddress(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}
	req := &http.Request{
		Host:   "192.168.1.1:10250",
		URL:    &url.URL{Path: "/metrics"},
		Header: make(http.Header),
	}

	name, ip, port, _ := hm.getNormalRequestDestAddress(req)
	if name != "" || ip != "" || port != "" {
		t.Errorf("expected empty result for IP address, got name=%s, ip=%s, port=%s", name, ip, port)
	}
}

func Test_getAPIServerRequestDestAddress(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, node2, pod1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	tests := []struct {
		name         string
		path         string
		headers      map[string]string
		expectedName string
		expectedIP   string
		expectedPort string
		expectError  bool
	}{
		{
			name: "exec request with host header",
			path: "/exec/default/pod1/container1",
			headers: map[string]string{
				utils.RavenProxyHostHeaderKey: "node1",
				utils.RavenProxyDestHeaderKey: "192.168.1.1:10250",
			},
			expectedName: "node1",
			expectedIP:   "192.168.1.1",
			expectedPort: "10250",
			expectError:  false,
		},
		{
			name:         "exec request without host header",
			path:         "/exec/default/pod1/container1",
			headers:      map[string]string{},
			expectedName: "node1",
			expectedIP:   "192.168.1.1",
			expectedPort: "10250",
			expectError:  false,
		},
		{
			name:         "pod not found",
			path:         "/exec/default/pod-nonexistent/container1",
			headers:      map[string]string{},
			expectedName: "",
			expectedIP:   "",
			expectedPort: "",
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				URL:    &url.URL{Path: tt.path},
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}

			name, ip, port, err := hm.getAPIServerRequestDestAddress(req)
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}
			if name != tt.expectedName {
				t.Errorf("expected name %s, got %s", tt.expectedName, name)
			}
			if ip != tt.expectedIP {
				t.Errorf("expected IP %s, got %s", tt.expectedIP, ip)
			}
			if port != tt.expectedPort {
				t.Errorf("expected port %s, got %s", tt.expectedPort, port)
			}
		})
	}
}

func Test_NewHeaderManager(t *testing.T) {
	client := NewFakeClient()
	hm := NewHeaderManager(client, "test-gateway", true)
	if hm == nil {
		t.Errorf("NewHeaderManager returned nil")
	}
}

func Test_Handler_NilRequest(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	handler := hm.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler should not be called for nil request")
	}))

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, nil)
}

func Test_Handler_InvalidHost(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	handler := hm.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler should not be called for invalid host")
	}))

	req := httptest.NewRequest("GET", "http://invalid-host-no-port/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}

func Test_Handler_NormalRequest_Success(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	handlerCalled := false
	handler := hm.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify headers are set correctly
		if r.Header.Get(utils.RavenProxyHostHeaderKey) == "" {
			t.Errorf("expected RavenProxyHostHeaderKey to be set")
		}
		if r.Header.Get(utils.RavenProxyDestHeaderKey) == "" {
			t.Errorf("expected RavenProxyDestHeaderKey to be set")
		}
		if r.Header.Get(utils.RavenProxyServerForwardModeHeaderKey) == "" {
			t.Errorf("expected RavenProxyServerForwardModeHeaderKey to be set")
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "http://node1:10250/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !handlerCalled {
		t.Errorf("expected handler to be called")
	}
}

func Test_Handler_APIServerRequest_Success(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(node1, pod1, gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	handlerCalled := false
	handler := hm.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		// Verify forward mode header
		mode := r.Header.Get(utils.RavenProxyServerForwardModeHeaderKey)
		if mode != utils.RavenProxyServerForwardLocalMode {
			t.Errorf("expected forward mode %s, got %s", utils.RavenProxyServerForwardLocalMode, mode)
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("POST", "http://localhost/exec/default/pod1/container1", nil)
	req.Header.Set(utils.RavenProxyHostHeaderKey, "node1")
	req.Header.Set(utils.RavenProxyDestHeaderKey, "192.168.1.1:10250")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if !handlerCalled {
		t.Errorf("expected handler to be called")
	}
}

func Test_Handler_NodeNotFound(t *testing.T) {
	hm := &headerManger{
		client:      NewFakeClient(gw),
		gatewayName: "gw-fake",
		isIPv4:      true,
	}

	handler := hm.Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("handler should not be called when node not found")
	}))

	req := httptest.NewRequest("GET", "http://node-nonexistent:10250/metrics", nil)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("expected status %d, got %d", http.StatusBadRequest, recorder.Code)
	}
}
