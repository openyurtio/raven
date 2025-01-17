package proxyserver

import (
	"testing"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/openyurtio/api/raven"
	"github.com/openyurtio/api/raven/v1beta1"
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
}

var node2 = &v1.Node{
	ObjectMeta: metav1.ObjectMeta{
		Name: "node2",
		Labels: map[string]string{
			raven.LabelCurrentGateway: "gw-fake",
		},
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
