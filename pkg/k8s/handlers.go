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

package k8s

import (
	"context"

	"github.com/go-logr/logr"
	ravenv1alpha1 "github.com/openyurtio/raven-controller-manager/pkg/ravencontroller/apis/raven/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/event"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/source"
)

type GatewayReconciler struct {
	client.Client
	Log        logr.Logger
	Scheme     *runtime.Scheme
	controller *EngineController
}

func (r *GatewayReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := log.FromContext(ctx)
	log.V(4).Info("started reconciling Gateway", "name", req.Name)
	defer func() {
		log.V(4).Info("finished reconciling Gateway", "name", req.Name)
	}()
	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *GatewayReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).For(&ravenv1alpha1.Gateway{}).
		Watches(
			&source.Kind{Type: &ravenv1alpha1.Gateway{}},
			&handler.EnqueueRequestForObject{},
			builder.WithPredicates(&Predicate{r.controller}),
		).Complete(r)
}

type Predicate struct {
	controller *EngineController
}

func (g Predicate) Create(event event.CreateEvent) bool {
	gw, ok := event.Object.(*ravenv1alpha1.Gateway)
	if ok {
		g.controller.handleCreateGateway(gw)
	}
	return false
}

func (g Predicate) Delete(event event.DeleteEvent) bool {
	gw, ok := event.Object.(*ravenv1alpha1.Gateway)
	if ok {
		g.controller.handleDeleteGateway(gw)
	}
	return false
}

func (g Predicate) Update(event event.UpdateEvent) bool {
	gw, ok := event.ObjectNew.(*ravenv1alpha1.Gateway)
	if ok {
		g.controller.handleUpdateGateway(event.ObjectOld, gw)
	}
	return false
}

func (g Predicate) Generic(event event.GenericEvent) bool {
	return true
}
