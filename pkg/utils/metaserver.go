/*
Copyright 2023 The OpenYurt Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"context"
	"net/http"

	"k8s.io/klog/v2"

	"github.com/gorilla/mux"
	"github.com/openyurtio/openyurt/pkg/util/profile"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func RunMetaServer(ctx context.Context, addr string) {
	go func(ctx context.Context) {
		klog.Infoln("start handling meta requests(metrics/pprof)", "server endpoint", addr)
		defer klog.Infoln("meta server stopped", "server endpoint", addr)
		muxHandler := mux.NewRouter()
		muxHandler.Handle("/metrics", promhttp.Handler())
		// register handler for pprof
		profile.Install(muxHandler)
		metaServer := &http.Server{
			Addr:           addr,
			Handler:        muxHandler,
			MaxHeaderBytes: 1 << 20,
		}
		go func(ctx context.Context) {
			<-ctx.Done()
			err := metaServer.Shutdown(ctx)
			if err != nil {
				klog.Errorf("failed to shutdown meta server, error %s", err.Error())
			}
		}(ctx)
		err := metaServer.ListenAndServe()
		if err != nil {
			klog.ErrorS(err, "meta server could not listen")
		}
	}(ctx)
}
