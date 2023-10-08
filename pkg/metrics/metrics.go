/*
Copyright 2020 The OpenYurt Authors.

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

package metrics

import (
	"strings"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/openyurtio/openyurt/pkg/projectinfo"
)

var (
	namespace = strings.ReplaceAll(projectinfo.GetTunnelName(), "-", "_")
	subsystem = "server"
)

var (
	// Metrics provides access to all tunnel server metrics.
	Metrics = newRavenProxyMetrics()
)

type RavenProxyMetrics struct {
	proxyingRequestsCollector *prometheus.GaugeVec
	proxyingRequestsGauge     prometheus.Gauge
	cloudNodeGauge            prometheus.Gauge
}

func newRavenProxyMetrics() *RavenProxyMetrics {
	proxyingRequestsCollector := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "in_proxy_requests",
			Help:      "how many http requests are proxying by raven proxy server",
		},
		[]string{"verb", "path"})
	proxyingRequestsGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "total_in_proxy_requests",
			Help:      "the number of http requests are proxying by raven proxy server",
		})
	cloudNodeGauge := prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "cloud_nodes_counter",
			Help:      "counter of cloud nodes that do not run raven proxy client",
		})

	prometheus.MustRegister(proxyingRequestsCollector)
	prometheus.MustRegister(proxyingRequestsGauge)
	prometheus.MustRegister(cloudNodeGauge)
	return &RavenProxyMetrics{
		proxyingRequestsCollector: proxyingRequestsCollector,
		proxyingRequestsGauge:     proxyingRequestsGauge,
		cloudNodeGauge:            cloudNodeGauge,
	}
}

func (tsm *RavenProxyMetrics) Reset() {
	tsm.proxyingRequestsCollector.Reset()
	tsm.proxyingRequestsGauge.Set(float64(0))
	tsm.cloudNodeGauge.Set(float64(0))
}

func (tsm *RavenProxyMetrics) IncInFlightRequests(verb, path string) {
	tsm.proxyingRequestsCollector.WithLabelValues(verb, path).Inc()
	tsm.proxyingRequestsGauge.Inc()
}

func (tsm *RavenProxyMetrics) DecInFlightRequests(verb, path string) {
	tsm.proxyingRequestsCollector.WithLabelValues(verb, path).Dec()
	tsm.proxyingRequestsGauge.Dec()
}

func (tsm *RavenProxyMetrics) ObserveCloudNodes(cnt int) {
	tsm.cloudNodeGauge.Set(float64(cnt))
}
