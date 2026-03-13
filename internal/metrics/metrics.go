// Package metrics provides Prometheus metrics collection and export.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for s3slower.
type Metrics struct {
	RequestsTotal      *prometheus.CounterVec
	RequestErrorsTotal *prometheus.CounterVec
	RequestDurationMs  *prometheus.HistogramVec
	RequestBytesTotal  *prometheus.CounterVec
	ResponseBytesTotal *prometheus.CounterVec
}

// DefaultLabels are the standard labels for all metrics.
var DefaultLabels = []string{"hostname", "comm", "s3_operation", "bucket", "endpoint"}

// New creates a new Metrics instance with all counters/gauges/histograms.
func New(extraLabels []string) *Metrics {
	labels := append(DefaultLabels, extraLabels...)

	m := &Metrics{
		RequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_requests_total",
				Help: "Total number of S3 requests",
			},
			labels,
		),
		RequestErrorsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_request_errors_total",
				Help: "Total number of S3 request errors",
			},
			labels,
		),
		RequestDurationMs: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Name:    "s3slower_request_duration_ms",
				Help:    "Request duration in milliseconds",
				Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000},
			},
			labels,
		),
		RequestBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_request_bytes_total",
				Help: "Total request bytes",
			},
			labels,
		),
		ResponseBytesTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_response_bytes_total",
				Help: "Total response bytes",
			},
			labels,
		),
	}

	return m
}

// Register registers all metrics with the given registry.
func (m *Metrics) Register(reg prometheus.Registerer) error {
	collectors := []prometheus.Collector{
		m.RequestsTotal,
		m.RequestErrorsTotal,
		m.RequestDurationMs,
		m.RequestBytesTotal,
		m.ResponseBytesTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return err
		}
	}

	return nil
}

// RecordRequest records a single S3 request.
func (m *Metrics) RecordRequest(labels prometheus.Labels, durationMs float64, reqBytes, respBytes int64, isError bool) {
	m.RequestsTotal.With(labels).Inc()
	m.RequestDurationMs.With(labels).Observe(durationMs)
	m.RequestBytesTotal.With(labels).Add(float64(reqBytes))
	m.ResponseBytesTotal.With(labels).Add(float64(respBytes))

	if isError {
		m.RequestErrorsTotal.With(labels).Inc()
	}
}

// Exporter manages the Prometheus HTTP server.
type Exporter struct {
	metrics  *Metrics
	registry *prometheus.Registry
	server   *http.Server
	addr     string
}

// NewExporter creates a new Prometheus exporter.
func NewExporter(addr string, extraLabels []string) *Exporter {
	reg := prometheus.NewRegistry()
	metrics := New(extraLabels)
	metrics.Register(reg)

	return &Exporter{
		metrics:  metrics,
		registry: reg,
		addr:     addr,
	}
}

// Metrics returns the metrics instance.
func (e *Exporter) Metrics() *Metrics {
	return e.metrics
}

// Start starts the HTTP server.
func (e *Exporter) Start() error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(e.registry, promhttp.HandlerOpts{}))
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	e.server = &http.Server{
		Addr:         e.addr,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	return e.server.ListenAndServe()
}

// Stop stops the HTTP server.
func (e *Exporter) Stop() error {
	if e.server != nil {
		return e.server.Close()
	}
	return nil
}

