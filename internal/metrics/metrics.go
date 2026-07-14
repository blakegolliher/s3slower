// Package metrics provides Prometheus metrics collection and export.
package metrics

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for s3slower.
type Metrics struct {
	RequestsTotal       *prometheus.CounterVec
	RequestErrorsTotal  *prometheus.CounterVec
	RequestDurationMs   *prometheus.HistogramVec
	RequestBytesTotal   *prometheus.CounterVec
	ResponseBytesTotal  *prometheus.CounterVec
	ResponseStatusTotal *prometheus.CounterVec
	EventsDroppedTotal  *prometheus.CounterVec
}

// DropReason values for the events_dropped_total metric.
const (
	// DropReasonPerfLost — the kernel ring buffer overflowed and lost samples
	// before userspace could drain them.
	DropReasonPerfLost = "perf_lost"
	// DropReasonChannelFull — the userspace pipeline channel was full and the
	// event was discarded rather than block the perf reader.
	DropReasonChannelFull = "channel_full"
)

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
		ResponseStatusTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_response_status_total",
				Help: "Total S3 responses by bucket and HTTP status code",
			},
			[]string{"bucket", "status_code"},
		),
		EventsDroppedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_events_dropped_total",
				Help: "Total events dropped before reaching the exporter, by reason",
			},
			[]string{"reason"},
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
		m.ResponseStatusTotal,
		m.EventsDroppedTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return err
		}
	}

	return nil
}

// RecordDrop increments the events_dropped_total counter for a reason.
// Reasons should come from the DropReason* constants for stability.
func (m *Metrics) RecordDrop(reason string, count uint64) {
	if count == 0 {
		return
	}
	m.EventsDroppedTotal.WithLabelValues(reason).Add(float64(count))
}

// RecordRequest records a single S3 request.
func (m *Metrics) RecordRequest(labels prometheus.Labels, durationMs float64, reqBytes, respBytes int64, isError bool, statusCode int) {
	m.RequestsTotal.With(labels).Inc()
	m.RequestDurationMs.With(labels).Observe(durationMs)
	m.RequestBytesTotal.With(labels).Add(float64(reqBytes))
	m.ResponseBytesTotal.With(labels).Add(float64(respBytes))

	if isError {
		m.RequestErrorsTotal.With(labels).Inc()
	}

	if statusCode > 0 {
		m.ResponseStatusTotal.With(prometheus.Labels{
			"bucket":      labels["bucket"],
			"status_code": strconv.Itoa(statusCode),
		}).Inc()
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
func NewExporter(addr string, extraLabels []string) (*Exporter, error) {
	reg := prometheus.NewRegistry()
	metrics := New(extraLabels)
	if err := metrics.Register(reg); err != nil {
		return nil, fmt.Errorf("register metrics: %w", err)
	}

	return &Exporter{
		metrics:  metrics,
		registry: reg,
		addr:     addr,
	}, nil
}

// Metrics returns the metrics instance.
func (e *Exporter) Metrics() *Metrics {
	return e.metrics
}

// Addr returns the listen address the exporter is configured with.
func (e *Exporter) Addr() string {
	return e.addr
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

