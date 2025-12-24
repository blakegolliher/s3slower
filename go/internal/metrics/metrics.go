// Package metrics provides Prometheus metrics collection and export.
package metrics

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds all Prometheus metrics for s3slower.
type Metrics struct {
	RequestsTotal       *prometheus.CounterVec
	RequestErrorsTotal  *prometheus.CounterVec
	RequestDurationMs   *prometheus.HistogramVec
	RequestDurationMin  *prometheus.GaugeVec
	RequestDurationMax  *prometheus.GaugeVec
	RequestBytesTotal   *prometheus.CounterVec
	ResponseBytesTotal  *prometheus.CounterVec
	PartialRequestsTotal *prometheus.CounterVec

	// Internal tracking
	mu             sync.RWMutex
	latencyMinMax  map[string]*latencyStats
}

type latencyStats struct {
	min float64
	max float64
}

// DefaultLabels are the standard labels for all metrics.
var DefaultLabels = []string{"hostname", "comm", "s3_operation", "method", "pid"}

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
		RequestDurationMin: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "s3slower_request_duration_min_ms",
				Help: "Minimum request duration in milliseconds",
			},
			labels,
		),
		RequestDurationMax: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: "s3slower_request_duration_max_ms",
				Help: "Maximum request duration in milliseconds",
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
		PartialRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Name: "s3slower_partial_requests_total",
				Help: "Total number of partial/multipart requests",
			},
			labels,
		),
		latencyMinMax: make(map[string]*latencyStats),
	}

	return m
}

// Register registers all metrics with the given registry.
func (m *Metrics) Register(reg prometheus.Registerer) error {
	collectors := []prometheus.Collector{
		m.RequestsTotal,
		m.RequestErrorsTotal,
		m.RequestDurationMs,
		m.RequestDurationMin,
		m.RequestDurationMax,
		m.RequestBytesTotal,
		m.ResponseBytesTotal,
		m.PartialRequestsTotal,
	}

	for _, c := range collectors {
		if err := reg.Register(c); err != nil {
			return err
		}
	}

	return nil
}

// RecordRequest records a single S3 request.
func (m *Metrics) RecordRequest(labels prometheus.Labels, durationMs float64, reqBytes, respBytes int64, isError, isPartial bool) {
	m.RequestsTotal.With(labels).Inc()
	m.RequestDurationMs.With(labels).Observe(durationMs)
	m.RequestBytesTotal.With(labels).Add(float64(reqBytes))
	m.ResponseBytesTotal.With(labels).Add(float64(respBytes))

	if isError {
		m.RequestErrorsTotal.With(labels).Inc()
	}

	if isPartial {
		m.PartialRequestsTotal.With(labels).Inc()
	}

	// Track min/max
	key := labelsToKey(labels)
	m.mu.Lock()
	defer m.mu.Unlock()

	stats, ok := m.latencyMinMax[key]
	if !ok {
		stats = &latencyStats{min: durationMs, max: durationMs}
		m.latencyMinMax[key] = stats
	} else {
		if durationMs < stats.min {
			stats.min = durationMs
		}
		if durationMs > stats.max {
			stats.max = durationMs
		}
	}

	m.RequestDurationMin.With(labels).Set(stats.min)
	m.RequestDurationMax.With(labels).Set(stats.max)
}

func labelsToKey(labels prometheus.Labels) string {
	// Sort keys for consistent ordering
	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	// Simple bubble sort for small number of keys
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	// Build key string
	key := ""
	for _, k := range keys {
		key += k + "=" + labels[k] + ";"
	}
	return key
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

// SampleBuffer is a thread-safe buffer for metric samples.
type SampleBuffer struct {
	samples []Sample
	maxSize int
	mu      sync.Mutex
}

// Sample represents a single metric sample.
type Sample struct {
	Timestamp   time.Time
	Labels      prometheus.Labels
	DurationMs  float64
	ReqBytes    int64
	RespBytes   int64
	IsError     bool
	IsPartial   bool
}

// NewSampleBuffer creates a new sample buffer.
func NewSampleBuffer(maxSize int) *SampleBuffer {
	return &SampleBuffer{
		samples: make([]Sample, 0, maxSize),
		maxSize: maxSize,
	}
}

// Add adds a sample to the buffer.
func (b *SampleBuffer) Add(s Sample) {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.samples) >= b.maxSize {
		// Remove oldest sample
		b.samples = b.samples[1:]
	}
	b.samples = append(b.samples, s)
}

// Flush returns and clears all samples.
func (b *SampleBuffer) Flush() []Sample {
	b.mu.Lock()
	defer b.mu.Unlock()

	result := make([]Sample, len(b.samples))
	copy(result, b.samples)
	b.samples = b.samples[:0]
	return result
}

// Len returns the number of samples in the buffer.
func (b *SampleBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.samples)
}
