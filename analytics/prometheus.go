package analytics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	passedPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "passed_pps",
			Help: "Passed packets per second",
		},
		[]string{"pop", "protocol"},
	)
	passedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "passed_bps",
			Help: "Passed bits per second",
		},
		[]string{"pop", "protocol"},
	)
	droppedPackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dropped_pps",
			Help: "Dropped packets per second",
		},
		[]string{"pop", "protocol"},
	)
	droppedBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dropped_bps",
			Help: "Dropped bits per second",
		},
		[]string{"pop", "protocol"},
	)
	cachePackets = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cache_pps",
			Help: "Dropped packets per second",
		},
		[]string{"pop", "protocol"},
	)
	cacheBits = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "cache_bps",
			Help: "Dropped bits per second",
		},
		[]string{"pop", "protocol"},
	)
	blockedIPs = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blocked_ips_total",
			Help: "Number of source IPs currently in blocklist map",
		},
		[]string{"pop"},
	)
)

func StartPrometheus(bind string) {
	// Register metrics with Prometheus's default registry
	prometheus.MustRegister(passedPackets)
	prometheus.MustRegister(passedBits)
	prometheus.MustRegister(droppedPackets)
	prometheus.MustRegister(droppedBits)
	prometheus.MustRegister(cachePackets)
	prometheus.MustRegister(cacheBits)
	prometheus.MustRegister(blockedIPs)

	//Remove default things
	prometheus.Unregister(prometheus.NewGoCollector())
	prometheus.Unregister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(bind, nil)
}
