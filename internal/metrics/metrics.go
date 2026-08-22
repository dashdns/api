// Package metrics declares the Prometheus surface of policy-controller.
//
// It follows dnsd's convention: collectors are package-level vars registered
// into the default registry from init, and served with promhttp.Handler(). The
// only deliberate difference is the listener -- dnsd owns :9090/metrics on the
// node, so this service defaults to :9091/metrics on its own port.
package metrics

import "github.com/prometheus/client_golang/prometheus"

// Namespace prefixes every collector.
const Namespace = "policy_controller"

var (
	// HTTPRequests counts requests by route pattern, method and status class.
	HTTPRequests = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "http_requests_total",
		Help:      "HTTP requests handled, by route pattern, method and status code",
	}, []string{"route", "method", "code"})

	// HTTPDuration observes handler latency.
	HTTPDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: Namespace,
		Name:      "http_request_duration_seconds",
		Help:      "HTTP handler latency by route pattern and method",
		Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
	}, []string{"route", "method"})

	// PoliciesTotal mirrors dnsd's dnsd_ip_blocklist_rules_count from the
	// control-plane side: how many rules we intend the fleet to enforce.
	PoliciesTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policies_total",
		Help:      "Number of per-IP policies served, by tenant",
	}, []string{"tenant"})

	// PolicyDomainsTotal counts individual (IP, domain) rules.
	PolicyDomainsTotal = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_domains_total",
		Help:      "Number of (client IP, domain) rules served, by tenant",
	}, []string{"tenant"})

	// PolicyRevision exposes the tenant's monotonic policy revision, which is
	// the easiest way to alert on "appliances are serving a stale snapshot".
	PolicyRevision = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "policy_revision",
		Help:      "Current policy revision, by tenant",
	}, []string{"tenant"})

	// PolicyFetches splits appliance polls into full bodies and 304s so the
	// caching win from ETag/Last-Modified is directly observable.
	PolicyFetches = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_fetches_total",
		Help:      "GET /api/policies results, by tenant and outcome (modified|not_modified)",
	}, []string{"tenant", "outcome"})

	// PolicySnapshotBuilds counts full rebuilds of the served payload. A ratio
	// far below PolicyFetches means the snapshot cache is doing its job.
	PolicySnapshotBuilds = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "policy_snapshot_builds_total",
		Help:      "Full rebuilds of the /api/policies payload, by tenant",
	}, []string{"tenant"})

	// AuthFailures counts rejected credentials by plane and reason.
	AuthFailures = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: Namespace,
		Name:      "auth_failures_total",
		Help:      "Rejected credentials, by plane (appliance|admin) and reason",
	}, []string{"plane", "reason"})

	// Appliances gauges registrations by state.
	Appliances = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "appliances_total",
		Help:      "Registered appliances, by tenant and state (active|revoked)",
	}, []string{"tenant", "state"})

	// TenantsTotal gauges the number of tenants.
	TenantsTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "tenants_total",
		Help:      "Number of configured tenants",
	})

	// BuildInfo carries version labels with a constant value of 1.
	BuildInfo = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: Namespace,
		Name:      "build_info",
		Help:      "Build metadata; always 1",
	}, []string{"version", "mode", "db_driver"})
)

func init() {
	prometheus.MustRegister(
		HTTPRequests,
		HTTPDuration,
		PoliciesTotal,
		PolicyDomainsTotal,
		PolicyRevision,
		PolicyFetches,
		PolicySnapshotBuilds,
		AuthFailures,
		Appliances,
		TenantsTotal,
		BuildInfo,
	)
}

// Outcomes for PolicyFetches.
const (
	OutcomeModified    = "modified"
	OutcomeNotModified = "not_modified"
)

// Planes for AuthFailures.
const (
	PlaneAppliance = "appliance"
	PlaneAdmin     = "admin"
)
