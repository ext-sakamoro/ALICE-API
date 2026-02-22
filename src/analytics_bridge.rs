//! ALICE-API × ALICE-Analytics Bridge
//!
//! API gateway metrics: unique clients (HLL), request latency (DDSketch),
//! endpoint frequency (CMS), rate-limit anomaly detection (MAD).

use alice_analytics::prelude::*;

/// API gateway metrics collector.
pub struct ApiMetrics {
    /// Unique client estimation (HyperLogLog++).
    pub unique_clients: HyperLogLog,
    /// Request latency quantiles (DDSketch).
    pub latency: DDSketch,
    /// Endpoint frequency (Count-Min Sketch).
    pub endpoint_freq: CountMinSketch,
    /// Anomaly detection on request rate.
    pub anomaly: MadDetector,
    /// Total requests.
    pub total: u64,
    /// Rate-limited requests.
    pub rate_limited: u64,
}

impl ApiMetrics {
    /// Create a new API metrics collector.
    pub fn new() -> Self {
        Self {
            unique_clients: HyperLogLog::new(),
            latency: DDSketch::new(0.01),
            endpoint_freq: CountMinSketch::new(),
            anomaly: MadDetector::new(3.0),
            total: 0,
            rate_limited: 0,
        }
    }

    /// Record a successful API request.
    #[inline(always)]
    pub fn record_request(&mut self, client_hash: u64, endpoint: &[u8], latency_us: f64) {
        self.unique_clients.insert(&client_hash);
        self.latency.insert(latency_us);
        self.endpoint_freq.insert_bytes(endpoint);
        self.anomaly.observe(latency_us);
        self.total += 1;
    }

    /// Record a rate-limited request.
    #[inline(always)]
    pub fn record_rate_limit(&mut self, client_hash: u64) {
        self.unique_clients.insert(&client_hash);
        self.rate_limited += 1;
        self.total += 1;
    }

    /// Estimated unique client count.
    #[inline(always)]
    pub fn unique_client_count(&self) -> f64 {
        self.unique_clients.cardinality()
    }
    /// P99 latency.
    #[inline(always)]
    pub fn p99_latency(&self) -> f64 {
        self.latency.quantile(0.99)
    }
    /// P50 latency.
    #[inline(always)]
    pub fn p50_latency(&self) -> f64 {
        self.latency.quantile(0.50)
    }
    /// Endpoint request frequency.
    #[inline(always)]
    pub fn endpoint_frequency(&self, endpoint: &[u8]) -> u64 {
        self.endpoint_freq.estimate_bytes(endpoint)
    }
    /// Check if a latency value is anomalous.
    #[inline(always)]
    pub fn is_latency_anomaly(&mut self, latency_us: f64) -> bool {
        self.anomaly.is_anomaly(latency_us)
    }
    /// Rate-limit ratio.
    #[inline(always)]
    pub fn rate_limit_ratio(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            // Reciprocal multiply: one division replaced by multiply
            let inv_total = 1.0_f64 / self.total as f64;
            self.rate_limited as f64 * inv_total
        }
    }
}

impl Default for ApiMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_metrics() {
        let mut m = ApiMetrics::new();
        for i in 0..100u64 {
            m.record_request(i % 10, b"/api/users", 50.0 + i as f64);
        }
        m.record_rate_limit(999);

        assert!(m.unique_client_count() > 5.0);
        assert!(m.p50_latency() > 0.0);
        assert_eq!(m.total, 101);
        assert_eq!(m.rate_limited, 1);
        assert!(m.rate_limit_ratio() < 0.02);
    }
}
