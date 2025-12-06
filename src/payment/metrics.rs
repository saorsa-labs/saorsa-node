//! Quoting metrics tracking for saorsa-node.
//!
//! Tracks metrics used for quote generation, including:
//! - `received_payment_count` - number of payments received
//! - Storage capacity and usage
//! - Network liveness information

use ant_evm::QuotingMetrics;
use parking_lot::RwLock;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::Instant;
use tracing::{debug, info, warn};

/// Tracker for quoting metrics.
///
/// Maintains state that influences quote pricing, including payment history,
/// storage capacity, and network information.
#[derive(Debug)]
pub struct QuotingMetricsTracker {
    /// Number of payments received by this node.
    received_payment_count: AtomicUsize,
    /// Maximum records the node can store.
    max_records: usize,
    /// Number of records currently stored.
    close_records_stored: AtomicUsize,
    /// Records stored by type: `Vec<(data_type_index, count)>`.
    records_per_type: RwLock<Vec<(u32, u32)>>,
    /// Node start time for calculating `live_time`.
    start_time: Instant,
    /// Path for persisting metrics (optional).
    persist_path: Option<PathBuf>,
    /// Estimated network size.
    network_size: AtomicU64,
}

impl QuotingMetricsTracker {
    /// Create a new metrics tracker.
    ///
    /// # Arguments
    ///
    /// * `max_records` - Maximum number of records this node can store
    /// * `initial_records` - Initial number of records stored
    #[must_use]
    pub fn new(max_records: usize, initial_records: usize) -> Self {
        Self {
            received_payment_count: AtomicUsize::new(0),
            max_records,
            close_records_stored: AtomicUsize::new(initial_records),
            records_per_type: RwLock::new(Vec::new()),
            start_time: Instant::now(),
            persist_path: None,
            network_size: AtomicU64::new(500), // Conservative default
        }
    }

    /// Create a new metrics tracker with persistence.
    ///
    /// # Arguments
    ///
    /// * `max_records` - Maximum number of records
    /// * `persist_path` - Path to persist metrics to disk
    #[must_use]
    pub fn with_persistence(max_records: usize, persist_path: &std::path::Path) -> Self {
        let mut tracker = Self::new(max_records, 0);
        tracker.persist_path = Some(persist_path.to_path_buf());

        // Try to load existing metrics
        if let Some(loaded) = Self::load_from_disk(persist_path) {
            tracker
                .received_payment_count
                .store(loaded.received_payment_count, Ordering::SeqCst);
            tracker
                .close_records_stored
                .store(loaded.close_records_stored, Ordering::SeqCst);
            *tracker.records_per_type.write() = loaded.records_per_type;
            info!(
                "Loaded persisted metrics: {} payments received",
                loaded.received_payment_count
            );
        }

        tracker
    }

    /// Record a payment received.
    pub fn record_payment(&self) {
        let count = self.received_payment_count.fetch_add(1, Ordering::SeqCst) + 1;
        debug!("Payment received, total count: {}", count);
        self.persist();
    }

    /// Record data stored.
    ///
    /// # Arguments
    ///
    /// * `data_type` - Type index of the data
    pub fn record_store(&self, data_type: u32) {
        self.close_records_stored.fetch_add(1, Ordering::SeqCst);

        // Update per-type counts (scope the write lock)
        {
            let mut records = self.records_per_type.write();
            if let Some(entry) = records.iter_mut().find(|(t, _)| *t == data_type) {
                entry.1 += 1;
            } else {
                records.push((data_type, 1));
            }
        }

        self.persist();
    }

    /// Get the number of payments received.
    #[must_use]
    pub fn payment_count(&self) -> usize {
        self.received_payment_count.load(Ordering::SeqCst)
    }

    /// Get the number of records stored.
    #[must_use]
    pub fn records_stored(&self) -> usize {
        self.close_records_stored.load(Ordering::SeqCst)
    }

    /// Get the node's live time in hours.
    #[must_use]
    pub fn live_time_hours(&self) -> u64 {
        self.start_time.elapsed().as_secs() / 3600
    }

    /// Update the estimated network size.
    pub fn set_network_size(&self, size: u64) {
        self.network_size.store(size, Ordering::SeqCst);
    }

    /// Get quoting metrics for quote generation.
    ///
    /// # Arguments
    ///
    /// * `data_size` - Size of the data being quoted
    /// * `data_type` - Type index of the data
    #[must_use]
    pub fn get_metrics(&self, data_size: usize, data_type: u32) -> QuotingMetrics {
        QuotingMetrics {
            data_type,
            data_size,
            close_records_stored: self.close_records_stored.load(Ordering::SeqCst),
            records_per_type: self.records_per_type.read().clone(),
            max_records: self.max_records,
            received_payment_count: self.received_payment_count.load(Ordering::SeqCst),
            live_time: self.live_time_hours(),
            network_density: None, // TODO: Calculate from DHT
            network_size: Some(self.network_size.load(Ordering::SeqCst)),
        }
    }

    /// Persist metrics to disk.
    fn persist(&self) {
        if let Some(ref path) = self.persist_path {
            let data = PersistedMetrics {
                received_payment_count: self.received_payment_count.load(Ordering::SeqCst),
                close_records_stored: self.close_records_stored.load(Ordering::SeqCst),
                records_per_type: self.records_per_type.read().clone(),
            };

            if let Ok(bytes) = rmp_serde::to_vec(&data) {
                if let Err(e) = std::fs::write(path, bytes) {
                    warn!("Failed to persist metrics: {}", e);
                }
            }
        }
    }

    /// Load metrics from disk.
    fn load_from_disk(path: &std::path::Path) -> Option<PersistedMetrics> {
        let bytes = std::fs::read(path).ok()?;
        rmp_serde::from_slice(&bytes).ok()
    }
}

/// Metrics persisted to disk.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct PersistedMetrics {
    received_payment_count: usize,
    close_records_stored: usize,
    records_per_type: Vec<(u32, u32)>,
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_tracker() {
        let tracker = QuotingMetricsTracker::new(1000, 50);
        assert_eq!(tracker.payment_count(), 0);
        assert_eq!(tracker.records_stored(), 50);
    }

    #[test]
    fn test_record_payment() {
        let tracker = QuotingMetricsTracker::new(1000, 0);
        assert_eq!(tracker.payment_count(), 0);

        tracker.record_payment();
        assert_eq!(tracker.payment_count(), 1);

        tracker.record_payment();
        assert_eq!(tracker.payment_count(), 2);
    }

    #[test]
    fn test_record_store() {
        let tracker = QuotingMetricsTracker::new(1000, 0);
        assert_eq!(tracker.records_stored(), 0);

        tracker.record_store(0); // Chunk type
        assert_eq!(tracker.records_stored(), 1);

        tracker.record_store(0);
        tracker.record_store(1); // Different type
        assert_eq!(tracker.records_stored(), 3);

        let metrics = tracker.get_metrics(1024, 0);
        assert_eq!(metrics.records_per_type.len(), 2);
    }

    #[test]
    fn test_get_metrics() {
        let tracker = QuotingMetricsTracker::new(1000, 100);
        tracker.record_payment();
        tracker.record_payment();

        let metrics = tracker.get_metrics(2048, 0);
        assert_eq!(metrics.data_size, 2048);
        assert_eq!(metrics.data_type, 0);
        assert_eq!(metrics.max_records, 1000);
        assert_eq!(metrics.close_records_stored, 100);
        assert_eq!(metrics.received_payment_count, 2);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("metrics.bin");

        // Create and populate tracker
        {
            let tracker = QuotingMetricsTracker::with_persistence(1000, &path);
            tracker.record_payment();
            tracker.record_payment();
            tracker.record_store(0);
        }

        // Load from disk
        let tracker = QuotingMetricsTracker::with_persistence(1000, &path);
        assert_eq!(tracker.payment_count(), 2);
        assert_eq!(tracker.records_stored(), 1);
    }
}
