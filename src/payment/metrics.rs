//! Quoting metrics tracking for ant-node.
//!
//! Tracks the single piece of state that influences quote pricing today:
//! the number of records currently stored in the node's close range.
//! See `payment::pricing::calculate_price` for the formula.

use std::sync::atomic::{AtomicUsize, Ordering};

/// Tracker for quoting metrics.
///
/// Holds the `close_records_stored` counter consumed by
/// [`calculate_price`](crate::payment::pricing::calculate_price).
#[derive(Debug)]
pub struct QuotingMetricsTracker {
    close_records_stored: AtomicUsize,
}

impl QuotingMetricsTracker {
    /// Create a new metrics tracker.
    ///
    /// # Arguments
    ///
    /// * `initial_records` - Initial number of records stored
    #[must_use]
    pub fn new(initial_records: usize) -> Self {
        Self {
            close_records_stored: AtomicUsize::new(initial_records),
        }
    }

    /// Record that a record was stored.
    pub fn record_store(&self) {
        self.close_records_stored.fetch_add(1, Ordering::SeqCst);
    }

    /// Overwrite the counter with an authoritative count of held records.
    ///
    /// This is the deletion-aware path and the SINGLE source of truth for the
    /// priced record count: the handler calls it at quote time with the live
    /// live chunk count (`current_chunks()`), so any record removed from
    /// storage — by delete, prune, or otherwise — is reflected on the next
    /// quote with no per-delete bookkeeping to keep in sync. `record_store`
    /// remains only an optimistic between-quote hint; the resync overwrites it.
    pub fn set_records(&self, count: usize) {
        self.close_records_stored.store(count, Ordering::SeqCst);
    }

    /// Get the number of records stored.
    #[must_use]
    pub fn records_stored(&self) -> usize {
        self.close_records_stored.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_tracker() {
        let tracker = QuotingMetricsTracker::new(50);
        assert_eq!(tracker.records_stored(), 50);
    }

    #[test]
    fn test_record_store_increments_counter() {
        let tracker = QuotingMetricsTracker::new(0);
        assert_eq!(tracker.records_stored(), 0);

        tracker.record_store();
        assert_eq!(tracker.records_stored(), 1);

        tracker.record_store();
        tracker.record_store();
        assert_eq!(tracker.records_stored(), 3);
    }

    #[test]
    fn test_set_records_resyncs_to_authoritative_count() {
        let tracker = QuotingMetricsTracker::new(100);
        assert_eq!(tracker.records_stored(), 100);

        // Resync down (e.g. after deletions/pruning the store now holds fewer).
        tracker.set_records(42);
        assert_eq!(tracker.records_stored(), 42);

        // Resync up (e.g. after new stores).
        tracker.set_records(57);
        assert_eq!(tracker.records_stored(), 57);

        // Resync to zero (empty store).
        tracker.set_records(0);
        assert_eq!(tracker.records_stored(), 0);
    }
}
