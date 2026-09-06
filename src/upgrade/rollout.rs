//! Staged rollout for network-wide upgrades.
//!
//! This module provides deterministic delay calculation to prevent mass node
//! restarts during upgrades. Each node calculates a unique delay based on its
//! node ID, distributing upgrades evenly across the configured time window.
//!
//! ## Why Staged Rollout?
//!
//! When a new version is released, if all nodes upgrade simultaneously:
//! - Network partitioning may occur
//! - Data availability could be temporarily reduced
//! - The network may become unstable
//!
//! By spreading upgrades over a 24-hour window (default), we ensure:
//! - Continuous network availability
//! - Gradual transition to the new version
//! - Ability to detect issues before all nodes upgrade
//!
//! ## Deterministic Delays
//!
//! The delay is calculated deterministically from the node ID hash, so:
//! - Each node gets a consistent delay (no drift on restarts)
//! - Nodes are evenly distributed across the rollout window
//! - The same node always upgrades at the same point in the window

use crate::logging::debug;
use std::time::Duration;

/// Staged rollout configuration and delay calculation.
#[derive(Debug, Clone)]
pub struct StagedRollout {
    /// Maximum delay in hours (nodes will be distributed from 0 to this value).
    max_delay_hours: u64,
    /// Hash of the node ID for deterministic delay calculation.
    node_id_hash: [u8; 32],
}

impl StagedRollout {
    /// Create a new staged rollout calculator.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node's unique identifier (typically a public key)
    /// * `max_delay_hours` - Maximum rollout window (default: 24 hours)
    #[must_use]
    pub fn new(node_id: &[u8], max_delay_hours: u64) -> Self {
        let node_id_hash = *blake3::hash(node_id).as_bytes();

        Self {
            max_delay_hours,
            node_id_hash,
        }
    }

    /// Calculate the delay before this node should apply an upgrade.
    ///
    /// The delay is deterministically derived from the node ID, ensuring:
    /// - Each node gets a consistent delay on every check
    /// - Nodes are evenly distributed across the rollout window
    /// - The delay is reproducible (same node ID = same delay)
    #[must_use]
    pub fn calculate_delay(&self) -> Duration {
        if self.max_delay_hours == 0 {
            return Duration::ZERO;
        }

        // Use first 8 bytes of hash as a u64 for delay calculation
        let hash_value = u64::from_le_bytes([
            self.node_id_hash[0],
            self.node_id_hash[1],
            self.node_id_hash[2],
            self.node_id_hash[3],
            self.node_id_hash[4],
            self.node_id_hash[5],
            self.node_id_hash[6],
            self.node_id_hash[7],
        ]);

        // Calculate delay as a fraction of the max window
        // hash_value / u64::MAX gives a value between 0 and 1
        let max_delay_secs = self.max_delay_hours * 3600;

        // Avoid division by zero and calculate proportional delay
        #[allow(clippy::cast_precision_loss)]
        let delay_fraction = (hash_value as f64) / (u64::MAX as f64);

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let delay_secs = (delay_fraction * max_delay_secs as f64) as u64;

        let delay = Duration::from_secs(delay_secs);

        debug!(
            "Calculated staged rollout delay: {}h {}m {}s",
            delay.as_secs() / 3600,
            (delay.as_secs() % 3600) / 60,
            delay.as_secs() % 60
        );

        delay
    }

    /// Get the maximum rollout window in hours.
    #[must_use]
    pub fn max_delay_hours(&self) -> u64 {
        self.max_delay_hours
    }

    /// Check if staged rollout is enabled (`max_delay_hours` > 0).
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.max_delay_hours > 0
    }

    /// Calculate the delay for a specific version upgrade.
    ///
    /// This includes the version in the hash to ensure different versions
    /// get different delays for the same node (useful for critical updates
    /// that should be spread differently).
    #[must_use]
    pub fn calculate_delay_for_version(&self, version: &semver::Version) -> Duration {
        if self.max_delay_hours == 0 {
            return Duration::ZERO;
        }

        // Include version in the hash for version-specific delays
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.node_id_hash);
        hasher.update(version.to_string().as_bytes());
        let hash_result = hasher.finalize();

        let hash_value = u64::from_le_bytes([
            hash_result.as_bytes()[0],
            hash_result.as_bytes()[1],
            hash_result.as_bytes()[2],
            hash_result.as_bytes()[3],
            hash_result.as_bytes()[4],
            hash_result.as_bytes()[5],
            hash_result.as_bytes()[6],
            hash_result.as_bytes()[7],
        ]);

        let max_delay_secs = self.max_delay_hours * 3600;

        #[allow(clippy::cast_precision_loss)]
        let delay_fraction = (hash_value as f64) / (u64::MAX as f64);

        #[allow(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            clippy::cast_precision_loss
        )]
        let delay_secs = (delay_fraction * max_delay_secs as f64) as u64;

        Duration::from_secs(delay_secs)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Test 1: Zero delay when disabled
    #[test]
    fn test_zero_delay_when_disabled() {
        let rollout = StagedRollout::new(b"node-1", 0);
        assert_eq!(rollout.calculate_delay(), Duration::ZERO);
        assert!(!rollout.is_enabled());
    }

    /// Test 2: Delay within expected range
    #[test]
    fn test_delay_within_range() {
        let rollout = StagedRollout::new(b"node-1", 24);
        let delay = rollout.calculate_delay();

        // Should be between 0 and 24 hours
        assert!(delay <= Duration::from_hours(24));
        assert!(rollout.is_enabled());
    }

    /// Test 3: Deterministic delays (same node ID = same delay)
    #[test]
    fn test_deterministic_delay() {
        let rollout1 = StagedRollout::new(b"node-1", 24);
        let rollout2 = StagedRollout::new(b"node-1", 24);

        assert_eq!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    /// Test 4: Different nodes get different delays
    #[test]
    fn test_different_nodes_different_delays() {
        let rollout1 = StagedRollout::new(b"node-1", 24);
        let rollout2 = StagedRollout::new(b"node-2", 24);

        // Different node IDs should (very likely) produce different delays
        // There's a tiny chance they could be equal, but statistically negligible
        assert_ne!(rollout1.calculate_delay(), rollout2.calculate_delay());
    }

    /// Test 5: Delay scales with max hours
    #[test]
    fn test_delay_scales_with_max_hours() {
        let node_id = b"consistent-node";
        let rollout_12h = StagedRollout::new(node_id, 12);
        let rollout_24h = StagedRollout::new(node_id, 24);

        // The 24h rollout should have roughly double the delay of 12h
        // (within some tolerance since we're dealing with fractions)
        let delay_12h = rollout_12h.calculate_delay().as_secs();
        let delay_24h = rollout_24h.calculate_delay().as_secs();

        // Check ratio is approximately 2:1 (with 10% tolerance)
        if delay_12h > 0 {
            #[allow(clippy::cast_precision_loss)]
            let ratio = delay_24h as f64 / delay_12h as f64;
            assert!(
                (ratio - 2.0).abs() < 0.1,
                "Ratio should be ~2.0, got {ratio}"
            );
        }
    }

    /// Test 6: Version-specific delays differ
    #[test]
    fn test_version_specific_delays() {
        let rollout = StagedRollout::new(b"node-1", 24);
        let v1 = semver::Version::new(1, 0, 0);
        let v2 = semver::Version::new(2, 0, 0);

        let delay_v1 = rollout.calculate_delay_for_version(&v1);
        let delay_v2 = rollout.calculate_delay_for_version(&v2);

        // Different versions should produce different delays
        assert_ne!(delay_v1, delay_v2);
    }

    /// Test 7: Max delay hours getter
    #[test]
    fn test_max_delay_hours_getter() {
        let rollout = StagedRollout::new(b"node", 48);
        assert_eq!(rollout.max_delay_hours(), 48);
    }

    /// Test 8: Large node ID handled correctly
    #[test]
    fn test_large_node_id() {
        let large_id = vec![0xABu8; 1000];
        let rollout = StagedRollout::new(&large_id, 24);
        let delay = rollout.calculate_delay();

        assert!(delay <= Duration::from_hours(24));
    }

    /// Test 9: Empty node ID handled
    #[test]
    fn test_empty_node_id() {
        let rollout = StagedRollout::new(&[], 24);
        let delay = rollout.calculate_delay();

        // Should still produce a valid delay
        assert!(delay <= Duration::from_hours(24));
    }

    /// Test 10: Distribution test - ensure delays are spread across window
    #[test]
    fn test_delay_distribution() {
        let max_hours = 24u64;
        let max_secs = max_hours * 3600;
        let mut delays = Vec::new();

        // Generate 100 different node delays
        for i in 0..100 {
            let node_id = format!("node-{i}");
            let rollout = StagedRollout::new(node_id.as_bytes(), max_hours);
            delays.push(rollout.calculate_delay().as_secs());
        }

        // Calculate basic statistics
        let min = *delays.iter().min().unwrap();
        let max = *delays.iter().max().unwrap();

        // Delays should be distributed across the window
        // At least some should be in the first quarter and some in the last quarter
        assert!(min < max_secs / 4, "Should have some early delays");
        assert!(max > 3 * max_secs / 4, "Should have some late delays");
    }
}
