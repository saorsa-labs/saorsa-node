//! Persistent `PaidForList` backed by LMDB.
//!
//! Tracks keys this node believes are paid-authorized. Survives restarts
//! (Invariant 15). Bounded by `PaidCloseGroup` membership with
//! hysteresis-based pruning.
//!
//! ## Storage layout
//!
//! ```text
//! {root}/paid_list.mdb/   -- LMDB environment directory
//! ```
//!
//! One unnamed database stores set membership: key = 32-byte `XorName`,
//! value = empty byte slice.
//!
//! ## Out-of-range timestamps
//!
//! Per-key `PaidOutOfRangeFirstSeen` and `RecordOutOfRangeFirstSeen`
//! timestamps live in memory only. On restart the hysteresis clock
//! restarts from zero, which is safe: the prune timer simply starts
//! fresh.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use crate::logging::{debug, trace, warn};
use heed::types::Bytes;
use heed::{Database, Env, EnvOpenOptions};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::Path;
use std::time::Instant;
use tokio::task::spawn_blocking;
use tokio_util::task::TaskTracker;

use crate::ant_protocol::XORNAME_LEN;

/// Default LMDB map size for the paid list: 256 MiB.
///
/// The paid list stores only 32-byte keys with empty values, so this is
/// generous even for very large close-group memberships.
const DEFAULT_MAP_SIZE: usize = 256 * 1_024 * 1_024;

/// Persistent paid-for-list backed by LMDB.
///
/// Tracks which keys this node believes are paid-authorized.
/// Survives node restarts via LMDB persistence.
pub struct PaidList {
    /// LMDB environment.
    env: Env,
    /// The unnamed default database (key = `XorName` bytes, value = empty).
    db: Database<Bytes, Bytes>,
    /// In-memory: when each paid key first went out of `PaidCloseGroup` range.
    /// Cleared on restart (safe: hysteresis clock restarts from zero).
    paid_out_of_range: RwLock<HashMap<XorName, Instant>>,
    /// In-memory: when each stored record first went out of
    /// storage-responsibility range.
    record_out_of_range: RwLock<HashMap<XorName, Instant>>,
    /// Cursor used by paid-list pruning to rotate through expired entries when
    /// the per-pass remote confirmation cap is exhausted.
    paid_prune_cursor: RwLock<usize>,
    /// Tracks every paid-list LMDB blocking task.
    ///
    /// Same rationale as `ChunkStore::blocking_tracker`: a `spawn_blocking`
    /// closure owns a cloned [`Env`] and keeps running when its async awaiter
    /// is dropped, so [`Self::wait_idle`] waits on the blocking tasks
    /// themselves before the environment may be reopened.
    blocking_tracker: TaskTracker,
}

impl PaidList {
    /// Open or create a `PaidList` backed by LMDB at `{root_dir}/paid_list.mdb/`.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB environment cannot be opened or the
    /// database cannot be created.
    #[allow(unsafe_code)]
    pub async fn new(root_dir: &Path) -> Result<Self> {
        let env_dir = root_dir.join("paid_list.mdb");

        std::fs::create_dir_all(&env_dir)
            .map_err(|e| Error::Storage(format!("Failed to create paid-list directory: {e}")))?;

        let env_dir_clone = env_dir.clone();
        // Constructor-only blocking task: it runs before `self` (and its
        // `blocking_tracker`) exists, so it is deliberately untracked.  The
        // constructor awaits it right here, so it cannot outlive this call.
        let (env, db) = spawn_blocking(move || -> Result<(Env, Database<Bytes, Bytes>)> {
            // SAFETY: `EnvOpenOptions::open()` is unsafe because LMDB uses
            // memory-mapped I/O and relies on OS file-locking to prevent
            // corruption from concurrent access by multiple processes. We
            // satisfy this by giving each node instance a unique `root_dir`
            // (typically named by its full 64-hex peer ID), ensuring no two
            // processes open the same LMDB environment.
            let env = unsafe {
                EnvOpenOptions::new()
                    .map_size(DEFAULT_MAP_SIZE)
                    .max_dbs(1)
                    .open(&env_dir_clone)
                    .map_err(|e| {
                        Error::Storage(format!("Failed to open paid-list LMDB env: {e}"))
                    })?
            };

            let mut wtxn = env
                .write_txn()
                .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
            let db: Database<Bytes, Bytes> = env
                .create_database(&mut wtxn, None)
                .map_err(|e| Error::Storage(format!("Failed to create paid-list database: {e}")))?;
            wtxn.commit()
                .map_err(|e| Error::Storage(format!("Failed to commit db creation: {e}")))?;

            Ok((env, db))
        })
        .await
        .map_err(|e| Error::Storage(format!("Paid-list init task failed: {e}")))??;

        let paid_list = Self {
            env,
            db,
            paid_out_of_range: RwLock::new(HashMap::new()),
            record_out_of_range: RwLock::new(HashMap::new()),
            paid_prune_cursor: RwLock::new(0),
            blocking_tracker: TaskTracker::new(),
        };

        let count = paid_list.count()?;
        debug!("Initialized paid-list at {env_dir:?} ({count} existing keys)");

        Ok(paid_list)
    }

    /// Insert a key into the paid-for set.
    ///
    /// Returns `true` if the key was newly added, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn insert(&self, key: &XorName) -> Result<bool> {
        // Fast-path: avoid write transaction if key already present.
        if self.contains(key)? {
            trace!("Paid-list key {} already present", hex::encode(key));
            return Ok(false);
        }

        let key_owned = *key;
        let env = self.env.clone();
        let db = self.db;

        let was_new = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

                // Authoritative existence check inside the serialized write txn.
                if db
                    .get(&wtxn, &key_owned)
                    .map_err(|e| {
                        Error::Storage(format!("Failed to check paid-list existence: {e}"))
                    })?
                    .is_some()
                {
                    return Ok(false);
                }

                db.put(&mut wtxn, &key_owned, &[])
                    .map_err(|e| Error::Storage(format!("Failed to insert into paid-list: {e}")))?;
                wtxn.commit().map_err(|e| {
                    Error::Storage(format!("Failed to commit paid-list insert: {e}"))
                })?;

                Ok(true)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list insert task failed: {e}")))??;

        if was_new {
            debug!("Added key {} to paid-list", hex::encode(key));
        }

        Ok(was_new)
    }

    /// Remove a key from the paid-for set.
    ///
    /// Also clears any in-memory out-of-range timestamps for this key.
    ///
    /// Returns `true` if the key existed and was removed, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn remove(&self, key: &XorName) -> Result<bool> {
        let key_owned = *key;
        let env = self.env.clone();
        let db = self.db;

        let existed = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<bool> {
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;
                let deleted = db
                    .delete(&mut wtxn, &key_owned)
                    .map_err(|e| Error::Storage(format!("Failed to delete from paid-list: {e}")))?;
                wtxn.commit().map_err(|e| {
                    Error::Storage(format!("Failed to commit paid-list delete: {e}"))
                })?;
                Ok(deleted)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list remove task failed: {e}")))??;

        if existed {
            self.paid_out_of_range.write().remove(key);
            self.record_out_of_range.write().remove(key);
            debug!("Removed key {} from paid-list", hex::encode(key));
        }

        Ok(existed)
    }

    /// Check whether a key is in the paid-for set.
    ///
    /// This is a synchronous read-only operation (no write transaction needed).
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn contains(&self, key: &XorName) -> Result<bool> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let found = self
            .db
            .get(&rtxn, key.as_ref())
            .map_err(|e| Error::Storage(format!("Failed to check paid-list membership: {e}")))?
            .is_some();
        Ok(found)
    }

    /// Return the number of keys in the paid-for set.
    ///
    /// This is an O(1) read of the B-tree page header, not a full scan.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction fails.
    pub fn count(&self) -> Result<u64> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let entries = self
            .db
            .stat(&rtxn)
            .map_err(|e| Error::Storage(format!("Failed to read paid-list stats: {e}")))?
            .entries;
        Ok(entries as u64)
    }

    /// Return all keys in the paid-for set.
    ///
    /// Used during hint construction to advertise which keys this node holds.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB read transaction or iteration fails.
    pub fn all_keys(&self) -> Result<Vec<XorName>> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| Error::Storage(format!("Failed to create read txn: {e}")))?;
        let mut keys = Vec::new();
        let iter = self
            .db
            .iter(&rtxn)
            .map_err(|e| Error::Storage(format!("Failed to iterate paid-list: {e}")))?;
        for result in iter {
            let (key_bytes, _) = result
                .map_err(|e| Error::Storage(format!("Failed to read paid-list entry: {e}")))?;
            if key_bytes.len() == XORNAME_LEN {
                let mut key = [0u8; XORNAME_LEN];
                key.copy_from_slice(key_bytes);
                keys.push(key);
            } else {
                warn!(
                    "PaidList: skipping entry with unexpected key length {} (expected {XORNAME_LEN})",
                    key_bytes.len()
                );
            }
        }
        Ok(keys)
    }

    /// Record the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Only sets the timestamp if one is not already recorded (first
    /// observation wins).
    pub fn set_paid_out_of_range(&self, key: &XorName) {
        self.paid_out_of_range
            .write()
            .entry(*key)
            .or_insert_with(Instant::now);
    }

    /// Clear the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Called when the key moves back into `PaidCloseGroup` range.
    pub fn clear_paid_out_of_range(&self, key: &XorName) {
        self.paid_out_of_range.write().remove(key);
    }

    /// Get the `PaidOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Returns `None` if the key is currently in range (no timestamp set).
    pub fn paid_out_of_range_since(&self, key: &XorName) -> Option<Instant> {
        self.paid_out_of_range.read().get(key).copied()
    }

    /// Record the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Only sets the timestamp if one is not already recorded (first
    /// observation wins).
    pub fn set_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range
            .write()
            .entry(*key)
            .or_insert_with(Instant::now);
    }

    /// Clear the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Called when the record moves back into storage-responsibility range.
    pub fn clear_record_out_of_range(&self, key: &XorName) {
        self.record_out_of_range.write().remove(key);
    }

    /// Get the `RecordOutOfRangeFirstSeen` timestamp for a key.
    ///
    /// Returns `None` if the record is currently in range (no timestamp set).
    pub fn record_out_of_range_since(&self, key: &XorName) -> Option<Instant> {
        self.record_out_of_range.read().get(key).copied()
    }

    /// Starting offset for the next paid-list prune scan.
    ///
    /// LMDB iteration order is stable, so a bounded prune pass must rotate its
    /// verification window or later expired entries can be starved behind
    /// earlier unconfirmed entries.
    pub(crate) fn paid_prune_scan_start(&self, paid_key_count: usize) -> usize {
        if paid_key_count == 0 {
            return 0;
        }

        *self.paid_prune_cursor.read() % paid_key_count
    }

    /// Advance the paid-list prune cursor after one pass.
    pub(crate) fn advance_paid_prune_cursor(
        &self,
        paid_key_count: usize,
        scan_start: usize,
        last_selected_offset: Option<usize>,
    ) {
        let mut cursor = self.paid_prune_cursor.write();
        if paid_key_count == 0 {
            *cursor = 0;
            return;
        }

        let advance_by = last_selected_offset.map_or(1, |offset| offset.saturating_add(1));
        *cursor = (scan_start + advance_by) % paid_key_count;
    }

    /// Remove multiple keys in a single write transaction.
    ///
    /// Also clears any in-memory out-of-range timestamps for removed keys.
    ///
    /// Returns the number of keys that were actually present and removed.
    ///
    /// # Cancellation
    ///
    /// The delete commits inside `spawn_blocking`, which cancellation cannot
    /// reach; the timestamp clear below happens only after that await resumes.
    /// Dropping this future in between therefore leaves keys deleted on disk
    /// with their `paid_out_of_range` entries still set.
    ///
    /// That window is deliberately left open. The only caller is the prune pass
    /// (`pruning::prune_paid_entries`), reached from `run_neighbor_sync_round`,
    /// which is awaited inside a `select!` racing the engine's shutdown token —
    /// so shutdown is the only way to hit it. `paid_out_of_range` is in-memory
    /// only (never persisted), so the stale entries die with the process that
    /// cancelled the prune, and a reopened `PaidList` starts with an empty map.
    ///
    /// Do NOT "fix" this by clearing the timestamps before the commit: a failed
    /// commit would then leave a live key with a cleared hysteresis clock,
    /// restarting its prune countdown from zero. That is a real correctness
    /// regression in exchange for a window with no observable effect.
    ///
    /// # Errors
    ///
    /// Returns an error if the LMDB write transaction fails.
    pub async fn remove_batch(&self, keys: &[XorName]) -> Result<usize> {
        if keys.is_empty() {
            return Ok(0);
        }

        let keys_owned: Vec<XorName> = keys.to_vec();
        let env = self.env.clone();
        let db = self.db;

        let removed_keys = self
            .blocking_tracker
            .spawn_blocking(move || -> Result<Vec<XorName>> {
                let mut wtxn = env
                    .write_txn()
                    .map_err(|e| Error::Storage(format!("Failed to create write txn: {e}")))?;

                let mut removed = Vec::new();
                for key in &keys_owned {
                    let deleted = db.delete(&mut wtxn, key.as_ref()).map_err(|e| {
                        Error::Storage(format!("Failed to delete from paid-list: {e}"))
                    })?;
                    if deleted {
                        removed.push(*key);
                    }
                }

                wtxn.commit()
                    .map_err(|e| Error::Storage(format!("Failed to commit batch remove: {e}")))?;

                Ok(removed)
            })
            .await
            .map_err(|e| Error::Storage(format!("Paid-list batch remove task failed: {e}")))??;

        // Clear in-memory timestamps for all removed keys.
        // Acquire and release each lock separately to minimize hold time.
        if !removed_keys.is_empty() {
            {
                let mut paid_oor = self.paid_out_of_range.write();
                for key in &removed_keys {
                    paid_oor.remove(key);
                }
            }
            {
                let mut record_oor = self.record_out_of_range.write();
                for key in &removed_keys {
                    record_oor.remove(key);
                }
            }
        }

        let count = removed_keys.len();
        debug!("Batch-removed {count} keys from paid-list");
        Ok(count)
    }

    /// Wait until every tracked paid-list LMDB blocking task has finished.
    ///
    /// Dropping an async caller (e.g. a `select!` losing to a shutdown token)
    /// does not cancel an already-spawned blocking closure — the closure keeps
    /// running on the blocking pool with a cloned [`Env`].  This method waits
    /// for those detached closures too, so when it returns no blocking
    /// operation still holds the environment.
    ///
    /// Quiescence is only meaningful once callers have stopped issuing new
    /// operations; concurrent traffic can keep the tracker non-empty
    /// indefinitely.  The paid list remains fully usable afterwards (the
    /// internal tracker is reopened before returning).
    pub async fn wait_idle(&self) {
        self.blocking_tracker.close();
        self.blocking_tracker.wait().await;
        self.blocking_tracker.reopen();
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Short probe used to prove `wait_idle` is still blocked on a parked op.
    const WAIT_IDLE_BLOCKED_PROBE: std::time::Duration = std::time::Duration::from_millis(200);
    /// Generous ceiling for `wait_idle` to complete once the op is released.
    const WAIT_IDLE_COMPLETE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

    async fn create_test_paid_list() -> (PaidList, tempfile::TempDir) {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let paid_list = PaidList::new(temp_dir.path())
            .await
            .expect("create paid list");
        (paid_list, temp_dir)
    }

    #[tokio::test]
    async fn test_insert_and_contains() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xAA; 32];
        assert!(!pl.contains(&key).expect("contains before insert"));

        let was_new = pl.insert(&key).await.expect("insert");
        assert!(was_new);

        assert!(pl.contains(&key).expect("contains after insert"));
    }

    #[tokio::test]
    async fn test_insert_duplicate_returns_false() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xBB; 32];

        let first = pl.insert(&key).await.expect("first insert");
        assert!(first);

        let second = pl.insert(&key).await.expect("second insert");
        assert!(!second);
    }

    #[tokio::test]
    async fn test_remove_existing() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xCC; 32];
        pl.insert(&key).await.expect("insert");
        assert!(pl.contains(&key).expect("contains"));

        let removed = pl.remove(&key).await.expect("remove");
        assert!(removed);
        assert!(!pl.contains(&key).expect("contains after remove"));
    }

    #[tokio::test]
    async fn test_remove_nonexistent() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xDD; 32];
        let removed = pl.remove(&key).await.expect("remove nonexistent");
        assert!(!removed);
    }

    #[tokio::test]
    async fn test_persistence_across_reopen() {
        let temp_dir = tempfile::TempDir::new().expect("create temp dir");
        let key: XorName = [0xEE; 32];

        // Insert a key, then drop the PaidList.
        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("create paid list");
            pl.insert(&key).await.expect("insert");
            assert_eq!(pl.count().expect("count"), 1);
        }

        // Re-open and verify the key persisted.
        {
            let pl = PaidList::new(temp_dir.path())
                .await
                .expect("reopen paid list");
            assert_eq!(pl.count().expect("count"), 1);
            assert!(pl.contains(&key).expect("contains after reopen"));
        }
    }

    #[tokio::test]
    async fn test_all_keys() {
        let (pl, _temp) = create_test_paid_list().await;

        let key_a: XorName = [0x01; 32];
        let key_b: XorName = [0x02; 32];
        let key_c: XorName = [0x03; 32];

        pl.insert(&key_a).await.expect("insert 1");
        pl.insert(&key_b).await.expect("insert 2");
        pl.insert(&key_c).await.expect("insert 3");

        let mut keys = pl.all_keys().expect("all_keys");
        keys.sort_unstable();

        let mut expected = vec![key_a, key_b, key_c];
        expected.sort_unstable();

        assert_eq!(keys, expected);
    }

    #[tokio::test]
    async fn test_count() {
        let (pl, _temp) = create_test_paid_list().await;

        assert_eq!(pl.count().expect("count empty"), 0);

        let key1: XorName = [0x10; 32];
        let key2: XorName = [0x20; 32];

        pl.insert(&key1).await.expect("insert 1");
        assert_eq!(pl.count().expect("count after 1"), 1);

        pl.insert(&key2).await.expect("insert 2");
        assert_eq!(pl.count().expect("count after 2"), 2);

        pl.remove(&key1).await.expect("remove 1");
        assert_eq!(pl.count().expect("count after remove"), 1);
    }

    #[tokio::test]
    async fn test_paid_out_of_range_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xF0; 32];

        // Initially no timestamp.
        assert!(pl.paid_out_of_range_since(&key).is_none());

        // Set timestamp.
        let before = Instant::now();
        pl.set_paid_out_of_range(&key);
        let after = Instant::now();

        let ts = pl
            .paid_out_of_range_since(&key)
            .expect("timestamp should exist");
        assert!(ts >= before);
        assert!(ts <= after);

        // Setting again should not update (first observation wins).
        std::thread::sleep(std::time::Duration::from_millis(10));
        pl.set_paid_out_of_range(&key);
        let ts2 = pl
            .paid_out_of_range_since(&key)
            .expect("timestamp should still exist");
        assert_eq!(ts, ts2);

        // Clear.
        pl.clear_paid_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_record_out_of_range_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xF1; 32];

        assert!(pl.record_out_of_range_since(&key).is_none());

        let before = Instant::now();
        pl.set_record_out_of_range(&key);
        let after = Instant::now();

        let ts = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist");
        assert!(ts >= before);
        assert!(ts <= after);

        // Setting again should not update.
        std::thread::sleep(std::time::Duration::from_millis(10));
        pl.set_record_out_of_range(&key);
        let ts2 = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should still exist");
        assert_eq!(ts, ts2);

        // Clear.
        pl.clear_record_out_of_range(&key);
        assert!(pl.record_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_remove_clears_timestamps() {
        let (pl, _temp) = create_test_paid_list().await;

        let key: XorName = [0xA0; 32];
        pl.insert(&key).await.expect("insert");

        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_some());
        assert!(pl.record_out_of_range_since(&key).is_some());

        pl.remove(&key).await.expect("remove");
        assert!(pl.paid_out_of_range_since(&key).is_none());
        assert!(pl.record_out_of_range_since(&key).is_none());
    }

    #[tokio::test]
    async fn test_remove_batch() {
        let (pl, _temp) = create_test_paid_list().await;

        let key1: XorName = [0x01; 32];
        let key2: XorName = [0x02; 32];
        let key3: XorName = [0x03; 32];
        let key4: XorName = [0x04; 32]; // not inserted

        pl.insert(&key1).await.expect("insert 1");
        pl.insert(&key2).await.expect("insert 2");
        pl.insert(&key3).await.expect("insert 3");

        // Set timestamps to verify they get cleared.
        pl.set_paid_out_of_range(&key1);
        pl.set_record_out_of_range(&key2);

        let removed = pl
            .remove_batch(&[key1, key2, key4])
            .await
            .expect("remove_batch");
        assert_eq!(removed, 2); // key1 and key2 existed; key4 did not

        assert!(!pl.contains(&key1).expect("key1 gone"));
        assert!(!pl.contains(&key2).expect("key2 gone"));
        assert!(pl.contains(&key3).expect("key3 still present"));
        assert_eq!(pl.count().expect("count"), 1);

        // Timestamps should be cleared for removed keys.
        assert!(pl.paid_out_of_range_since(&key1).is_none());
        assert!(pl.record_out_of_range_since(&key2).is_none());
    }

    #[tokio::test]
    async fn test_remove_batch_empty() {
        let (pl, _temp) = create_test_paid_list().await;

        let removed = pl.remove_batch(&[]).await.expect("remove_batch empty");
        assert_eq!(removed, 0);
    }

    /// Park the paid-list env's single LMDB writer slot on a test-held write
    /// transaction, so the next tracked write blocks inside its closure.
    ///
    /// Returns once the transaction is open. Dropping the returned sender
    /// releases the slot.
    async fn hold_write_txn(
        pl: &PaidList,
    ) -> (
        tokio::sync::oneshot::Sender<()>,
        tokio::task::JoinHandle<()>,
    ) {
        let env = pl.env.clone();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let (opened_tx, opened_rx) = tokio::sync::oneshot::channel::<()>();
        let holder = tokio::task::spawn_blocking(move || {
            let _wtxn = env.write_txn().expect("open holder write txn");
            let _ = opened_tx.send(());
            let _ = release_rx.blocking_recv();
        });
        opened_rx.await.expect("holder txn opened");
        (release_tx, holder)
    }

    /// Dropping an `insert` awaiter does not cancel its `spawn_blocking` LMDB
    /// transaction; `wait_idle` must wait for that detached write, and the
    /// paid list must remain usable afterwards.
    #[tokio::test]
    async fn wait_idle_waits_for_detached_insert_blocking_op() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x77; 32];

        let (release, holder) = hold_write_txn(&pl).await;

        // Drop the awaiting future mid-flight: the biased select! polls the
        // insert once — far enough to spawn the blocking task, which parks on
        // the held writer slot — then completes on the ready branch.
        tokio::select! {
            biased;
            res = pl.insert(&key) => {
                panic!("insert must be parked on the writer slot, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        // The blocking op is still running: wait_idle must not complete.
        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, pl.wait_idle()).await;
        assert!(
            blocked.is_err(),
            "wait_idle returned while the insert blocking op was parked"
        );

        // Release the writer slot: the detached closure commits and exits.
        drop(release);
        holder.await.expect("holder task");
        tokio::time::timeout(WAIT_IDLE_COMPLETE_TIMEOUT, pl.wait_idle())
            .await
            .expect("wait_idle after release");

        // The dropped awaiter did not lose the write: it committed.
        assert!(pl.contains(&key).expect("contains after release"));

        // The paid list remains usable after wait_idle (tracker reopened).
        let key2: XorName = [0x78; 32];
        assert!(pl.insert(&key2).await.expect("insert after wait_idle"));
    }

    /// Same shape as the insert test, for `remove_batch`: a detached batch
    /// removal must hold `wait_idle` open until its transaction commits.
    #[tokio::test]
    async fn wait_idle_waits_for_detached_remove_batch_blocking_op() {
        let (pl, _temp) = create_test_paid_list().await;
        let key_a: XorName = [0x79; 32];
        let key_b: XorName = [0x7A; 32];
        pl.insert(&key_a).await.expect("insert a");
        pl.insert(&key_b).await.expect("insert b");

        let (release, holder) = hold_write_txn(&pl).await;

        let batch = [key_a, key_b];
        tokio::select! {
            biased;
            res = pl.remove_batch(&batch) => {
                panic!("remove_batch must be parked on the writer slot, got {res:?}")
            }
            () = std::future::ready(()) => {}
        }

        let blocked = tokio::time::timeout(WAIT_IDLE_BLOCKED_PROBE, pl.wait_idle()).await;
        assert!(
            blocked.is_err(),
            "wait_idle returned while the remove_batch blocking op was parked"
        );

        drop(release);
        holder.await.expect("holder task");
        tokio::time::timeout(WAIT_IDLE_COMPLETE_TIMEOUT, pl.wait_idle())
            .await
            .expect("wait_idle after release");

        // The dropped awaiter did not lose the batch removal: it committed.
        assert!(!pl.contains(&key_a).expect("key_a removed"));
        assert!(!pl.contains(&key_b).expect("key_b removed"));

        // The paid list remains usable after wait_idle (tracker reopened).
        assert!(pl.insert(&key_a).await.expect("insert after wait_idle"));
    }

    #[tokio::test]
    async fn paid_prune_cursor_advances_past_selected_window() {
        const PAID_KEY_COUNT: usize = 10;
        const START_CURSOR: usize = 2;
        const LAST_SELECTED_OFFSET: usize = 3;
        const EXPECTED_CURSOR: usize = 6;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = START_CURSOR;

        let scan_start = pl.paid_prune_scan_start(PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(PAID_KEY_COUNT, scan_start, Some(LAST_SELECTED_OFFSET));

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    #[tokio::test]
    async fn paid_prune_cursor_advances_even_without_selected_entry() {
        const PAID_KEY_COUNT: usize = 10;
        const START_CURSOR: usize = 9;
        const EXPECTED_CURSOR: usize = 0;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = START_CURSOR;

        let scan_start = pl.paid_prune_scan_start(PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(PAID_KEY_COUNT, scan_start, None);

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    #[tokio::test]
    async fn paid_prune_cursor_resets_for_empty_paid_list() {
        const STALE_CURSOR: usize = 7;
        const EMPTY_PAID_KEY_COUNT: usize = 0;
        const EXPECTED_CURSOR: usize = 0;

        let (pl, _temp) = create_test_paid_list().await;
        *pl.paid_prune_cursor.write() = STALE_CURSOR;

        let scan_start = pl.paid_prune_scan_start(EMPTY_PAID_KEY_COUNT);
        pl.advance_paid_prune_cursor(EMPTY_PAID_KEY_COUNT, scan_start, Some(STALE_CURSOR));

        assert_eq!(*pl.paid_prune_cursor.read(), EXPECTED_CURSOR);
    }

    // -- Scenario tests -------------------------------------------------------

    /// #50: Key goes out of range. `set_record_out_of_range` called.
    /// Immediately the elapsed time is less than `PRUNE_HYSTERESIS_DURATION`,
    /// so a prune pass should NOT delete it. We verify the timestamp is
    /// present but recent.
    #[tokio::test]
    async fn scenario_50_hysteresis_prevents_premature_deletion() {
        let hysteresis = crate::replication::config::PRUNE_HYSTERESIS_DURATION;
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x50; 32];

        // Key goes out of range — record the timestamp.
        pl.set_record_out_of_range(&key);

        // Timestamp must be present.
        let since = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist after set");

        // Elapsed time is effectively zero — well below hysteresis threshold.
        let elapsed = since.elapsed();
        assert!(
            elapsed < hysteresis,
            "elapsed ({elapsed:?}) should be far below PRUNE_HYSTERESIS_DURATION ({hysteresis:?})",
        );
    }

    /// #51: Key goes out of range, then comes back. Timestamp is cleared.
    /// If the key leaves again, the clock restarts from now.
    #[tokio::test]
    async fn scenario_51_timestamp_reset_on_heal() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x51; 32];

        // Key goes out of range.
        pl.set_record_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "timestamp should exist after going out of range"
        );

        // Partition heals — key comes back in range.
        pl.clear_record_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_none(),
            "timestamp should be cleared after heal"
        );

        // Key goes out of range again — clock must restart.
        let before_second = Instant::now();
        pl.set_record_out_of_range(&key);
        let second_ts = pl
            .record_out_of_range_since(&key)
            .expect("timestamp should exist after second out-of-range");
        assert!(
            second_ts >= before_second,
            "new timestamp should be >= the instant before second set call"
        );
    }

    /// #52: Paid and record out-of-range timestamps are independent.
    /// Clearing one must not affect the other.
    #[tokio::test]
    async fn scenario_52_paid_and_record_timestamps_independent() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x52; 32];

        // Set both timestamps.
        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);
        assert!(pl.paid_out_of_range_since(&key).is_some());
        assert!(pl.record_out_of_range_since(&key).is_some());

        // Clear record — paid must survive.
        pl.clear_record_out_of_range(&key);
        assert!(
            pl.paid_out_of_range_since(&key).is_some(),
            "paid timestamp should survive clearing record timestamp"
        );
        assert!(pl.record_out_of_range_since(&key).is_none());

        // Re-set record, then clear paid — record must survive.
        pl.set_record_out_of_range(&key);
        pl.clear_paid_out_of_range(&key);
        assert!(
            pl.record_out_of_range_since(&key).is_some(),
            "record timestamp should survive clearing paid timestamp"
        );
        assert!(pl.paid_out_of_range_since(&key).is_none());
    }

    /// #23: Inserting then removing a key from the paid list clears both
    /// the persistence entry and any in-memory out-of-range timestamps.
    #[tokio::test]
    async fn scenario_23_paid_list_entry_removed() {
        let (pl, _temp) = create_test_paid_list().await;
        let key: XorName = [0x23; 32];

        // Insert key and attach out-of-range timestamps.
        pl.insert(&key).await.expect("insert");
        pl.set_paid_out_of_range(&key);
        pl.set_record_out_of_range(&key);

        // Remove — should clear everything.
        let removed = pl.remove(&key).await.expect("remove");
        assert!(removed, "key should have existed");
        assert!(
            !pl.contains(&key).expect("contains check"),
            "key should be gone from paid list"
        );
        assert!(
            pl.paid_out_of_range_since(&key).is_none(),
            "paid timestamp should be cleaned up on remove"
        );
        assert!(
            pl.record_out_of_range_since(&key).is_none(),
            "record timestamp should be cleaned up on remove"
        );
    }

    /// #13: Responsible range shrink — out-of-range records have their
    /// timestamp recorded, are NOT pruned before `PRUNE_HYSTERESIS_DURATION`,
    /// and new in-range keys are still accepted while out-of-range keys
    /// await expiry.
    #[tokio::test]
    async fn scenario_13_responsible_range_shrink() {
        let hysteresis = crate::replication::config::PRUNE_HYSTERESIS_DURATION;
        let (pl, _temp) = create_test_paid_list().await;

        let out_of_range_key: XorName = [0x13; 32];
        let in_range_key: XorName = [0x14; 32];

        // Insert both keys initially (simulating they were once in range).
        pl.insert(&out_of_range_key)
            .await
            .expect("insert out-of-range");
        pl.insert(&in_range_key).await.expect("insert in-range");

        // Range shrinks: out_of_range_key is no longer in responsibility range.
        // Record RecordOutOfRangeFirstSeen.
        pl.set_record_out_of_range(&out_of_range_key);
        let first_seen = pl
            .record_out_of_range_since(&out_of_range_key)
            .expect("timestamp should be recorded for out-of-range key");

        // Key must NOT be pruned yet — elapsed time is far below hysteresis.
        let elapsed = first_seen.elapsed();
        assert!(
            elapsed < hysteresis,
            "elapsed {elapsed:?} should be below PRUNE_HYSTERESIS_DURATION \
             ({hysteresis:?}) — key must not be pruned yet"
        );

        // The key should still exist in the paid list (not deleted).
        assert!(
            pl.contains(&out_of_range_key).expect("contains"),
            "out-of-range key should still be retained within hysteresis window"
        );

        // In-range key is unaffected — no out-of-range timestamp set.
        assert!(
            pl.record_out_of_range_since(&in_range_key).is_none(),
            "in-range key should have no out-of-range timestamp"
        );

        // New in-range keys are still accepted during this period.
        let new_key: XorName = [0x15; 32];
        let was_new = pl.insert(&new_key).await.expect("insert new key");
        assert!(
            was_new,
            "new in-range keys should still be accepted while out-of-range keys await expiry"
        );
        assert!(
            pl.contains(&new_key).expect("contains new"),
            "newly inserted in-range key should be present"
        );
    }

    /// #46: Bootstrap claim first-seen is recorded and follows
    /// first-observation-wins semantics.
    #[test]
    fn scenario_46_bootstrap_claim_first_seen_recorded() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x46; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        let first_ts = Instant::now()
            .checked_sub(std::time::Duration::from_secs(3))
            .unwrap_or_else(Instant::now);
        let observed = state.observe_bootstrap_claim(peer, first_ts, grace_period);
        assert_eq!(
            observed,
            crate::replication::types::BootstrapClaimObservation::WithinGrace {
                first_seen: first_ts
            }
        );

        // Verify recorded.
        assert_eq!(
            state.bootstrap_claims.get(&peer),
            Some(&first_ts),
            "first-seen timestamp should be recorded"
        );
        assert_eq!(
            state.bootstrap_claim_history.get(&peer),
            Some(&first_ts),
            "first-ever timestamp should be retained"
        );

        // Observe again while still active — must NOT overwrite
        // (first-observation-wins).
        let later_ts = Instant::now();
        let observed = state.observe_bootstrap_claim(peer, later_ts, grace_period);
        assert_eq!(
            observed,
            crate::replication::types::BootstrapClaimObservation::WithinGrace {
                first_seen: first_ts
            }
        );
        assert_eq!(
            state.bootstrap_claims.get(&peer),
            Some(&first_ts),
            "second insert must not overwrite the original timestamp"
        );
    }

    /// #48: Peer P first claimed bootstrapping >24 h ago.  On next interaction
    /// the claim age exceeds `BOOTSTRAP_CLAIM_GRACE_PERIOD` and the node emits
    /// `BootstrapClaimAbuse` evidence.
    #[test]
    fn scenario_48_bootstrap_claim_abuse_after_grace_period() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x48; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        // Record a first-seen timestamp >24 h ago.
        // `Instant::checked_sub` can fail on Windows where the epoch is
        // process-start, so fall back to a recent instant when the platform
        // cannot represent the backdated time (the claim-age assertion is
        // skipped in that case since the subtraction itself proves nothing
        // about production behaviour).
        let grace_plus_margin = grace_period + std::time::Duration::from_secs(3600);
        let first_seen = Instant::now()
            .checked_sub(grace_plus_margin)
            .unwrap_or_else(Instant::now);
        state.bootstrap_claims.insert(peer, first_seen);
        state.bootstrap_claim_history.insert(peer, first_seen);

        // On platforms that support the backdated instant, verify claim age.
        let claim_age = Instant::now().duration_since(first_seen);
        if claim_age > std::time::Duration::from_secs(1) {
            assert!(
                claim_age > grace_period,
                "claim age {claim_age:?} should exceed grace period {grace_period:?}",
            );
        }

        // Caller constructs BootstrapClaimAbuse evidence.
        let evidence =
            crate::replication::types::FailureEvidence::BootstrapClaimAbuse { peer, first_seen };

        let crate::replication::types::FailureEvidence::BootstrapClaimAbuse {
            peer: p,
            first_seen: fs,
        } = evidence
        else {
            unreachable!("evidence was just constructed as BootstrapClaimAbuse");
        };
        assert_eq!(p, peer);
        assert_eq!(fs, first_seen);
    }

    /// #49: Bootstrap claim is cleared when a peer responds normally.
    #[test]
    fn scenario_49_bootstrap_claim_cleared() {
        let grace_period = crate::replication::config::BOOTSTRAP_CLAIM_GRACE_PERIOD;
        let peer = saorsa_core::identity::PeerId::from_bytes([0x49; 32]);
        let mut state = crate::replication::types::NeighborSyncState::new_cycle(vec![peer]);

        // Record a bootstrap claim.
        let first_seen = Instant::now();
        let _ = state.observe_bootstrap_claim(peer, first_seen, grace_period);
        assert!(
            state.bootstrap_claims.contains_key(&peer),
            "claim should exist after insert"
        );

        // Peer responded normally — clear only the active claim.
        state.clear_active_bootstrap_claim(&peer);
        assert!(
            !state.bootstrap_claims.contains_key(&peer),
            "claim should be gone after normal response"
        );
        assert!(
            state.bootstrap_claim_history.contains_key(&peer),
            "claim history should remain so the peer cannot claim bootstrapping again"
        );

        let repeated = state.observe_bootstrap_claim(peer, Instant::now(), grace_period);
        assert_eq!(
            repeated,
            crate::replication::types::BootstrapClaimObservation::Repeated { first_seen },
            "a second bootstrap claim should be classified as repeated abuse"
        );
    }
}
