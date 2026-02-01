//! Content-addressed disk storage with sharded directories.
//!
//! Provides persistent storage for chunks using a two-level directory structure
//! to avoid large directory listings:
//!
//! ```text
//! {root}/chunks/{xx}/{yy}/{address}.chunk
//! ```
//!
//! Where `xx` and `yy` are the first two bytes of the address in hex.

use crate::ant_protocol::XorName;
use crate::error::{Error, Result};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tokio::sync::Mutex;
use tracing::{debug, trace, warn};

/// Configuration for disk storage.
#[derive(Debug, Clone)]
pub struct DiskStorageConfig {
    /// Root directory for chunk storage.
    pub root_dir: PathBuf,
    /// Whether to verify content on read (compares hash to address).
    pub verify_on_read: bool,
    /// Maximum number of chunks to store (0 = unlimited).
    pub max_chunks: usize,
}

impl Default for DiskStorageConfig {
    fn default() -> Self {
        Self {
            root_dir: PathBuf::from(".saorsa/chunks"),
            verify_on_read: true,
            max_chunks: 0,
        }
    }
}

/// Statistics about storage operations.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total number of chunks stored.
    pub chunks_stored: u64,
    /// Total number of chunks retrieved.
    pub chunks_retrieved: u64,
    /// Total bytes stored.
    pub bytes_stored: u64,
    /// Total bytes retrieved.
    pub bytes_retrieved: u64,
    /// Number of duplicate writes (already exists).
    pub duplicates: u64,
    /// Number of verification failures on read.
    pub verification_failures: u64,
}

/// Content-addressed disk storage.
///
/// Uses a sharded directory structure for efficient storage:
/// ```text
/// {root}/chunks/{xx}/{yy}/{address}.chunk
/// ```
pub struct DiskStorage {
    /// Storage configuration.
    config: DiskStorageConfig,
    /// Operation statistics.
    stats: parking_lot::RwLock<StorageStats>,
    /// Per-address locks to prevent TOCTOU races on concurrent puts.
    address_locks: Mutex<HashMap<XorName, Arc<Mutex<()>>>>,
}

impl DiskStorage {
    /// Create a new disk storage instance.
    ///
    /// # Errors
    ///
    /// Returns an error if the root directory cannot be created.
    pub async fn new(config: DiskStorageConfig) -> Result<Self> {
        // Ensure root directory exists
        let chunks_dir = config.root_dir.join("chunks");
        fs::create_dir_all(&chunks_dir)
            .await
            .map_err(|e| Error::Storage(format!("Failed to create chunks directory: {e}")))?;

        debug!("Initialized disk storage at {:?}", config.root_dir);

        Ok(Self {
            config,
            stats: parking_lot::RwLock::new(StorageStats::default()),
            address_locks: Mutex::new(HashMap::new()),
        })
    }

    /// Store a chunk.
    ///
    /// Uses atomic write (temp file + rename) for crash safety.
    ///
    /// # Arguments
    ///
    /// * `address` - Content address (should be SHA256 of content)
    /// * `content` - Chunk data
    ///
    /// # Returns
    ///
    /// Returns `true` if the chunk was newly stored, `false` if it already existed.
    ///
    /// # Errors
    ///
    /// Returns an error if the write fails or content doesn't match address.
    pub async fn put(&self, address: &XorName, content: &[u8]) -> Result<bool> {
        // Verify content address
        let computed = Self::compute_address(content);
        if computed != *address {
            return Err(Error::Storage(format!(
                "Content address mismatch: expected {}, computed {}",
                hex::encode(address),
                hex::encode(computed)
            )));
        }

        // Acquire per-address lock to prevent TOCTOU races between
        // concurrent puts for the same address.
        let lock = {
            let mut locks = self.address_locks.lock().await;
            Arc::clone(
                locks
                    .entry(*address)
                    .or_insert_with(|| Arc::new(Mutex::new(()))),
            )
        };
        let _guard = lock.lock().await;

        let chunk_path = self.chunk_path(address);

        // Check if already exists (safe under per-address lock)
        let file_exists = fs::try_exists(&chunk_path).await.is_ok_and(|v| v);
        if file_exists {
            trace!("Chunk {} already exists", hex::encode(address));
            {
                let mut stats = self.stats.write();
                stats.duplicates += 1;
            }
            return Ok(false);
        }

        // Enforce max_chunks capacity limit (0 = unlimited)
        if self.config.max_chunks > 0 {
            let chunks_stored = self.stats.read().chunks_stored;
            if chunks_stored >= self.config.max_chunks as u64 {
                return Err(Error::Storage(format!(
                    "Storage capacity reached: {} chunks stored, max is {}",
                    chunks_stored, self.config.max_chunks
                )));
            }
        }

        // Ensure parent directories exist
        if let Some(parent) = chunk_path.parent() {
            fs::create_dir_all(parent)
                .await
                .map_err(|e| Error::Storage(format!("Failed to create shard directory: {e}")))?;
        }

        // Atomic write: temp file + sync + rename
        let temp_path = chunk_path.with_extension("tmp");
        let mut file = fs::File::create(&temp_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to create temp file: {e}")))?;

        file.write_all(content)
            .await
            .map_err(|e| Error::Storage(format!("Failed to write chunk: {e}")))?;

        file.sync_data()
            .await
            .map_err(|e| Error::Storage(format!("Failed to sync chunk to disk: {e}")))?;

        // Rename for atomic commit
        fs::rename(&temp_path, &chunk_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to rename temp file: {e}")))?;

        {
            let mut stats = self.stats.write();
            stats.chunks_stored += 1;
            stats.bytes_stored += content.len() as u64;
        }

        debug!(
            "Stored chunk {} ({} bytes)",
            hex::encode(address),
            content.len()
        );

        Ok(true)
    }

    /// Retrieve a chunk.
    ///
    /// # Arguments
    ///
    /// * `address` - Content address to retrieve
    ///
    /// # Returns
    ///
    /// Returns `Some(content)` if found, `None` if not found.
    ///
    /// # Errors
    ///
    /// Returns an error if read fails or verification fails.
    pub async fn get(&self, address: &XorName) -> Result<Option<Vec<u8>>> {
        let chunk_path = self.chunk_path(address);

        match fs::try_exists(&chunk_path).await {
            Ok(false) | Err(_) => {
                trace!("Chunk {} not found", hex::encode(address));
                return Ok(None);
            }
            Ok(true) => {}
        }

        let content = fs::read(&chunk_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to read chunk: {e}")))?;

        // Verify content if configured
        if self.config.verify_on_read {
            let computed = Self::compute_address(&content);
            if computed != *address {
                {
                    let mut stats = self.stats.write();
                    stats.verification_failures += 1;
                }
                warn!(
                    "Chunk verification failed: expected {}, computed {}",
                    hex::encode(address),
                    hex::encode(computed)
                );
                return Err(Error::Storage(format!(
                    "Chunk verification failed for {}",
                    hex::encode(address)
                )));
            }
        }

        {
            let mut stats = self.stats.write();
            stats.chunks_retrieved += 1;
            stats.bytes_retrieved += content.len() as u64;
        }

        debug!(
            "Retrieved chunk {} ({} bytes)",
            hex::encode(address),
            content.len()
        );

        Ok(Some(content))
    }

    /// Check if a chunk exists.
    ///
    /// # Errors
    ///
    /// Returns an error if the filesystem check fails.
    pub async fn exists(&self, address: &XorName) -> Result<bool> {
        let chunk_path = self.chunk_path(address);
        fs::try_exists(&chunk_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to check chunk existence: {e}")))
    }

    /// Delete a chunk.
    ///
    /// # Errors
    ///
    /// Returns an error if deletion fails.
    pub async fn delete(&self, address: &XorName) -> Result<bool> {
        let chunk_path = self.chunk_path(address);

        let file_exists = fs::try_exists(&chunk_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to check chunk existence: {e}")))?;
        if !file_exists {
            return Ok(false);
        }

        fs::remove_file(&chunk_path)
            .await
            .map_err(|e| Error::Storage(format!("Failed to delete chunk: {e}")))?;

        debug!("Deleted chunk {}", hex::encode(address));

        Ok(true)
    }

    /// Get storage statistics.
    #[must_use]
    pub fn stats(&self) -> StorageStats {
        self.stats.read().clone()
    }

    /// Get the path for a chunk.
    fn chunk_path(&self, address: &XorName) -> PathBuf {
        // Two-level sharding using first two bytes
        let shard1 = format!("{:02x}", address[0]);
        let shard2 = format!("{:02x}", address[1]);
        let filename = format!("{}.chunk", hex::encode(address));

        self.config
            .root_dir
            .join("chunks")
            .join(shard1)
            .join(shard2)
            .join(filename)
    }

    /// Compute content address (SHA256 hash).
    #[must_use]
    pub fn compute_address(content: &[u8]) -> XorName {
        crate::client::compute_address(content)
    }

    /// Get the root directory.
    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.config.root_dir
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_storage() -> (DiskStorage, TempDir) {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = DiskStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 0,
        };
        let storage = DiskStorage::new(config).await.expect("create storage");
        (storage, temp_dir)
    }

    #[tokio::test]
    async fn test_put_and_get() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"hello world";
        let address = DiskStorage::compute_address(content);

        // Store chunk
        let is_new = storage.put(&address, content).await.expect("put");
        assert!(is_new);

        // Retrieve chunk
        let retrieved = storage.get(&address).await.expect("get");
        assert_eq!(retrieved, Some(content.to_vec()));
    }

    #[tokio::test]
    async fn test_put_duplicate() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"test data";
        let address = DiskStorage::compute_address(content);

        // First store
        let is_new1 = storage.put(&address, content).await.expect("put 1");
        assert!(is_new1);

        // Duplicate store
        let is_new2 = storage.put(&address, content).await.expect("put 2");
        assert!(!is_new2);

        // Check stats
        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 1);
        assert_eq!(stats.duplicates, 1);
    }

    #[tokio::test]
    async fn test_get_not_found() {
        let (storage, _temp) = create_test_storage().await;

        let address = [0xAB; 32];
        let result = storage.get(&address).await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_exists() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"exists test";
        let address = DiskStorage::compute_address(content);

        assert!(!storage.exists(&address).await.expect("exists"));

        storage.put(&address, content).await.expect("put");

        assert!(storage.exists(&address).await.expect("exists"));
    }

    #[tokio::test]
    async fn test_delete() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"delete test";
        let address = DiskStorage::compute_address(content);

        // Store
        storage.put(&address, content).await.expect("put");
        assert!(storage.exists(&address).await.expect("exists"));

        // Delete
        let deleted = storage.delete(&address).await.expect("delete");
        assert!(deleted);
        assert!(!storage.exists(&address).await.expect("exists"));

        // Delete again (already deleted)
        let deleted2 = storage.delete(&address).await.expect("delete 2");
        assert!(!deleted2);
    }

    #[tokio::test]
    async fn test_max_chunks_enforced() {
        let temp_dir = TempDir::new().expect("create temp dir");
        let config = DiskStorageConfig {
            root_dir: temp_dir.path().to_path_buf(),
            verify_on_read: true,
            max_chunks: 2,
        };
        let storage = DiskStorage::new(config).await.expect("create storage");

        let content1 = b"chunk one";
        let content2 = b"chunk two";
        let content3 = b"chunk three";
        let addr1 = DiskStorage::compute_address(content1);
        let addr2 = DiskStorage::compute_address(content2);
        let addr3 = DiskStorage::compute_address(content3);

        // First two should succeed
        assert!(storage.put(&addr1, content1).await.is_ok());
        assert!(storage.put(&addr2, content2).await.is_ok());

        // Third should be rejected
        let result = storage.put(&addr3, content3).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("capacity reached"));
    }

    #[tokio::test]
    async fn test_address_mismatch() {
        let (storage, _temp) = create_test_storage().await;

        let content = b"some content";
        let wrong_address = [0xFF; 32]; // Wrong address

        let result = storage.put(&wrong_address, content).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("mismatch"));
    }

    #[tokio::test]
    async fn test_chunk_path_sharding() {
        let (storage, _temp) = create_test_storage().await;

        // Address starting with 0xAB, 0xCD...
        let mut address = [0u8; 32];
        address[0] = 0xAB;
        address[1] = 0xCD;

        let path = storage.chunk_path(&address);
        let path_str = path.to_string_lossy();

        // Should contain sharded directories
        assert!(path_str.contains("ab"));
        assert!(path_str.contains("cd"));
        assert!(path_str.ends_with(".chunk"));
    }

    #[test]
    fn test_compute_address() {
        // Known SHA256 hash of "hello world"
        let content = b"hello world";
        let address = DiskStorage::compute_address(content);

        let expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        assert_eq!(hex::encode(address), expected_hex);
    }

    #[tokio::test]
    async fn test_stats() {
        let (storage, _temp) = create_test_storage().await;

        let content1 = b"content 1";
        let content2 = b"content 2";
        let address1 = DiskStorage::compute_address(content1);
        let address2 = DiskStorage::compute_address(content2);

        // Store two chunks
        storage.put(&address1, content1).await.expect("put 1");
        storage.put(&address2, content2).await.expect("put 2");

        // Retrieve one
        storage.get(&address1).await.expect("get");

        let stats = storage.stats();
        assert_eq!(stats.chunks_stored, 2);
        assert_eq!(stats.chunks_retrieved, 1);
        assert_eq!(
            stats.bytes_stored,
            content1.len() as u64 + content2.len() as u64
        );
        assert_eq!(stats.bytes_retrieved, content1.len() as u64);
    }
}
