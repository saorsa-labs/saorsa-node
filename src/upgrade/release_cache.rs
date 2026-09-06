//! Disk cache for GitHub release metadata.
//!
//! When multiple ant-node instances run on the same machine, each would
//! otherwise poll the GitHub API independently.  `ReleaseCache` stores the
//! most recent API response on disk with a configurable TTL so that only the
//! first node to hit a stale cache actually contacts GitHub.

use crate::error::{Error, Result};
use crate::logging::debug;
use crate::upgrade::monitor::{Asset, GitHubRelease};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// On-disk cache for GitHub release metadata.
#[derive(Clone)]
pub struct ReleaseCache {
    /// Directory that holds the cache file and its lock.
    cache_dir: PathBuf,
    /// How long a cached response is considered fresh.
    ttl: Duration,
}

/// Serialized container written to disk.
#[derive(Serialize, Deserialize)]
struct CachedReleases {
    /// The GitHub repo these releases belong to (e.g. "owner/repo").
    repo: String,
    /// When the releases were fetched (seconds since UNIX epoch).
    fetched_at_epoch_secs: u64,
    /// The cached release objects.
    releases: Vec<CachedRelease>,
}

/// Serialized mirror of [`GitHubRelease`].
#[derive(Serialize, Deserialize)]
struct CachedRelease {
    tag_name: String,
    name: String,
    body: String,
    prerelease: bool,
    assets: Vec<CachedAsset>,
}

/// Serialized mirror of [`Asset`].
#[derive(Serialize, Deserialize)]
struct CachedAsset {
    name: String,
    browser_download_url: String,
}

// ---------------------------------------------------------------------------
// Conversions
// ---------------------------------------------------------------------------

impl From<&GitHubRelease> for CachedRelease {
    fn from(r: &GitHubRelease) -> Self {
        Self {
            tag_name: r.tag_name.clone(),
            name: r.name.clone(),
            body: r.body.clone(),
            prerelease: r.prerelease,
            assets: r.assets.iter().map(CachedAsset::from).collect(),
        }
    }
}

impl From<CachedRelease> for GitHubRelease {
    fn from(c: CachedRelease) -> Self {
        Self {
            tag_name: c.tag_name,
            name: c.name,
            body: c.body,
            prerelease: c.prerelease,
            assets: c.assets.into_iter().map(Asset::from).collect(),
        }
    }
}

impl From<&Asset> for CachedAsset {
    fn from(a: &Asset) -> Self {
        Self {
            name: a.name.clone(),
            browser_download_url: a.browser_download_url.clone(),
        }
    }
}

impl From<CachedAsset> for Asset {
    fn from(c: CachedAsset) -> Self {
        Self {
            name: c.name,
            browser_download_url: c.browser_download_url,
        }
    }
}

// ---------------------------------------------------------------------------
// ReleaseCache implementation
// ---------------------------------------------------------------------------

impl ReleaseCache {
    /// Create a new release cache backed by the given directory.
    #[must_use]
    pub fn new(cache_dir: PathBuf, ttl: Duration) -> Self {
        Self { cache_dir, ttl }
    }

    /// Return the cached releases if the cache file exists, belongs to the
    /// same repo, and has not expired.  Returns `None` on any error (missing,
    /// corrupted, expired, wrong repo) — callers should fall back to the
    /// network in that case.
    #[must_use]
    pub fn read_if_valid(&self, repo: &str) -> Option<Vec<GitHubRelease>> {
        let data = fs::read_to_string(self.cache_file()).ok()?;
        let cached: CachedReleases = serde_json::from_str(&data).ok()?;

        if cached.repo != repo {
            debug!(
                "Release cache repo mismatch: cached={}, wanted={}",
                cached.repo, repo
            );
            return None;
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs();
        let age_secs = now.saturating_sub(cached.fetched_at_epoch_secs);
        if age_secs >= self.ttl.as_secs() {
            debug!(
                "Release cache expired (age={}s, ttl={}s)",
                age_secs,
                self.ttl.as_secs()
            );
            return None;
        }

        Some(
            cached
                .releases
                .into_iter()
                .map(GitHubRelease::from)
                .collect(),
        )
    }

    /// Acquire the exclusive cache lock, re-check the cache, and return
    /// valid cached releases if another node populated them while we waited.
    ///
    /// Returns `Ok(Some(releases))` if a valid cache was found under the
    /// lock, or `Ok(None)` if the cache is still stale/missing and the
    /// caller should fetch from the network.  The returned
    /// The returned lock guard must be held until after writing the fresh
    /// data so that other nodes block rather than all hitting the API.
    ///
    /// **Note:** `lock_exclusive()` blocks the calling thread.  Callers in
    /// async contexts should wrap this in `tokio::task::spawn_blocking`.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock file cannot be created or acquired.
    pub fn lock_and_recheck(
        &self,
        repo: &str,
    ) -> Result<(ReleaseCacheLockGuard, Option<Vec<GitHubRelease>>)> {
        let lock_path = self.lock_file();
        let lock = File::create(&lock_path)
            .map_err(|e| Error::Upgrade(format!("Failed to create release cache lock: {e}")))?;
        lock.lock_exclusive()
            .map_err(|e| Error::Upgrade(format!("Failed to acquire release cache lock: {e}")))?;

        let cached = self.read_if_valid(repo);
        Ok((ReleaseCacheLockGuard { _file: lock }, cached))
    }

    /// Write releases to the cache, using an exclusive file lock to
    /// coordinate with other nodes on the same machine.
    ///
    /// The write is atomic: data goes to a temp file first, then is renamed
    /// over the cache file.
    ///
    /// # Errors
    ///
    /// Returns an error if the lock cannot be acquired or the file cannot be
    /// written.
    pub fn write(&self, repo: &str, releases: &[GitHubRelease]) -> Result<()> {
        let lock_path = self.lock_file();
        let lock = File::create(&lock_path)
            .map_err(|e| Error::Upgrade(format!("Failed to create release cache lock: {e}")))?;
        lock.lock_exclusive()
            .map_err(|e| Error::Upgrade(format!("Failed to acquire release cache lock: {e}")))?;

        let result = self.write_inner(repo, releases);

        drop(lock); // Dropping the file releases the exclusive lock
        result
    }

    /// Write releases to the cache while the caller already holds the
    /// lock guard.  The guard is consumed to ensure the lock is released
    /// after writing.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be written.
    pub fn write_under_lock(
        &self,
        _guard: ReleaseCacheLockGuard,
        repo: &str,
        releases: &[GitHubRelease],
    ) -> Result<()> {
        self.write_inner(repo, releases)
    }

    // -- private helpers -----------------------------------------------------

    fn write_inner(&self, repo: &str, releases: &[GitHubRelease]) -> Result<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| Error::Upgrade(format!("System clock error: {e}")))?
            .as_secs();

        let cached = CachedReleases {
            repo: repo.to_string(),
            fetched_at_epoch_secs: now,
            releases: releases.iter().map(CachedRelease::from).collect(),
        };

        let json = serde_json::to_string(&cached)
            .map_err(|e| Error::Upgrade(format!("Failed to serialize release cache: {e}")))?;

        // Write to temp file then rename into place.
        // Remove dest first on Windows where rename fails if it exists.
        let tmp_path = self.cache_dir.join("releases.json.tmp");
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        let cache_file = self.cache_file();
        let _ = fs::remove_file(&cache_file);
        fs::rename(&tmp_path, &cache_file)?;

        debug!("Wrote release cache ({} releases)", releases.len());
        Ok(())
    }

    fn cache_file(&self) -> PathBuf {
        self.cache_dir.join("releases.json")
    }

    fn lock_file(&self) -> PathBuf {
        self.cache_dir.join("releases.lock")
    }
}

/// RAII guard that holds an exclusive release cache lock.
///
/// The underlying file lock is released when this guard is dropped.
pub struct ReleaseCacheLockGuard {
    _file: File,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn sample_releases() -> Vec<GitHubRelease> {
        vec![GitHubRelease {
            tag_name: "v1.2.0".to_string(),
            name: "Release 1.2.0".to_string(),
            body: "Notes".to_string(),
            prerelease: false,
            assets: vec![Asset {
                name: "ant-node-x86_64-linux.tar.gz".to_string(),
                browser_download_url: "https://example.com/bin".to_string(),
            }],
        }]
    }

    #[test]
    fn test_write_read_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let cache = ReleaseCache::new(tmp.path().to_path_buf(), Duration::from_mins(5));

        cache.write("owner/repo", &sample_releases()).unwrap();

        let loaded = cache.read_if_valid("owner/repo").unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].tag_name, "v1.2.0");
        assert_eq!(loaded[0].assets.len(), 1);
        assert_eq!(loaded[0].assets[0].name, "ant-node-x86_64-linux.tar.gz");
    }

    #[test]
    fn test_ttl_expiry_returns_none() {
        let tmp = TempDir::new().unwrap();
        // TTL of 0 seconds — anything written is immediately expired
        let cache = ReleaseCache::new(tmp.path().to_path_buf(), Duration::from_secs(0));

        cache.write("owner/repo", &sample_releases()).unwrap();

        assert!(cache.read_if_valid("owner/repo").is_none());
    }

    #[test]
    fn test_wrong_repo_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = ReleaseCache::new(tmp.path().to_path_buf(), Duration::from_mins(5));

        cache.write("owner/repo", &sample_releases()).unwrap();

        assert!(cache.read_if_valid("other/repo").is_none());
    }

    #[test]
    fn test_corrupted_file_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = ReleaseCache::new(tmp.path().to_path_buf(), Duration::from_mins(5));

        fs::write(cache.cache_file(), "not valid json!!!").unwrap();

        assert!(cache.read_if_valid("owner/repo").is_none());
    }

    #[test]
    fn test_missing_file_returns_none() {
        let tmp = TempDir::new().unwrap();
        let cache = ReleaseCache::new(tmp.path().to_path_buf(), Duration::from_mins(5));

        assert!(cache.read_if_valid("owner/repo").is_none());
    }
}
