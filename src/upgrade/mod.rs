//! Auto-upgrade system with ML-DSA signature verification.
//!
//! This module handles:
//! - Polling GitHub releases for new versions
//! - Verifying ML-DSA-65 signatures on binaries
//! - Replacing the running binary with rollback support
//! - Staged rollout to prevent mass network restarts
//! - Auto-apply: download, extract, verify, replace, restart

mod apply;
mod monitor;
mod rollout;
mod signature;

pub use apply::AutoApplyUpgrader;
pub use monitor::{find_platform_asset, version_from_tag, Asset, GitHubRelease, UpgradeMonitor};
pub use rollout::StagedRollout;
pub use signature::{
    verify_binary_signature, verify_binary_signature_with_key, verify_from_file,
    verify_from_file_with_key, PUBLIC_KEY_SIZE, SIGNATURE_SIZE, SIGNING_CONTEXT,
};

use crate::error::{Error, Result};
use semver::Version;
use std::fs;
use std::path::Path;
use tracing::{debug, info, warn};

/// Maximum allowed upgrade binary size (200 MiB).
///
/// This is a sanity limit to prevent memory exhaustion during ML-DSA verification,
/// which requires loading the full binary into RAM.
const MAX_BINARY_SIZE_BYTES: usize = 200 * 1024 * 1024;

/// Information about an available upgrade.
#[derive(Debug, Clone)]
pub struct UpgradeInfo {
    /// The new version.
    pub version: Version,
    /// Download URL for the binary.
    pub download_url: String,
    /// Signature URL.
    pub signature_url: String,
    /// Release notes.
    pub release_notes: String,
}

/// Result of an upgrade operation.
#[derive(Debug)]
pub enum UpgradeResult {
    /// Upgrade was successful.
    Success {
        /// The new version.
        version: Version,
    },
    /// Upgrade failed, rolled back.
    RolledBack {
        /// Error that caused the rollback.
        reason: String,
    },
    /// No upgrade available.
    NoUpgrade,
}

/// Upgrade orchestrator with rollback support.
///
/// Handles the complete upgrade lifecycle:
/// 1. Validate upgrade (prevent downgrade)
/// 2. Download new binary and signature
/// 3. Verify ML-DSA-65 signature
/// 4. Create backup of current binary
/// 5. Atomic replacement
/// 6. Rollback on failure
pub struct Upgrader {
    /// Current running version.
    current_version: Version,
    /// HTTP client for downloads.
    client: reqwest::Client,
}

impl Upgrader {
    /// Create a new upgrader with the current package version.
    #[must_use]
    pub fn new() -> Self {
        let current_version =
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| Version::new(0, 0, 0));

        Self {
            current_version,
            client: reqwest::Client::new(),
        }
    }

    /// Create an upgrader with a custom version (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_version(version: Version) -> Self {
        Self {
            current_version: version,
            client: reqwest::Client::new(),
        }
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// Validate that the upgrade is allowed (prevents downgrade).
    ///
    /// # Errors
    ///
    /// Returns an error if the target version is older than or equal to current.
    pub fn validate_upgrade(&self, info: &UpgradeInfo) -> Result<()> {
        if info.version <= self.current_version {
            return Err(Error::Upgrade(format!(
                "Cannot downgrade from {} to {}",
                self.current_version, info.version
            )));
        }
        Ok(())
    }

    /// Create a backup of the current binary.
    ///
    /// # Arguments
    ///
    /// * `current` - Path to the current binary
    /// * `rollback_dir` - Directory to store the backup
    ///
    /// # Errors
    ///
    /// Returns an error if the backup cannot be created.
    pub fn create_backup(&self, current: &Path, rollback_dir: &Path) -> Result<()> {
        let filename = current
            .file_name()
            .ok_or_else(|| Error::Upgrade("Invalid binary path".to_string()))?;

        let backup_path = rollback_dir.join(format!("{}.backup", filename.to_string_lossy()));

        debug!("Creating backup at: {}", backup_path.display());
        fs::copy(current, &backup_path)?;
        Ok(())
    }

    /// Restore binary from backup.
    ///
    /// # Arguments
    ///
    /// * `current` - Path to restore to
    /// * `rollback_dir` - Directory containing the backup
    ///
    /// # Errors
    ///
    /// Returns an error if the backup cannot be restored.
    pub fn restore_from_backup(&self, current: &Path, rollback_dir: &Path) -> Result<()> {
        let filename = current
            .file_name()
            .ok_or_else(|| Error::Upgrade("Invalid binary path".to_string()))?;

        let backup_path = rollback_dir.join(format!("{}.backup", filename.to_string_lossy()));

        if !backup_path.exists() {
            return Err(Error::Upgrade("No backup found for rollback".to_string()));
        }

        info!("Restoring from backup: {}", backup_path.display());
        fs::copy(&backup_path, current)?;
        Ok(())
    }

    /// Atomically replace the binary (rename on POSIX).
    ///
    /// Preserves file permissions from the original binary.
    ///
    /// # Arguments
    ///
    /// * `new_binary` - Path to the new binary
    /// * `target` - Path to replace
    ///
    /// # Errors
    ///
    /// Returns an error if the replacement fails.
    pub fn atomic_replace(&self, new_binary: &Path, target: &Path) -> Result<()> {
        // Preserve original permissions on Unix
        #[cfg(unix)]
        {
            if let Ok(meta) = fs::metadata(target) {
                let perms = meta.permissions();
                fs::set_permissions(new_binary, perms)?;
            }
        }

        // Atomic rename
        fs::rename(new_binary, target)?;
        debug!("Atomic replacement complete");
        Ok(())
    }

    /// Download a file to the specified path.
    ///
    /// # Errors
    ///
    /// Returns an error if the download fails.
    async fn download(&self, url: &str, dest: &Path) -> Result<()> {
        debug!("Downloading: {}", url);

        let response = self
            .client
            .get(url)
            .send()
            .await
            .map_err(|e| Error::Network(format!("Download failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "Download returned status: {}",
                response.status()
            )));
        }

        let bytes = response
            .bytes()
            .await
            .map_err(|e| Error::Network(format!("Failed to read response: {e}")))?;

        Self::enforce_max_binary_size(bytes.len())?;

        fs::write(dest, &bytes)?;
        debug!("Downloaded {} bytes to {}", bytes.len(), dest.display());
        Ok(())
    }

    /// Ensure the downloaded binary is within a sane size limit.
    fn enforce_max_binary_size(len: usize) -> Result<()> {
        if len > MAX_BINARY_SIZE_BYTES {
            return Err(Error::Upgrade(format!(
                "Downloaded binary too large: {len} bytes (max {MAX_BINARY_SIZE_BYTES})"
            )));
        }
        Ok(())
    }

    /// Create a temp directory for upgrades in the same directory as the target binary.
    ///
    /// Ensures `fs::rename` is atomic by keeping source/target on the same filesystem.
    fn create_tempdir_in_target_dir(current_binary: &Path) -> Result<tempfile::TempDir> {
        let target_dir = current_binary
            .parent()
            .ok_or_else(|| Error::Upgrade("Current binary has no parent directory".to_string()))?;

        tempfile::Builder::new()
            .prefix("saorsa-upgrade-")
            .tempdir_in(target_dir)
            .map_err(|e| Error::Upgrade(format!("Failed to create temp dir: {e}")))
    }

    /// Perform upgrade with rollback support.
    ///
    /// This is the main upgrade entry point. It:
    /// 1. Validates the upgrade (prevents downgrade)
    /// 2. Creates a backup of the current binary
    /// 3. Downloads the new binary and signature
    /// 4. Verifies the ML-DSA-65 signature
    /// 5. Atomically replaces the binary
    /// 6. Rolls back on any failure
    ///
    /// # Arguments
    ///
    /// * `info` - Information about the upgrade to perform
    /// * `current_binary` - Path to the currently running binary
    /// * `rollback_dir` - Directory to store backup for rollback
    ///
    /// # Errors
    ///
    /// Returns an error only if both the upgrade AND rollback fail (critical).
    pub async fn perform_upgrade(
        &self,
        info: &UpgradeInfo,
        current_binary: &Path,
        rollback_dir: &Path,
    ) -> Result<UpgradeResult> {
        // Auto-upgrade on Windows is not supported yet due to running-binary locks.
        // We fail closed with an explicit reason rather than attempting a broken replace.
        if !Self::auto_upgrade_supported() {
            warn!(
                "Auto-upgrade is not supported on this platform; refusing upgrade to {}",
                info.version
            );
            return Ok(UpgradeResult::RolledBack {
                reason: "Auto-upgrade not supported on this platform".to_string(),
            });
        }

        // 1. Validate upgrade
        self.validate_upgrade(info)?;

        // 2. Create backup
        self.create_backup(current_binary, rollback_dir)?;

        // 3. Download new binary and signature to temp directory
        let temp_dir = Self::create_tempdir_in_target_dir(current_binary)?;
        let new_binary = temp_dir.path().join("new_binary");
        let sig_path = temp_dir.path().join("signature");

        if let Err(e) = self.download(&info.download_url, &new_binary).await {
            warn!("Download failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Download failed: {e}"),
            });
        }

        if let Err(e) = self.download(&info.signature_url, &sig_path).await {
            warn!("Signature download failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Signature download failed: {e}"),
            });
        }

        // 4. Verify signature
        if let Err(e) = signature::verify_from_file(&new_binary, &sig_path) {
            warn!("Signature verification failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Signature verification failed: {e}"),
            });
        }

        // 5. Atomic replacement
        if let Err(e) = self.atomic_replace(&new_binary, current_binary) {
            warn!("Replacement failed, rolling back: {e}");
            if let Err(restore_err) = self.restore_from_backup(current_binary, rollback_dir) {
                return Err(Error::Upgrade(format!(
                    "Critical: replacement failed ({e}) AND rollback failed ({restore_err})"
                )));
            }
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Replacement failed: {e}"),
            });
        }

        info!("Successfully upgraded to version {}", info.version);
        Ok(UpgradeResult::Success {
            version: info.version.clone(),
        })
    }

    /// Whether the current platform supports in-place auto-upgrade.
    ///
    /// On Windows, replacing a running executable is typically blocked by file locks.
    const fn auto_upgrade_supported() -> bool {
        !cfg!(windows)
    }
}

impl Default for Upgrader {
    fn default() -> Self {
        Self::new()
    }
}

/// Legacy function for backward compatibility.
///
/// # Errors
///
/// Returns an error if the upgrade fails and rollback is not possible.
pub async fn perform_upgrade(
    info: &UpgradeInfo,
    current_binary: &Path,
    rollback_dir: &Path,
) -> Result<UpgradeResult> {
    Upgrader::new()
        .perform_upgrade(info, current_binary, rollback_dir)
        .await
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::doc_markdown,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::case_sensitive_file_extension_comparisons
)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    /// Test 1: Backup creation
    #[test]
    fn test_backup_created() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("current");
        let rollback_dir = temp.path().join("rollback");
        fs::create_dir(&rollback_dir).unwrap();

        let original_content = b"old binary content";
        fs::write(&current, original_content).unwrap();

        let upgrader = Upgrader::new();
        upgrader.create_backup(&current, &rollback_dir).unwrap();

        let backup_path = rollback_dir.join("current.backup");
        assert!(backup_path.exists(), "Backup file should exist");
        assert_eq!(
            fs::read(&backup_path).unwrap(),
            original_content,
            "Backup content should match"
        );
    }

    /// Test 2: Restore from backup
    #[test]
    fn test_restore_from_backup() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        let rollback_dir = temp.path().join("rollback");
        fs::create_dir(&rollback_dir).unwrap();

        let original = b"original content";
        fs::write(&current, original).unwrap();

        let upgrader = Upgrader::new();
        upgrader.create_backup(&current, &rollback_dir).unwrap();

        // Simulate corruption
        fs::write(&current, b"corrupted content").unwrap();

        // Restore
        upgrader
            .restore_from_backup(&current, &rollback_dir)
            .unwrap();

        assert_eq!(fs::read(&current).unwrap(), original);
    }

    /// Test 3: Atomic replacement
    #[test]
    fn test_atomic_replacement() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        let new_binary = temp.path().join("new_binary");

        fs::write(&current, b"old").unwrap();
        fs::write(&new_binary, b"new").unwrap();

        let upgrader = Upgrader::new();
        upgrader.atomic_replace(&new_binary, &current).unwrap();

        assert_eq!(fs::read(&current).unwrap(), b"new");
        assert!(!new_binary.exists(), "Source should be moved, not copied");
    }

    /// Test 4: Downgrade prevention
    #[test]
    fn test_downgrade_prevention() {
        let current_version = Version::new(1, 1, 0);
        let older_version = Version::new(1, 0, 0);

        let upgrader = Upgrader::with_version(current_version);

        let info = UpgradeInfo {
            version: older_version,
            download_url: "test".to_string(),
            signature_url: "test.sig".to_string(),
            release_notes: "Old".to_string(),
        };

        let result = upgrader.validate_upgrade(&info);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("downgrade") || err_msg.contains("Cannot"),
            "Error should mention downgrade prevention: {err_msg}"
        );
    }

    /// Test 5: Same version prevention
    #[test]
    fn test_same_version_prevention() {
        let version = Version::new(1, 0, 0);
        let upgrader = Upgrader::with_version(version.clone());

        let info = UpgradeInfo {
            version,
            download_url: "test".to_string(),
            signature_url: "test.sig".to_string(),
            release_notes: "Same".to_string(),
        };

        let result = upgrader.validate_upgrade(&info);
        assert!(result.is_err(), "Same version should be rejected");
    }

    /// Test 6: Upgrade validation passes for newer version
    #[test]
    fn test_upgrade_validation_passes() {
        let upgrader = Upgrader::with_version(Version::new(1, 0, 0));

        let info = UpgradeInfo {
            version: Version::new(1, 1, 0),
            download_url: "test".to_string(),
            signature_url: "test.sig".to_string(),
            release_notes: "New".to_string(),
        };

        let result = upgrader.validate_upgrade(&info);
        assert!(result.is_ok(), "Newer version should be accepted");
    }

    /// Test 7: Restore fails without backup
    #[test]
    fn test_restore_fails_without_backup() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        let rollback_dir = temp.path().join("rollback");
        fs::create_dir(&rollback_dir).unwrap();

        fs::write(&current, b"content").unwrap();

        let upgrader = Upgrader::new();
        let result = upgrader.restore_from_backup(&current, &rollback_dir);

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("No backup"));
    }

    /// Test 8: Permissions preserved on Unix
    #[cfg(unix)]
    #[test]
    fn test_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        let new_binary = temp.path().join("new");

        fs::write(&current, b"old").unwrap();
        fs::write(&new_binary, b"new").unwrap();

        // Set executable permissions on original
        let mut perms = fs::metadata(&current).unwrap().permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&current, perms).unwrap();

        let upgrader = Upgrader::new();
        upgrader.atomic_replace(&new_binary, &current).unwrap();

        let new_perms = fs::metadata(&current).unwrap().permissions();
        assert_eq!(
            new_perms.mode() & 0o777,
            0o755,
            "Permissions should be preserved"
        );
    }

    /// Test 9: Current version getter
    #[test]
    fn test_current_version_getter() {
        let version = Version::new(2, 3, 4);
        let upgrader = Upgrader::with_version(version.clone());
        assert_eq!(*upgrader.current_version(), version);
    }

    /// Test 10: Default implementation
    #[test]
    fn test_default_impl() {
        let upgrader = Upgrader::default();
        // Should not panic and should have a valid version
        assert!(!upgrader.current_version().to_string().is_empty());
    }

    /// Test 11: Backup with special characters in filename
    #[test]
    fn test_backup_special_filename() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("saorsa-node-v1.0.0");
        let rollback_dir = temp.path().join("rollback");
        fs::create_dir(&rollback_dir).unwrap();

        fs::write(&current, b"content").unwrap();

        let upgrader = Upgrader::new();
        let result = upgrader.create_backup(&current, &rollback_dir);
        assert!(result.is_ok());

        let backup_path = rollback_dir.join("saorsa-node-v1.0.0.backup");
        assert!(backup_path.exists());
    }

    /// Test 12: UpgradeInfo construction
    #[test]
    fn test_upgrade_info() {
        let info = UpgradeInfo {
            version: Version::new(1, 2, 3),
            download_url: "https://example.com/binary".to_string(),
            signature_url: "https://example.com/binary.sig".to_string(),
            release_notes: "Bug fixes and improvements".to_string(),
        };

        assert_eq!(info.version, Version::new(1, 2, 3));
        assert!(info.download_url.contains("example.com"));
        assert!(info.signature_url.ends_with(".sig"));
    }

    /// Test 13: UpgradeResult variants
    #[test]
    fn test_upgrade_result_variants() {
        let success = UpgradeResult::Success {
            version: Version::new(1, 0, 0),
        };
        assert!(matches!(success, UpgradeResult::Success { .. }));

        let rolled_back = UpgradeResult::RolledBack {
            reason: "Test failure".to_string(),
        };
        assert!(matches!(rolled_back, UpgradeResult::RolledBack { .. }));

        let no_upgrade = UpgradeResult::NoUpgrade;
        assert!(matches!(no_upgrade, UpgradeResult::NoUpgrade));
    }

    /// Test 14: Large file backup
    #[test]
    fn test_large_file_backup() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("large_binary");
        let rollback_dir = temp.path().join("rollback");
        fs::create_dir(&rollback_dir).unwrap();

        // Create 1MB file
        let large_content: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        fs::write(&current, &large_content).unwrap();

        let upgrader = Upgrader::new();
        upgrader.create_backup(&current, &rollback_dir).unwrap();

        let backup_path = rollback_dir.join("large_binary.backup");
        assert_eq!(fs::read(&backup_path).unwrap(), large_content);
    }

    /// Test 15: Backup directory doesn't exist
    #[test]
    fn test_backup_nonexistent_rollback_dir() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        let rollback_dir = temp.path().join("nonexistent");

        fs::write(&current, b"content").unwrap();

        let upgrader = Upgrader::new();
        let result = upgrader.create_backup(&current, &rollback_dir);

        assert!(result.is_err(), "Should fail if rollback dir doesn't exist");
    }

    /// Test 16: Tempdir for upgrades is created in target directory.
    #[test]
    fn test_tempdir_in_target_dir() {
        let temp = TempDir::new().unwrap();
        let current = temp.path().join("binary");
        fs::write(&current, b"content").unwrap();

        let tempdir = Upgrader::create_tempdir_in_target_dir(&current).unwrap();

        assert_eq!(
            tempdir.path().parent().unwrap(),
            temp.path(),
            "Upgrade tempdir should be in same dir as target"
        );
    }

    /// Test 17: Enforce max binary size rejects huge downloads.
    #[test]
    fn test_enforce_max_binary_size_rejects_large() {
        let too_large = MAX_BINARY_SIZE_BYTES + 1;
        let result = Upgrader::enforce_max_binary_size(too_large);
        assert!(result.is_err());
    }

    /// Test 18: Enforce max binary size accepts reasonable downloads.
    #[test]
    fn test_enforce_max_binary_size_accepts_small() {
        let result = Upgrader::enforce_max_binary_size(1024);
        assert!(result.is_ok());
    }

    #[test]
    fn test_auto_upgrade_supported_flag_matches_platform() {
        if cfg!(windows) {
            assert!(!Upgrader::auto_upgrade_supported());
        } else {
            assert!(Upgrader::auto_upgrade_supported());
        }
    }
}
