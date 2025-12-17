//! Auto-apply upgrade functionality.
//!
//! This module handles the complete auto-upgrade workflow:
//! 1. Download archive from GitHub releases
//! 2. Extract the binary from tar.gz/zip
//! 3. Verify ML-DSA signature
//! 4. Replace running binary with backup
//! 5. Restart the node process

use crate::error::{Error, Result};
use crate::upgrade::{signature, UpgradeInfo, UpgradeResult};
use flate2::read::GzDecoder;
use semver::Version;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, error, info, warn};

/// Maximum allowed upgrade archive size (200 MiB).
const MAX_ARCHIVE_SIZE_BYTES: usize = 200 * 1024 * 1024;

/// Auto-apply upgrader with archive support.
pub struct AutoApplyUpgrader {
    /// Current running version.
    current_version: Version,
    /// HTTP client for downloads.
    client: reqwest::Client,
}

impl AutoApplyUpgrader {
    /// Create a new auto-apply upgrader.
    #[must_use]
    pub fn new() -> Self {
        let current_version =
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| Version::new(0, 0, 0));

        Self {
            current_version,
            client: reqwest::Client::builder()
                .user_agent(concat!("saorsa-node/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(300))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// Get the path to the currently running binary.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary path cannot be determined.
    pub fn current_binary_path() -> Result<PathBuf> {
        env::current_exe().map_err(|e| Error::Upgrade(format!("Cannot determine binary path: {e}")))
    }

    /// Perform the complete auto-apply upgrade workflow.
    ///
    /// # Arguments
    ///
    /// * `info` - Upgrade information from the monitor
    ///
    /// # Returns
    ///
    /// Returns `UpgradeResult::Success` and triggers a restart on success.
    /// Returns `UpgradeResult::RolledBack` if any step fails.
    ///
    /// # Errors
    ///
    /// Returns an error only for critical failures where rollback also fails.
    pub async fn apply_upgrade(&self, info: &UpgradeInfo) -> Result<UpgradeResult> {
        info!(
            "Starting auto-apply upgrade from {} to {}",
            self.current_version, info.version
        );

        // Validate upgrade (prevent downgrade)
        if info.version <= self.current_version {
            warn!(
                "Ignoring downgrade attempt: {} -> {}",
                self.current_version, info.version
            );
            return Ok(UpgradeResult::NoUpgrade);
        }

        // Get current binary path
        let current_binary = Self::current_binary_path()?;
        let binary_dir = current_binary
            .parent()
            .ok_or_else(|| Error::Upgrade("Cannot determine binary directory".to_string()))?;

        // Create temp directory for upgrade
        let temp_dir = tempfile::Builder::new()
            .prefix("saorsa-upgrade-")
            .tempdir_in(binary_dir)
            .map_err(|e| Error::Upgrade(format!("Failed to create temp dir: {e}")))?;

        let archive_path = temp_dir.path().join("archive");
        let sig_path = temp_dir.path().join("signature");

        // Step 1: Download archive
        info!("Downloading upgrade archive...");
        if let Err(e) = self.download(&info.download_url, &archive_path).await {
            warn!("Archive download failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Download failed: {e}"),
            });
        }

        // Step 2: Download signature
        info!("Downloading signature...");
        if let Err(e) = self.download(&info.signature_url, &sig_path).await {
            warn!("Signature download failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Signature download failed: {e}"),
            });
        }

        // Step 3: Extract binary from archive
        info!("Extracting binary from archive...");
        let extracted_binary = match self.extract_binary(&archive_path, temp_dir.path()) {
            Ok(path) => path,
            Err(e) => {
                warn!("Extraction failed: {e}");
                return Ok(UpgradeResult::RolledBack {
                    reason: format!("Extraction failed: {e}"),
                });
            }
        };

        // Step 4: Verify signature on extracted binary
        info!("Verifying ML-DSA signature...");
        if let Err(e) = signature::verify_from_file(&extracted_binary, &sig_path) {
            warn!("Signature verification failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Signature verification failed: {e}"),
            });
        }

        // Step 5: Create backup of current binary
        let backup_path = binary_dir.join(format!(
            "{}.backup",
            current_binary
                .file_name()
                .map(|s| s.to_string_lossy())
                .unwrap_or_else(|| "saorsa-node".into())
        ));
        info!("Creating backup at {}...", backup_path.display());
        if let Err(e) = fs::copy(&current_binary, &backup_path) {
            warn!("Backup creation failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Backup failed: {e}"),
            });
        }

        // Step 6: Replace binary
        info!("Replacing binary...");
        if let Err(e) = self.replace_binary(&extracted_binary, &current_binary) {
            warn!("Binary replacement failed: {e}");
            // Attempt rollback
            if let Err(restore_err) = fs::copy(&backup_path, &current_binary) {
                error!(
                    "CRITICAL: Replacement failed ({e}) AND rollback failed ({restore_err})"
                );
                return Err(Error::Upgrade(format!(
                    "Critical: replacement failed ({e}) AND rollback failed ({restore_err})"
                )));
            }
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Replacement failed: {e}"),
            });
        }

        info!(
            "Successfully upgraded to version {}! Restarting...",
            info.version
        );

        // Step 7: Trigger restart
        self.trigger_restart(&current_binary)?;

        Ok(UpgradeResult::Success {
            version: info.version.clone(),
        })
    }

    /// Download a file to the specified path.
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

        if bytes.len() > MAX_ARCHIVE_SIZE_BYTES {
            return Err(Error::Upgrade(format!(
                "Downloaded file too large: {} bytes (max {})",
                bytes.len(),
                MAX_ARCHIVE_SIZE_BYTES
            )));
        }

        fs::write(dest, &bytes)?;
        debug!("Downloaded {} bytes to {}", bytes.len(), dest.display());
        Ok(())
    }

    /// Extract the saorsa-node binary from a tar.gz archive.
    fn extract_binary(&self, archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
        let file = File::open(archive_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let extracted_binary = dest_dir.join("saorsa-node");

        for entry in archive
            .entries()
            .map_err(|e| Error::Upgrade(format!("Failed to read archive: {e}")))?
        {
            let mut entry =
                entry.map_err(|e| Error::Upgrade(format!("Failed to read entry: {e}")))?;
            let path = entry
                .path()
                .map_err(|e| Error::Upgrade(format!("Invalid path in archive: {e}")))?;

            // Look for the saorsa-node binary
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str == "saorsa-node" || name_str == "saorsa-node.exe" {
                    debug!("Found binary in archive: {}", path.display());

                    // Read and write the binary
                    let mut contents = Vec::new();
                    entry
                        .read_to_end(&mut contents)
                        .map_err(|e| Error::Upgrade(format!("Failed to read binary: {e}")))?;

                    fs::write(&extracted_binary, &contents)?;

                    // Make executable on Unix
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = fs::metadata(&extracted_binary)?.permissions();
                        perms.set_mode(0o755);
                        fs::set_permissions(&extracted_binary, perms)?;
                    }

                    return Ok(extracted_binary);
                }
            }
        }

        Err(Error::Upgrade(
            "saorsa-node binary not found in archive".to_string(),
        ))
    }

    /// Replace the current binary with the new one.
    fn replace_binary(&self, new_binary: &Path, target: &Path) -> Result<()> {
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
        debug!("Binary replacement complete");
        Ok(())
    }

    /// Trigger a restart of the node process.
    ///
    /// On Unix, uses exec() to replace the current process.
    /// The calling code should ensure graceful shutdown before calling this.
    fn trigger_restart(&self, binary_path: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;

            // Collect current args (skip the binary name)
            let args: Vec<String> = env::args().skip(1).collect();

            info!(
                "Executing restart: {} {:?}",
                binary_path.display(),
                args
            );

            // exec() replaces the current process
            let err = std::process::Command::new(binary_path).args(&args).exec();

            // If we get here, exec failed
            Err(Error::Upgrade(format!("Failed to exec new binary: {err}")))
        }

        #[cfg(not(unix))]
        {
            // On Windows, we can't replace a running binary
            // Just log and let the user restart manually
            warn!(
                "Auto-restart not supported on this platform. Please restart manually."
            );
            Ok(())
        }
    }
}

impl Default for AutoApplyUpgrader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_apply_upgrader_creation() {
        let upgrader = AutoApplyUpgrader::new();
        assert!(!upgrader.current_version().to_string().is_empty());
    }

    #[test]
    fn test_current_binary_path() {
        let result = AutoApplyUpgrader::current_binary_path();
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.exists() || path.to_string_lossy().contains("test"));
    }

    #[test]
    fn test_default_impl() {
        let upgrader = AutoApplyUpgrader::default();
        assert!(!upgrader.current_version().to_string().is_empty());
    }
}
