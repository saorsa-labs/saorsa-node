//! Auto-apply upgrade functionality.
//!
//! This module handles the complete auto-upgrade workflow:
//! 1. Download archive from GitHub releases
//! 2. Extract the binary from tar.gz/zip
//! 3. Verify ML-DSA signature
//! 4. Replace running binary with backup
//! 5. Restart the node process

use crate::error::{Error, Result};
use crate::logging::{debug, error, info, warn};
use crate::upgrade::binary_cache::BinaryCache;
use crate::upgrade::{signature, UpgradeInfo, UpgradeResult};
use flate2::read::GzDecoder;
use semver::Version;
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use tar::Archive;

/// Maximum allowed upgrade archive size (200 MiB).
pub(super) const MAX_ARCHIVE_SIZE_BYTES: usize = 200 * 1024 * 1024;

/// Exit code that signals the service manager to restart the process.
///
/// On Windows, `trigger_restart` exits with this code instead of using
/// `exec()`.  The wrapping service (e.g. NSSM or Windows Service) should be
/// configured to restart on this exit code.
pub const RESTART_EXIT_CODE: i32 = 100;

/// Auto-apply upgrader with archive support.
pub struct AutoApplyUpgrader {
    /// Current running version.
    current_version: Version,
    /// HTTP client for downloads.
    client: reqwest::Client,
    /// Shared binary cache (optional).
    binary_cache: Option<BinaryCache>,
    /// When true, exit cleanly for service manager restart instead of spawning.
    stop_on_upgrade: bool,
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
                .user_agent(concat!("ant-node/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_mins(5))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            binary_cache: None,
            stop_on_upgrade: false,
        }
    }

    /// Configure a shared binary cache for downloaded upgrades.
    ///
    /// When set, `apply_upgrade` will check the cache before downloading
    /// and store freshly verified binaries so other nodes can reuse them.
    #[must_use]
    pub fn with_binary_cache(mut self, cache: BinaryCache) -> Self {
        self.binary_cache = Some(cache);
        self
    }

    /// Configure the upgrader to exit cleanly instead of spawning a new process.
    ///
    /// When enabled, the node exits after applying an upgrade, relying on an
    /// external service manager (systemd, launchd, Windows Service) to restart it.
    #[must_use]
    pub fn with_stop_on_upgrade(mut self, stop: bool) -> Self {
        self.stop_on_upgrade = stop;
        self
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// Get the path to the currently running binary.
    ///
    /// On Linux, `/proc/self/exe` may have a `" (deleted)"` suffix when the on-disk binary has
    /// been replaced by another node's upgrade. This function strips that suffix so that backup
    /// creation, binary replacement, and restart all target the correct on-disk path.
    ///
    /// # Errors
    ///
    /// Returns an error if the binary path cannot be determined.
    pub fn current_binary_path() -> Result<PathBuf> {
        // Prefer the invoked path (argv[0]) if it exists, as it preserves symlinks.
        // Fall back to current_exe() which resolves symlinks via /proc/self/exe.
        let invoked_path = env::args().next().map(PathBuf::from);

        if let Some(ref invoked) = invoked_path {
            // Check for "(deleted)" suffix first — on Linux, /proc/self/exe
            // reports this when the on-disk binary has been replaced. The
            // `exists()` check below would return false for the suffixed path,
            // so we must strip it before testing existence.
            let path_str = invoked.to_string_lossy();
            let cleaned = if path_str.ends_with(" (deleted)") {
                let stripped = path_str.trim_end_matches(" (deleted)");
                debug!("Stripped '(deleted)' suffix from invoked path: {stripped}");
                PathBuf::from(stripped)
            } else {
                invoked.clone()
            };

            if cleaned.exists() {
                // Canonicalize to an absolute path so that trigger_restart
                // works even if the CWD has changed since startup.
                if let Ok(canonical) = cleaned.canonicalize() {
                    return Ok(canonical);
                }
                return Ok(cleaned);
            }
        }

        // Fall back to current_exe (resolves symlinks on Linux)
        let path = env::current_exe()
            .map_err(|e| Error::Upgrade(format!("Cannot determine binary path: {e}")))?;

        #[cfg(unix)]
        {
            let path_str = path.to_string_lossy();
            if path_str.ends_with(" (deleted)") {
                let cleaned = path_str.trim_end_matches(" (deleted)");
                debug!("Stripped '(deleted)' suffix from binary path: {cleaned}");
                return Ok(PathBuf::from(cleaned));
            }
        }

        Ok(path)
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

        // Create temp directory for upgrade.
        //
        // On Unix, create it with 0700 so a same-host attacker on a different
        // UID cannot read/write the staging area between when the cache
        // re-verifies the ML-DSA signature on a private copy and when
        // `extract_binary` reads it (closes a verify-vs-extract TOCTOU on
        // the staging directory). The `tempfile::Builder::permissions`
        // path is supported on tempfile 3 — on platforms that don't honour
        // it the call is a no-op and the ML-DSA verification on the
        // private copy still bounds the residual.
        let mut tempdir_builder = tempfile::Builder::new();
        tempdir_builder.prefix("ant-upgrade-");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            tempdir_builder.permissions(std::fs::Permissions::from_mode(0o700));
        }
        let temp_dir = tempdir_builder
            .tempdir_in(binary_dir)
            .map_err(|e| Error::Upgrade(format!("Failed to create temp dir: {e}")))?;

        let version_str = info.version.to_string();

        // Try the binary cache first; download/verify/extract errors are
        // recoverable and result in RolledBack rather than a hard error.
        let extracted_binary = match self
            .resolve_upgrade_binary(info, temp_dir.path(), &version_str)
            .await
        {
            Ok(path) => path,
            Err(e) => {
                warn!("Download/verify/extract failed: {e}");
                return Ok(UpgradeResult::RolledBack {
                    reason: format!("{e}"),
                });
            }
        };

        // Check if the on-disk binary has already been upgraded by a sibling service.
        // This prevents redundant backup/replace cycles when multiple nodes share one binary.
        if let Some(disk_version) = on_disk_version(&current_binary).await {
            if disk_version == info.version {
                info!(
                    "Binary already upgraded to {} by another service, skipping replacement",
                    info.version
                );
                let exit_code = self.prepare_restart(&current_binary)?;
                return Ok(UpgradeResult::Success {
                    version: info.version.clone(),
                    exit_code,
                });
            }
        }

        // Step 5: Create backup of current binary
        let backup_path = binary_dir.join(format!(
            "{}.backup",
            current_binary
                .file_name()
                .map_or_else(|| "ant-node".into(), |s| s.to_string_lossy())
        ));
        info!("Creating backup at {}...", backup_path.display());
        if let Err(e) = fs::copy(&current_binary, &backup_path) {
            warn!("Backup creation failed: {e}");
            return Ok(UpgradeResult::RolledBack {
                reason: format!("Backup failed: {e}"),
            });
        }

        // Step 6: Replace binary (offloaded to blocking thread to avoid
        // starving the tokio runtime, especially on Windows where retries sleep)
        info!("Replacing binary...");
        let new_bin = extracted_binary.clone();
        let target_bin = current_binary.clone();
        let replace_result =
            tokio::task::spawn_blocking(move || Self::replace_binary(&new_bin, &target_bin))
                .await
                .map_err(|e| Error::Upgrade(format!("Binary replacement task panicked: {e}")))?;
        if let Err(e) = replace_result {
            warn!("Binary replacement failed: {e}");
            // Attempt rollback
            if let Err(restore_err) = fs::copy(&backup_path, &current_binary) {
                error!("CRITICAL: Replacement failed ({e}) AND rollback failed ({restore_err})");
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

        // Step 7: Prepare restart (spawn new process if standalone mode)
        let exit_code = self.prepare_restart(&current_binary)?;

        Ok(UpgradeResult::Success {
            version: info.version.clone(),
            exit_code,
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

    /// Resolve the upgrade binary, checking the cache first and falling back
    /// to a full download/verify/extract cycle.
    ///
    /// On a cache miss the exclusive download lock is acquired (via
    /// `spawn_blocking` to avoid blocking the tokio runtime), the cache is
    /// re-checked, and if still missing the full download runs while the lock
    /// is held so that only one node downloads per version.
    async fn resolve_upgrade_binary(
        &self,
        info: &UpgradeInfo,
        dest_dir: &Path,
        version_str: &str,
    ) -> Result<PathBuf> {
        if let Some(ref cache) = self.binary_cache {
            // Fast path — cache hit without locking. The cache re-verifies
            // the ML-DSA signature over the archive on every call, so a
            // tampered cache entry returns None here and we fall through to
            // a fresh, fully verified download.
            // `dest_dir` is this upgrade's process-private temp dir, so the
            // cache stages + verifies the archive there; extraction then
            // reads exactly the verified bytes (no shared-file TOCTOU).
            if let Some(verified_archive) = cache.get_verified_archive(version_str, dest_dir) {
                match Self::extract_binary(&verified_archive, dest_dir) {
                    Ok(binary) => {
                        info!("Reused signature-verified cached archive for {version_str}");
                        return Ok(binary);
                    }
                    Err(e) => {
                        warn!("Failed to extract from cached archive, will re-download: {e}");
                        return self
                            .download_verify_extract(info, dest_dir, Some(cache))
                            .await;
                    }
                }
            }

            // Cache miss — acquire exclusive download lock via spawn_blocking
            // to avoid blocking the tokio runtime while waiting for the lock.
            let cache_clone = cache.clone();
            // Named `lock_guard` (not `_lock_guard`) so the compiler keeps it
            // alive across the `.await` below — dropping it would release the
            // file lock before the download completes.
            let lock_guard =
                tokio::task::spawn_blocking(move || cache_clone.acquire_download_lock())
                    .await
                    .map_err(|e| Error::Upgrade(format!("Lock task failed: {e}")))??;

            // Re-check cache under the lock — another node may have populated
            // it. Same re-verification guarantee as the fast path.
            if let Some(verified_archive) = cache.get_verified_archive(version_str, dest_dir) {
                if let Ok(binary) = Self::extract_binary(&verified_archive, dest_dir) {
                    info!(
                        "Signature-verified cached archive became available under lock for {version_str}"
                    );
                    return Ok(binary);
                }
            }

            // Still missing — download while holding the lock
            let result = self
                .download_verify_extract(info, dest_dir, Some(cache))
                .await;
            drop(lock_guard);
            result
        } else {
            self.download_verify_extract(info, dest_dir, None).await
        }
    }

    /// Download archive, verify signature, extract binary, and optionally
    /// store in the binary cache.
    ///
    /// # Errors
    ///
    /// Returns an error if any step (download, signature verification,
    /// extraction) fails.
    async fn download_verify_extract(
        &self,
        info: &UpgradeInfo,
        dest_dir: &Path,
        cache: Option<&BinaryCache>,
    ) -> Result<PathBuf> {
        let archive_path = dest_dir.join("archive");
        let sig_path = dest_dir.join("signature");

        // Step 1: Download archive
        info!("Downloading ant-node binary...");
        self.download(&info.download_url, &archive_path).await?;

        // Step 2: Download signature
        info!("Downloading signature...");
        self.download(&info.signature_url, &sig_path).await?;

        // Step 3: Verify signature on archive BEFORE extraction
        info!("Verifying ML-DSA signature on archive...");
        signature::verify_from_file(&archive_path, &sig_path)?;
        info!("Archive signature verified successfully");

        // Step 4: Extract binary from the just-verified archive.
        info!("Extracting binary from archive...");
        let extracted_binary = Self::extract_binary(&archive_path, dest_dir)?;

        // Step 5: Cache the signature-verified ARCHIVE (+ its signature)
        // AFTER successful extraction. We cache the signed artifact, never
        // the extracted binary, so every later cache hit can re-verify the
        // signature. Caching only after extract proves the archive is
        // actually usable on this platform avoids turning a
        // validly-signed-but-malformed release into a shared cache poison
        // pill (every later node would hit cache, fail extract, and
        // re-download).
        if let Some(c) = cache {
            let version_str = info.version.to_string();
            if let Err(e) = c.store_archive(&version_str, &archive_path, &sig_path) {
                warn!("Failed to store verified archive in cache: {e}");
            }
        }

        Ok(extracted_binary)
    }

    /// Extract the ant-node binary from an archive (tar.gz or zip).
    ///
    /// The archive format is detected by magic bytes:
    /// - `1f 8b` → gzip (tar.gz)
    /// - `50 4b` → zip
    fn extract_binary(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
        let mut file = File::open(archive_path)?;
        let mut magic = [0u8; 2];
        file.read_exact(&mut magic)
            .map_err(|e| Error::Upgrade(format!("Failed to read archive header: {e}")))?;
        drop(file);

        match magic {
            [0x1f, 0x8b] => Self::extract_from_tar_gz(archive_path, dest_dir),
            [0x50, 0x4b] => Self::extract_from_zip(archive_path, dest_dir),
            _ => Err(Error::Upgrade(format!(
                "Unknown archive format (magic bytes: {:02x} {:02x})",
                magic[0], magic[1]
            ))),
        }
    }

    /// Extract the ant-node binary from a tar.gz archive.
    fn extract_from_tar_gz(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
        let file = File::open(archive_path)?;
        let decoder = GzDecoder::new(file);
        let mut archive = Archive::new(decoder);

        let binary_name = if cfg!(windows) {
            "ant-node.exe"
        } else {
            "ant-node"
        };
        let extracted_binary = dest_dir.join(binary_name);

        for entry in archive
            .entries()
            .map_err(|e| Error::Upgrade(format!("Failed to read archive: {e}")))?
        {
            let mut entry =
                entry.map_err(|e| Error::Upgrade(format!("Failed to read entry: {e}")))?;
            let path = entry
                .path()
                .map_err(|e| Error::Upgrade(format!("Invalid path in archive: {e}")))?;

            // Look for the ant-node binary
            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str == "ant-node" || name_str == "ant-node.exe" {
                    debug!("Found binary in tar.gz archive: {}", path.display());

                    // Stream directly to disk to avoid large heap allocations
                    let mut out = File::create(&extracted_binary)?;
                    std::io::copy(&mut entry, &mut out)
                        .map_err(|e| Error::Upgrade(format!("Failed to write binary: {e}")))?;

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
            "ant-node binary not found in tar.gz archive".to_string(),
        ))
    }

    /// Extract the ant-node binary from a zip archive.
    fn extract_from_zip(archive_path: &Path, dest_dir: &Path) -> Result<PathBuf> {
        let file = File::open(archive_path)?;
        let mut archive = zip::ZipArchive::new(file)
            .map_err(|e| Error::Upgrade(format!("Failed to open zip archive: {e}")))?;

        let binary_name = if cfg!(windows) {
            "ant-node.exe"
        } else {
            "ant-node"
        };
        let extracted_binary = dest_dir.join(binary_name);

        for i in 0..archive.len() {
            let mut entry = archive
                .by_index(i)
                .map_err(|e| Error::Upgrade(format!("Failed to read zip entry: {e}")))?;

            let path = match entry.enclosed_name() {
                Some(p) => p.clone(),
                None => continue,
            };

            if let Some(name) = path.file_name() {
                let name_str = name.to_string_lossy();
                if name_str == "ant-node" || name_str == "ant-node.exe" {
                    debug!("Found binary in zip archive: {}", path.display());

                    // Stream directly to disk to avoid large heap allocations
                    let mut out = File::create(&extracted_binary)?;
                    std::io::copy(&mut entry, &mut out)
                        .map_err(|e| Error::Upgrade(format!("Failed to write binary: {e}")))?;

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
            "ant-node binary not found in zip archive".to_string(),
        ))
    }

    /// Replace the current binary with the new one.
    ///
    /// This is a blocking operation (filesystem I/O, and on Windows potentially
    /// retries with back-off). Call via `spawn_blocking` from async context.
    fn replace_binary(new_binary: &Path, target: &Path) -> Result<()> {
        #[cfg(unix)]
        {
            // Preserve original permissions on Unix
            if let Ok(meta) = fs::metadata(target) {
                let perms = meta.permissions();
                fs::set_permissions(new_binary, perms)?;
            }
            // Atomic rename
            fs::rename(new_binary, target)?;
        }

        #[cfg(windows)]
        {
            let _ = target; // target is the current exe — self_replace handles it
                            // Retry with back-off: Windows file locks may delay replacement
            let delays = [500u64, 1000, 2000];
            let mut last_err = None;
            for (attempt, delay_ms) in delays.iter().enumerate() {
                match self_replace::self_replace(new_binary) {
                    Ok(()) => {
                        last_err = None;
                        break;
                    }
                    Err(e) => {
                        warn!(
                            "self_replace attempt {} failed: {e}, retrying in {delay_ms}ms",
                            attempt + 1
                        );
                        last_err = Some(e);
                        std::thread::sleep(std::time::Duration::from_millis(*delay_ms));
                    }
                }
            }
            if let Some(e) = last_err {
                return Err(Error::Upgrade(format!(
                    "self_replace failed after retries: {e}"
                )));
            }
        }

        debug!("Binary replacement complete");
        Ok(())
    }

    /// Prepare for a restart after a successful upgrade.
    ///
    /// Returns the exit code that the process should use after graceful shutdown.
    /// The caller is responsible for triggering graceful shutdown (e.g. via
    /// `CancellationToken`) and then calling `std::process::exit()` with the
    /// returned code **after** all async cleanup has completed.
    ///
    /// **Service manager mode** (`stop_on_upgrade = true`):
    /// Returns exit code 0 on Unix or [`RESTART_EXIT_CODE`] on Windows so the
    /// service manager (systemd, launchd, Windows Service) restarts the process.
    ///
    /// **Standalone mode** (`stop_on_upgrade = false`):
    /// Spawns the new binary as a child process with the same arguments, then
    /// returns exit code 0.
    fn prepare_restart(&self, binary_path: &Path) -> Result<i32> {
        if self.stop_on_upgrade {
            let exit_code;

            #[cfg(unix)]
            {
                info!("Service manager mode: will exit with code 0 after graceful shutdown");
                exit_code = 0;
            }

            #[cfg(windows)]
            {
                let _ = binary_path;
                info!(
                    "Service manager mode: will exit with code {} after graceful shutdown",
                    RESTART_EXIT_CODE
                );
                exit_code = RESTART_EXIT_CODE;
            }

            #[cfg(not(any(unix, windows)))]
            {
                let _ = binary_path;
                warn!("Auto-restart not supported on this platform. Please restart manually.");
                exit_code = 0;
            }

            Ok(exit_code)
        } else {
            // Standalone mode: spawn new process, then exit after graceful shutdown
            let args: Vec<String> = env::args().skip(1).collect();

            info!("Spawning new process: {} {:?}", binary_path.display(), args);

            std::process::Command::new(binary_path)
                .args(&args)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::inherit())
                .stderr(std::process::Stdio::inherit())
                .spawn()
                .map_err(|e| Error::Upgrade(format!("Failed to spawn new binary: {e}")))?;

            info!("New process spawned, will exit after graceful shutdown");
            Ok(0)
        }
    }
}

/// Run the on-disk binary with `--version` and parse the reported version.
///
/// Returns `None` if the binary cannot be executed, times out, or the output
/// cannot be parsed.  Uses `tokio::process::Command` with a 5-second timeout
/// to avoid blocking the async runtime.
///
/// Output format is expected to be "ant-node X.Y.Z" or "ant-node X.Y.Z-rc.N".
async fn on_disk_version(binary_path: &Path) -> Option<Version> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(binary_path)
            .arg("--version")
            .output(),
    )
    .await
    .ok()?
    .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let version_str = stdout.trim().strip_prefix("ant-node ")?;
    Version::parse(version_str).ok()
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

    /// Helper: create a tar.gz archive containing a fake binary.
    fn create_tar_gz_archive(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        use flate2::write::GzEncoder;
        use flate2::Compression;

        let archive_path = dir.join("test.tar.gz");
        let file = File::create(&archive_path).unwrap();
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = tar::Builder::new(encoder);

        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, binary_name, content)
            .unwrap();
        builder.finish().unwrap();

        archive_path
    }

    /// Helper: create a zip archive containing a fake binary.
    fn create_zip_archive(dir: &Path, binary_name: &str, content: &[u8]) -> PathBuf {
        use std::io::Write;

        let archive_path = dir.join("test.zip");
        let file = File::create(&archive_path).unwrap();
        let mut zip_writer = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip_writer.start_file(binary_name, options).unwrap();
        zip_writer.write_all(content).unwrap();
        zip_writer.finish().unwrap();

        archive_path
    }

    #[test]
    fn test_extract_binary_from_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"fake-binary-content";
        let archive = create_tar_gz_archive(dir.path(), "ant-node", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_ok());

        let extracted = result.unwrap();
        assert!(extracted.exists());
        assert_eq!(fs::read(&extracted).unwrap(), content);
    }

    #[test]
    fn test_extract_binary_from_zip() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"fake-binary-content";
        let archive = create_zip_archive(dir.path(), "ant-node", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_ok());

        let extracted = result.unwrap();
        assert!(extracted.exists());
        assert_eq!(fs::read(&extracted).unwrap(), content);
    }

    #[test]
    fn test_extract_binary_from_zip_with_exe() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"fake-windows-binary";
        let archive = create_zip_archive(dir.path(), "ant-node.exe", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_ok());

        let extracted = result.unwrap();
        assert!(extracted.exists());
        assert_eq!(fs::read(&extracted).unwrap(), content);
    }

    #[test]
    fn test_extract_binary_from_tar_gz_nested_path() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"nested-binary";
        let archive = create_tar_gz_archive(dir.path(), "some/nested/path/ant-node", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_ok());

        let extracted = result.unwrap();
        assert!(extracted.exists());
        assert_eq!(fs::read(&extracted).unwrap(), content);
    }

    #[test]
    fn test_extract_binary_unknown_format() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("bad_archive");
        fs::write(&archive_path, b"XX not a real archive").unwrap();

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive_path, dest.path());
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("Unknown archive format"));
    }

    #[test]
    fn test_extract_binary_missing_binary_in_tar_gz() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"not-the-binary";
        let archive = create_tar_gz_archive(dir.path(), "other-file", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found in tar.gz archive"));
    }

    #[test]
    fn test_extract_binary_missing_binary_in_zip() {
        let dir = tempfile::tempdir().unwrap();
        let content = b"not-the-binary";
        let archive = create_zip_archive(dir.path(), "other-file", content);

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive, dest.path());
        assert!(result.is_err());

        let err = result.unwrap_err().to_string();
        assert!(err.contains("not found in zip archive"));
    }

    #[test]
    fn test_extract_binary_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let archive_path = dir.path().join("empty");
        fs::write(&archive_path, b"").unwrap();

        let dest = tempfile::tempdir().unwrap();
        let result = AutoApplyUpgrader::extract_binary(&archive_path, dest.path());
        assert!(result.is_err());
    }
}
