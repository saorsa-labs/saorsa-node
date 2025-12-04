//! GitHub release monitor for auto-upgrades.
//!
//! This module provides functionality to:
//! - Poll GitHub releases API for new versions
//! - Filter releases by channel (stable/beta)
//! - Find platform-specific binary assets
//! - Detect available upgrades
//! - Staged rollout with deterministic delays

use crate::config::UpgradeChannel;
use crate::error::{Error, Result};
use crate::upgrade::rollout::StagedRollout;
use crate::upgrade::UpgradeInfo;
use semver::Version;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

/// GitHub release API response.
#[derive(Debug, Deserialize)]
pub struct GitHubRelease {
    /// Git tag name (e.g., "v1.2.0").
    pub tag_name: String,
    /// Release title.
    pub name: String,
    /// Release description/notes.
    pub body: String,
    /// Whether this is a pre-release.
    pub prerelease: bool,
    /// Attached binary assets.
    pub assets: Vec<Asset>,
}

/// GitHub release asset (attached file).
#[derive(Debug, Deserialize, Clone)]
pub struct Asset {
    /// Filename of the asset.
    pub name: String,
    /// Direct download URL.
    pub browser_download_url: String,
}

/// Monitors GitHub releases for new versions.
pub struct UpgradeMonitor {
    /// GitHub repository (owner/repo format).
    repo: String,
    /// Release channel to track.
    channel: UpgradeChannel,
    /// How often to check for updates.
    check_interval: Duration,
    /// Current version.
    current_version: Version,
    /// HTTP client for GitHub API requests.
    client: reqwest::Client,
    /// Staged rollout calculator (optional).
    staged_rollout: Option<StagedRollout>,
    /// When the current pending upgrade was first detected.
    pending_upgrade_detected: Option<Instant>,
    /// The version of the pending upgrade (for tracking rollout state).
    pending_upgrade_version: Option<Version>,
}

impl UpgradeMonitor {
    /// Create a new upgrade monitor.
    ///
    /// # Arguments
    ///
    /// * `repo` - GitHub repository in "owner/repo" format
    /// * `channel` - Release channel to track (Stable or Beta)
    /// * `check_interval_hours` - How often to check for updates
    #[must_use]
    pub fn new(repo: String, channel: UpgradeChannel, check_interval_hours: u64) -> Self {
        let current_version =
            Version::parse(env!("CARGO_PKG_VERSION")).unwrap_or_else(|_| Version::new(0, 0, 0));

        let client = reqwest::Client::builder()
            .user_agent(concat!("saorsa-node/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            repo,
            channel,
            check_interval: Duration::from_secs(check_interval_hours * 3600),
            current_version,
            client,
            staged_rollout: None,
            pending_upgrade_detected: None,
            pending_upgrade_version: None,
        }
    }

    /// Configure staged rollout for this monitor.
    ///
    /// # Arguments
    ///
    /// * `node_id` - The node's unique identifier for deterministic delay calculation
    /// * `max_delay_hours` - Maximum rollout window (0 to disable)
    #[must_use]
    pub fn with_staged_rollout(mut self, node_id: &[u8], max_delay_hours: u64) -> Self {
        if max_delay_hours > 0 {
            self.staged_rollout = Some(StagedRollout::new(node_id, max_delay_hours));
            info!("Staged rollout enabled: {} hour window", max_delay_hours);
        }
        self
    }

    /// Create a monitor with a custom current version (for testing).
    #[cfg(test)]
    #[must_use]
    pub fn with_version(
        repo: String,
        channel: UpgradeChannel,
        check_interval_hours: u64,
        current_version: Version,
    ) -> Self {
        let client = reqwest::Client::builder()
            .user_agent(concat!("saorsa-node/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        Self {
            repo,
            channel,
            check_interval: Duration::from_secs(check_interval_hours * 3600),
            current_version,
            client,
            staged_rollout: None,
            pending_upgrade_detected: None,
            pending_upgrade_version: None,
        }
    }

    /// Get the check interval.
    #[must_use]
    pub fn check_interval(&self) -> Duration {
        self.check_interval
    }

    /// Get the current version.
    #[must_use]
    pub fn current_version(&self) -> &Version {
        &self.current_version
    }

    /// Get the tracked repository.
    #[must_use]
    pub fn repo(&self) -> &str {
        &self.repo
    }

    /// Check if version matches the configured channel.
    ///
    /// - Stable channel: Only accepts versions without pre-release suffixes
    /// - Beta channel: Accepts all versions (stable and pre-release)
    #[must_use]
    pub fn version_matches_channel(&self, version: &Version) -> bool {
        match self.channel {
            UpgradeChannel::Stable => version.pre.is_empty(),
            UpgradeChannel::Beta => true, // Beta accepts all
        }
    }

    /// Check GitHub for available updates.
    ///
    /// This method only checks for available updates, it does not respect
    /// staged rollout delays. Use [`Self::check_for_ready_upgrade`] for staged rollout
    /// aware upgrade checking.
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub API request fails.
    pub async fn check_for_updates(&self) -> Result<Option<UpgradeInfo>> {
        let api_url = format!("https://api.github.com/repos/{}/releases/latest", self.repo);

        debug!("Checking for updates from: {}", api_url);

        let response = self
            .client
            .get(&api_url)
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .map_err(|e| Error::Network(format!("GitHub API request failed: {e}")))?;

        if !response.status().is_success() {
            return Err(Error::Network(format!(
                "GitHub API returned status: {}",
                response.status()
            )));
        }

        let release: GitHubRelease = response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse release: {e}")))?;

        Ok(self.process_release(&release))
    }

    /// Check for available updates with staged rollout awareness.
    ///
    /// This method:
    /// 1. Checks GitHub for available updates
    /// 2. If staged rollout is enabled and an upgrade is found:
    ///    - Starts tracking the upgrade detection time
    ///    - Returns `None` until the calculated delay has passed
    ///    - Returns the upgrade info once the node is ready to apply it
    ///
    /// # Errors
    ///
    /// Returns an error if the GitHub API request fails.
    pub async fn check_for_ready_upgrade(&mut self) -> Result<Option<UpgradeInfo>> {
        let upgrade_info = self.check_for_updates().await?;

        let Some(info) = upgrade_info else {
            // No upgrade available - reset tracking state
            self.pending_upgrade_detected = None;
            self.pending_upgrade_version = None;
            return Ok(None);
        };

        // If staged rollout is not enabled, return immediately
        let Some(ref rollout) = self.staged_rollout else {
            return Ok(Some(info));
        };

        // Check if this is a new version or we're still tracking the same one
        let is_new_version = self
            .pending_upgrade_version
            .as_ref()
            .map_or(true, |v| *v != info.version);

        if is_new_version {
            // New version detected - start rollout timer
            self.pending_upgrade_detected = Some(Instant::now());
            self.pending_upgrade_version = Some(info.version.clone());

            let delay = rollout.calculate_delay_for_version(&info.version);
            info!(
                "New version {} detected. Staged rollout delay: {}h {}m",
                info.version,
                delay.as_secs() / 3600,
                (delay.as_secs() % 3600) / 60
            );
        }

        // Calculate if we're past the rollout delay
        let Some(detected_at) = self.pending_upgrade_detected else {
            // Should not happen, but handle gracefully
            warn!("Pending upgrade detected but no timestamp recorded");
            return Ok(Some(info));
        };

        let delay = rollout.calculate_delay_for_version(&info.version);
        let elapsed = detected_at.elapsed();

        if elapsed >= delay {
            info!(
                "Staged rollout delay elapsed. Ready to upgrade to version {}",
                info.version
            );
            Ok(Some(info))
        } else {
            let remaining = delay - elapsed;
            debug!(
                "Staged rollout: {}h {}m remaining before upgrade to {}",
                remaining.as_secs() / 3600,
                (remaining.as_secs() % 3600) / 60,
                info.version
            );
            Ok(None)
        }
    }

    /// Get the remaining time until this node should upgrade.
    ///
    /// Returns `None` if no upgrade is pending or staged rollout is disabled.
    #[must_use]
    pub fn time_until_upgrade(&self) -> Option<Duration> {
        let rollout = self.staged_rollout.as_ref()?;
        let version = self.pending_upgrade_version.as_ref()?;
        let detected_at = self.pending_upgrade_detected?;

        let delay = rollout.calculate_delay_for_version(version);
        let elapsed = detected_at.elapsed();

        if elapsed >= delay {
            Some(Duration::ZERO)
        } else {
            Some(delay - elapsed)
        }
    }

    /// Check if staged rollout is enabled.
    #[must_use]
    pub fn has_staged_rollout(&self) -> bool {
        self.staged_rollout.is_some()
    }

    /// Get the pending upgrade version, if any.
    #[must_use]
    pub fn pending_version(&self) -> Option<&Version> {
        self.pending_upgrade_version.as_ref()
    }

    /// Process a GitHub release and determine if an upgrade is available.
    fn process_release(&self, release: &GitHubRelease) -> Option<UpgradeInfo> {
        let latest_version = version_from_tag(&release.tag_name)?;

        // Check if newer
        if latest_version <= self.current_version {
            debug!("Current version {} is up to date", self.current_version);
            return None;
        }

        // Check channel filter
        if !self.version_matches_channel(&latest_version) {
            debug!(
                "Version {} doesn't match channel {:?}",
                latest_version, self.channel
            );
            return None;
        }

        // Find platform assets
        let binary_asset = find_platform_asset(&release.assets)?;

        let sig_name = format!("{}.sig", binary_asset.name);
        let sig_asset = release.assets.iter().find(|a| a.name == sig_name)?;

        info!(
            "New version available: {} -> {}",
            self.current_version, latest_version
        );

        Some(UpgradeInfo {
            version: latest_version,
            download_url: binary_asset.browser_download_url.clone(),
            signature_url: sig_asset.browser_download_url.clone(),
            release_notes: release.body.clone(),
        })
    }
}

/// Parse version from git tag.
///
/// Handles both "v1.2.3" and "1.2.3" formats.
#[must_use]
pub fn version_from_tag(tag: &str) -> Option<Version> {
    let version_str = tag.strip_prefix('v').unwrap_or(tag);
    Version::parse(version_str).ok()
}

/// Find the appropriate binary asset for the current platform.
///
/// Looks for assets matching the current OS and architecture.
/// On Windows, also looks for `.exe` suffixed binaries.
#[must_use]
pub fn find_platform_asset(assets: &[Asset]) -> Option<&Asset> {
    let arch = std::env::consts::ARCH;
    let os = std::env::consts::OS;

    // Build platform-specific patterns
    let patterns = build_platform_patterns(arch, os);

    // Try each pattern in order of specificity
    for pattern in &patterns {
        if let Some(asset) = assets
            .iter()
            .find(|a| a.name.contains(pattern) && is_binary_asset(&a.name))
        {
            return Some(asset);
        }
    }

    None
}

/// Check if an asset name represents a downloadable binary or archive.
///
/// This includes direct executables, as well as archive formats (`.tar.gz`, `.zip`)
/// that contain binaries.
#[allow(clippy::case_sensitive_file_extension_comparisons)]
fn is_binary_asset(name: &str) -> bool {
    let lower = name.to_lowercase();

    // Exclude signatures and other non-binary files (already lowercased above)
    if lower.ends_with(".sig")
        || lower.ends_with(".sha256")
        || lower.ends_with(".md5")
        || lower.ends_with(".txt")
        || lower.ends_with(".md")
        || lower.ends_with(".deb")
        || lower.ends_with(".rpm")
        || lower.ends_with(".msi")
    {
        return false;
    }

    // Accept archive formats on all platforms
    if lower.ends_with(".tar.gz") || lower.ends_with(".zip") {
        return true;
    }

    // On Windows, prefer .exe files for direct binary downloads
    #[cfg(windows)]
    if !lower.ends_with(".exe") {
        return false;
    }

    true
}

/// Build platform-specific search patterns.
fn build_platform_patterns(arch: &str, os: &str) -> Vec<String> {
    let mut patterns = Vec::new();

    // Map arch to common naming conventions
    let arch_patterns: Vec<&str> = match arch {
        "x86_64" => vec!["x86_64", "amd64"],
        "aarch64" => vec!["aarch64", "arm64"],
        "x86" => vec!["i686", "i386", "x86"],
        _ => vec![arch],
    };

    // Map OS to common naming conventions
    let os_patterns: Vec<&str> = match os {
        "linux" => vec!["linux", "unknown-linux-gnu", "linux-gnu"],
        "macos" => vec!["darwin", "macos", "apple-darwin"],
        "windows" => vec!["windows", "pc-windows-msvc", "win64"],
        _ => vec![os],
    };

    // Generate all combinations
    for arch_pat in &arch_patterns {
        for os_pat in &os_patterns {
            patterns.push(format!("{arch_pat}-{os_pat}"));
            patterns.push(format!("{os_pat}-{arch_pat}"));
        }
    }

    // Add individual patterns as fallback
    for arch_pat in &arch_patterns {
        patterns.push((*arch_pat).to_string());
    }

    patterns
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    /// Test 1: Version comparison - newer available
    #[test]
    fn test_version_newer_available() {
        let current = Version::new(1, 0, 0);
        let latest = Version::new(1, 1, 0);
        assert!(latest > current);
    }

    /// Test 2: Version comparison - same version
    #[test]
    fn test_version_same() {
        let current = Version::new(1, 0, 0);
        let latest = Version::new(1, 0, 0);
        assert!(latest <= current);
    }

    /// Test 3: Version comparison - older available (downgrade prevention)
    #[test]
    fn test_version_older_rejected() {
        let current = Version::new(1, 1, 0);
        let latest = Version::new(1, 0, 0);
        assert!(latest <= current);
    }

    /// Test 4: Pre-release handling
    #[test]
    fn test_prerelease_version() {
        let stable = Version::parse("1.0.0").unwrap();
        let beta = Version::parse("1.1.0-beta.1").unwrap();
        // Beta 1.1.0 considered newer than stable 1.0.0
        assert!(beta > stable);
    }

    /// Test 5: Channel filtering - stable only
    #[test]
    fn test_stable_channel_filters_beta() {
        let monitor = UpgradeMonitor::new(
            "dirvine/saorsa-node".to_string(),
            UpgradeChannel::Stable,
            24,
        );

        let beta_version = Version::parse("1.0.0-beta.1").unwrap();
        assert!(!monitor.version_matches_channel(&beta_version));

        let stable_version = Version::parse("1.0.0").unwrap();
        assert!(monitor.version_matches_channel(&stable_version));
    }

    /// Test 6: Channel filtering - beta includes beta
    #[test]
    fn test_beta_channel_accepts_beta() {
        let monitor =
            UpgradeMonitor::new("dirvine/saorsa-node".to_string(), UpgradeChannel::Beta, 24);

        let beta_version = Version::parse("1.0.0-beta.1").unwrap();
        assert!(monitor.version_matches_channel(&beta_version));
    }

    /// Test 7: Parse GitHub release response
    #[test]
    fn test_parse_github_release() {
        let json = r#"{
            "tag_name": "v1.2.0",
            "name": "Release 1.2.0",
            "body": "Release notes here",
            "prerelease": false,
            "assets": [
                {
                    "name": "saorsa-node-x86_64-unknown-linux-gnu",
                    "browser_download_url": "https://example.com/binary"
                },
                {
                    "name": "saorsa-node-x86_64-unknown-linux-gnu.sig",
                    "browser_download_url": "https://example.com/binary.sig"
                }
            ]
        }"#;

        let release: GitHubRelease = serde_json::from_str(json).unwrap();
        assert_eq!(release.tag_name, "v1.2.0");
        assert_eq!(release.name, "Release 1.2.0");
        assert_eq!(release.body, "Release notes here");
        assert!(!release.prerelease);
        assert_eq!(release.assets.len(), 2);
    }

    /// Test 8: Extract version from tag
    #[test]
    fn test_version_from_tag() {
        assert_eq!(version_from_tag("v1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(version_from_tag("1.2.3"), Some(Version::new(1, 2, 3)));
        assert_eq!(
            version_from_tag("v1.0.0-beta.1"),
            Some(Version::parse("1.0.0-beta.1").unwrap())
        );
        assert_eq!(version_from_tag("invalid"), None);
        assert_eq!(version_from_tag(""), None);
    }

    /// Test 9: Find correct asset for platform
    #[test]
    fn test_find_platform_asset() {
        // Test with archive format (CLI releases)
        let assets = vec![
            Asset {
                name: "saorsa-node-cli-linux-x64.tar.gz".to_string(),
                browser_download_url: "https://example.com/linux".to_string(),
            },
            Asset {
                name: "saorsa-node-cli-linux-x64.tar.gz.sig".to_string(),
                browser_download_url: "https://example.com/linux.sig".to_string(),
            },
            Asset {
                name: "saorsa-node-cli-macos-arm64.tar.gz".to_string(),
                browser_download_url: "https://example.com/macos".to_string(),
            },
            Asset {
                name: "saorsa-node-cli-macos-arm64.tar.gz.sig".to_string(),
                browser_download_url: "https://example.com/macos.sig".to_string(),
            },
            Asset {
                name: "saorsa-node-cli-windows-x64.zip".to_string(),
                browser_download_url: "https://example.com/windows".to_string(),
            },
            Asset {
                name: "saorsa-node-cli-windows-x64.zip.sig".to_string(),
                browser_download_url: "https://example.com/windows.sig".to_string(),
            },
        ];

        let asset = find_platform_asset(&assets);
        assert!(asset.is_some(), "Should find platform asset");
        let asset = asset.unwrap();
        // Should not be a .sig file
        assert!(!asset.name.to_lowercase().ends_with(".sig"));
        // Should be an archive
        assert!(
            asset.name.ends_with(".tar.gz") || asset.name.ends_with(".zip"),
            "Should be an archive format"
        );
    }

    /// Test: `is_binary_asset` correctly identifies binaries and archives
    #[test]
    fn test_is_binary_asset() {
        // Archive formats should be identified (CLI releases)
        assert!(is_binary_asset("saorsa-node-cli-linux-x64.tar.gz"));
        assert!(is_binary_asset("saorsa-node-cli-macos-arm64.tar.gz"));
        assert!(is_binary_asset("saorsa-node-cli-windows-x64.zip"));

        // Signature and metadata files should be excluded
        assert!(!is_binary_asset("saorsa-node.sig"));
        assert!(!is_binary_asset("saorsa-node.sha256"));
        assert!(!is_binary_asset("saorsa-node.md5"));
        assert!(!is_binary_asset("RELEASE_NOTES.txt"));
        assert!(!is_binary_asset("README.md"));

        // Installer packages should be excluded (handled separately)
        assert!(!is_binary_asset("saorsa-node.deb"));
        assert!(!is_binary_asset("saorsa-node.rpm"));
        assert!(!is_binary_asset("saorsa-node.msi"));
    }

    /// Test 10: Monitor check interval
    #[test]
    fn test_check_interval() {
        let monitor = UpgradeMonitor::new("test/repo".to_string(), UpgradeChannel::Stable, 24);
        assert_eq!(monitor.check_interval(), Duration::from_secs(24 * 3600));

        let monitor2 = UpgradeMonitor::new("test/repo".to_string(), UpgradeChannel::Stable, 6);
        assert_eq!(monitor2.check_interval(), Duration::from_secs(6 * 3600));
    }

    /// Test 11: Process release - upgrade available
    #[test]
    fn test_process_release_upgrade_available() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(1, 0, 0),
        );

        // Build platform-specific archive name using friendly naming
        let (friendly_os, archive_ext) = match std::env::consts::OS {
            "linux" => ("linux", "tar.gz"),
            "macos" => ("macos", "tar.gz"),
            "windows" => ("windows", "zip"),
            _ => ("unknown", "tar.gz"),
        };
        let friendly_arch = match std::env::consts::ARCH {
            "x86_64" => "x64",
            "aarch64" => "arm64",
            _ => std::env::consts::ARCH,
        };
        let archive_name = format!("saorsa-node-cli-{friendly_os}-{friendly_arch}.{archive_ext}");

        let release = GitHubRelease {
            tag_name: "v1.1.0".to_string(),
            name: "Release 1.1.0".to_string(),
            body: "New features".to_string(),
            prerelease: false,
            assets: vec![
                Asset {
                    name: archive_name.clone(),
                    browser_download_url: "https://example.com/binary".to_string(),
                },
                Asset {
                    name: format!("{archive_name}.sig"),
                    browser_download_url: "https://example.com/binary.sig".to_string(),
                },
            ],
        };

        let result = monitor.process_release(&release);
        assert!(result.is_some(), "Should find upgrade");
        let info = result.unwrap();
        assert_eq!(info.version, Version::new(1, 1, 0));
        assert_eq!(info.release_notes, "New features");
    }

    /// Test 12: Process release - no upgrade (same version)
    #[test]
    fn test_process_release_no_upgrade_same_version() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(1, 0, 0),
        );

        let release = GitHubRelease {
            tag_name: "v1.0.0".to_string(),
            name: "Release 1.0.0".to_string(),
            body: "Current version".to_string(),
            prerelease: false,
            assets: vec![],
        };

        let result = monitor.process_release(&release);
        assert!(result.is_none(), "Should not find upgrade for same version");
    }

    /// Test 13: Process release - no upgrade (older version)
    #[test]
    fn test_process_release_no_upgrade_older_version() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(1, 1, 0),
        );

        let release = GitHubRelease {
            tag_name: "v1.0.0".to_string(),
            name: "Release 1.0.0".to_string(),
            body: "Old version".to_string(),
            prerelease: false,
            assets: vec![],
        };

        let result = monitor.process_release(&release);
        assert!(
            result.is_none(),
            "Should not find upgrade for older version"
        );
    }

    /// Test 14: Process release - beta filtered by stable channel
    #[test]
    fn test_process_release_beta_filtered() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(1, 0, 0),
        );

        let release = GitHubRelease {
            tag_name: "v1.1.0-beta.1".to_string(),
            name: "Beta Release".to_string(),
            body: "Beta features".to_string(),
            prerelease: true,
            assets: vec![],
        };

        let result = monitor.process_release(&release);
        assert!(
            result.is_none(),
            "Stable channel should filter beta releases"
        );
    }

    /// Test 15: Monitor repo getter
    #[test]
    fn test_monitor_repo() {
        let monitor = UpgradeMonitor::new(
            "dirvine/saorsa-node".to_string(),
            UpgradeChannel::Stable,
            24,
        );
        assert_eq!(monitor.repo(), "dirvine/saorsa-node");
    }

    /// Test 16: Current version getter
    #[test]
    fn test_monitor_current_version() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(2, 3, 4),
        );
        assert_eq!(*monitor.current_version(), Version::new(2, 3, 4));
    }

    /// Test 17: Build platform patterns
    #[test]
    fn test_build_platform_patterns() {
        let patterns = build_platform_patterns("x86_64", "linux");
        assert!(patterns.iter().any(|p| p.contains("x86_64")));
        assert!(patterns.iter().any(|p| p.contains("linux")));

        let patterns_arm = build_platform_patterns("aarch64", "macos");
        assert!(patterns_arm
            .iter()
            .any(|p| p.contains("aarch64") || p.contains("arm64")));
        assert!(patterns_arm
            .iter()
            .any(|p| p.contains("darwin") || p.contains("macos")));
    }

    /// Test 18: Invalid tag handling
    #[test]
    fn test_process_release_invalid_tag() {
        let monitor = UpgradeMonitor::with_version(
            "test/repo".to_string(),
            UpgradeChannel::Stable,
            24,
            Version::new(1, 0, 0),
        );

        let release = GitHubRelease {
            tag_name: "not-a-version".to_string(),
            name: "Invalid Release".to_string(),
            body: "Invalid".to_string(),
            prerelease: false,
            assets: vec![],
        };

        let result = monitor.process_release(&release);
        assert!(result.is_none(), "Should gracefully handle invalid tag");
    }
}
