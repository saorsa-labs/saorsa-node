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
use crate::logging::{debug, info, warn};
use crate::upgrade::release_cache::ReleaseCache;
use crate::upgrade::rollout::StagedRollout;
use crate::upgrade::UpgradeInfo;
use semver::Version;
use serde::Deserialize;
use std::time::{Duration, Instant};

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
    /// Disk cache for GitHub release metadata (shared across instances).
    release_cache: Option<ReleaseCache>,
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
            .user_agent(concat!("ant-node/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| {
                warn!("Failed to build reqwest client for upgrades: {e}");
                reqwest::Client::new()
            });

        Self {
            repo,
            channel,
            check_interval: Duration::from_secs(check_interval_hours * 3600),
            current_version,
            client,
            staged_rollout: None,
            release_cache: None,
            pending_upgrade_detected: None,
            pending_upgrade_version: None,
        }
    }

    /// Configure a shared disk cache for release metadata.
    ///
    /// When set, `check_for_updates` will consult the cache before hitting
    /// the GitHub API.  Fresh results are written back so that other nodes
    /// on the same machine can reuse them.
    #[must_use]
    pub fn with_release_cache(mut self, cache: ReleaseCache) -> Self {
        self.release_cache = Some(cache);
        self
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
            .user_agent(concat!("ant-node/", env!("CARGO_PKG_VERSION")))
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|e| {
                warn!("Failed to build reqwest client for upgrades: {e}");
                reqwest::Client::new()
            });

        Self {
            repo,
            channel,
            check_interval: Duration::from_secs(check_interval_hours * 3600),
            current_version,
            client,
            staged_rollout: None,
            release_cache: None,
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
    /// - Stable: only final releases, i.e. no pre-release component at all.
    /// - Beta: final releases, plus pre-releases whose first identifier is exactly `beta`
    ///   (`0.17.0-beta.1`, `0.17.0-beta`).
    ///
    /// Every other pre-release suffix, `-rc.*` included, is rejected on both channels.
    #[must_use]
    pub fn version_matches_channel(&self, version: &Version) -> bool {
        version_matches_channel(version, self.channel)
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
        // Try the shared disk cache first (lock-free fast path)
        if let Some(ref cache) = self.release_cache {
            if let Some(cached_releases) = cache.read_if_valid(&self.repo) {
                info!(
                    "Using cached release info ({} releases)",
                    cached_releases.len()
                );
                return Ok(select_upgrade_from_releases(
                    &cached_releases,
                    &self.current_version,
                    self.channel,
                    self.pending_upgrade_version.as_ref(),
                ));
            }

            // Cache stale/missing — acquire lock and re-check so only one
            // node actually hits the GitHub API while the rest wait.
            let cache_clone = cache.clone();
            let repo_clone = self.repo.clone();
            let (lock_guard, rechecked) =
                tokio::task::spawn_blocking(move || cache_clone.lock_and_recheck(&repo_clone))
                    .await
                    .map_err(|e| Error::Upgrade(format!("Cache lock task failed: {e}")))??;

            if let Some(cached_releases) = rechecked {
                info!(
                    "Using cached release info after lock ({} releases)",
                    cached_releases.len()
                );
                return Ok(select_upgrade_from_releases(
                    &cached_releases,
                    &self.current_version,
                    self.channel,
                    self.pending_upgrade_version.as_ref(),
                ));
            }

            info!("No valid cache under lock, fetching from API");

            // Fetch from API while holding the lock
            let releases = self.fetch_releases_from_api().await?;

            // Write fresh results under the lock for other nodes
            if let Err(e) = cache.write_under_lock(lock_guard, &self.repo, &releases) {
                warn!("Failed to write release cache: {e}");
            }

            return Ok(select_upgrade_from_releases(
                &releases,
                &self.current_version,
                self.channel,
                self.pending_upgrade_version.as_ref(),
            ));
        }

        // No cache configured — fetch directly
        let releases = self.fetch_releases_from_api().await?;
        Ok(select_upgrade_from_releases(
            &releases,
            &self.current_version,
            self.channel,
            self.pending_upgrade_version.as_ref(),
        ))
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
            let restart_time = chrono::Utc::now();
            info!(
                "Node will stop/restart for upgrade at {}",
                restart_time.to_rfc3339()
            );
            return Ok(Some(info));
        };

        // Check if this is a new version or we're still tracking the same one
        let is_new_version = self
            .pending_upgrade_version
            .as_ref()
            .is_none_or(|v| *v != info.version);

        if is_new_version {
            // New version detected - start rollout timer
            self.pending_upgrade_detected = Some(Instant::now());
            self.pending_upgrade_version = Some(info.version.clone());

            let delay = rollout.calculate_delay_for_version(&info.version);
            let restart_time = chrono::Utc::now()
                + chrono::Duration::from_std(delay).unwrap_or_else(|_| chrono::Duration::hours(1));
            info!(
                new_version = %info.version,
                delay_hours = delay.as_secs() / 3600,
                delay_minutes = (delay.as_secs() % 3600) / 60,
                "New version detected, staged rollout delay calculated"
            );
            info!(
                "Node will stop/restart for upgrade at {}",
                restart_time.to_rfc3339()
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
                version = %info.version,
                "Staged rollout delay elapsed, ready to upgrade"
            );
            Ok(Some(info))
        } else {
            let remaining = delay.saturating_sub(elapsed);
            debug!(
                "Staged rollout: {}h {}m remaining before upgrade to {}",
                remaining.as_secs() / 3600,
                (remaining.as_secs() % 3600) / 60,
                info.version
            );
            Ok(None)
        }
    }

    /// Fetch releases from the GitHub API.
    async fn fetch_releases_from_api(&self) -> Result<Vec<GitHubRelease>> {
        let api_url = format!("https://api.github.com/repos/{}/releases", self.repo);
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

        response
            .json()
            .await
            .map_err(|e| Error::Network(format!("Failed to parse releases: {e}")))
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
            Some(delay.saturating_sub(elapsed))
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
    #[allow(dead_code)]
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

        if is_redundant_beta_promotion(&latest_version, &self.current_version, self.channel) {
            debug!("Skipping {latest_version}: promotion of the beta already running");
            return None;
        }

        // Find platform assets
        let binary_asset = find_platform_asset(&release.assets)?;

        let sig_name = format!("{}.sig", binary_asset.name);
        let sig_asset = release.assets.iter().find(|a| a.name == sig_name)?;

        info!(
            current_version = %self.current_version,
            new_version = %latest_version,
            "New version available"
        );

        Some(UpgradeInfo {
            version: latest_version,
            download_url: binary_asset.browser_download_url.clone(),
            signature_url: sig_asset.browser_download_url.clone(),
            release_notes: release.body.clone(),
        })
    }
}

/// Check whether a version is eligible for the given upgrade channel.
///
/// - Stable: only final releases, i.e. no pre-release component at all.
/// - Beta: final releases, plus pre-releases whose first identifier is exactly `beta`
///   (`0.17.0-beta.1`, `0.17.0-beta`).
///
/// Every other pre-release suffix is rejected on both channels. In particular `-rc.*`
/// is not a beta candidate: release candidates are published before the release gates
/// have given a verdict, and semver ranks `-rc` above `-beta`, so accepting them would
/// pull beta nodes off their soak build and onto un-gated code.
#[must_use]
fn version_matches_channel(version: &Version, channel: UpgradeChannel) -> bool {
    if version.pre.is_empty() {
        return true;
    }

    match channel {
        UpgradeChannel::Stable => false,
        UpgradeChannel::Beta => is_beta_prerelease(version),
    }
}

/// Whether a version's pre-release component marks it as a beta build.
///
/// Matches on the exact first identifier, so `0.17.0-beta.1` and `0.17.0-beta` qualify while
/// `0.17.0-betax.1` does not.
#[must_use]
fn is_beta_prerelease(version: &Version) -> bool {
    version.pre.as_str().split('.').next() == Some("beta")
}

/// Whether upgrading to `candidate` would only trade a beta build for its own promotion.
///
/// Promoting `X.Y.Z-beta.N` to the final `X.Y.Z` re-tags the same code, so a node already running
/// that beta would swap its binary and restart for no behavioural change. Semver ranks the final
/// above the pre-release, so without this the hop would happen on every release train, to every
/// beta node.
///
/// Only the matching final is skipped. A genuinely newer final — `0.19.0` while running
/// `0.18.0-beta.1` — is still taken, so a node does not stagnate if the beta line stalls.
///
/// `current` is the build the node is *committed to*, which during a staged rollout is the target
/// it has already selected rather than the one it is still running. Without that, a node part-way
/// through its rollout delay for `0.19.0-beta.1` would compare `0.19.0` against the older
/// `0.18.0-beta.1`, find the cores differ, and take the final instead — so whether a node kept its
/// beta identity would depend on where its rollout jitter fell.
///
/// Beta channel only: a node running a beta build while configured for `stable` should land on the
/// final, since that is its route back to the stable line.
#[must_use]
fn is_redundant_beta_promotion(
    candidate: &Version,
    current: &Version,
    channel: UpgradeChannel,
) -> bool {
    channel == UpgradeChannel::Beta
        && candidate.pre.is_empty()
        && is_beta_prerelease(current)
        && (candidate.major, candidate.minor, candidate.patch)
            == (current.major, current.minor, current.patch)
}

/// Select the most appropriate upgrade from a list of releases.
///
/// Only versions eligible for the channel are considered, and a beta node skips the promotion of
/// the build it is committed to; see `version_matches_channel` and `is_redundant_beta_promotion`.
///
/// Returns the newest version that matches the channel and has platform assets.
fn select_upgrade_from_releases(
    releases: &[GitHubRelease],
    current_version: &Version,
    channel: UpgradeChannel,
    pending_version: Option<&Version>,
) -> Option<UpgradeInfo> {
    // The build this node is committed to: the staged-rollout target it has already selected if
    // there is one, otherwise whatever it is running. Only the redundancy check uses this — the
    // "is it newer" guard stays on the running version, so a withdrawn pending release cannot
    // strand the node above everything still published.
    let committed_version = pending_version.unwrap_or(current_version);
    let mut best: Option<UpgradeInfo> = None;

    for release in releases {
        let Some(version) = version_from_tag(&release.tag_name) else {
            continue;
        };

        if version <= *current_version {
            continue;
        }

        if !version_matches_channel(&version, channel) {
            continue;
        }

        if is_redundant_beta_promotion(&version, committed_version, channel) {
            debug!("Skipping {version}: promotion of the beta already running");
            continue;
        }

        let Some(binary_asset) = find_platform_asset(&release.assets) else {
            continue;
        };

        let sig_name = format!("{}.sig", binary_asset.name);
        let Some(sig_asset) = release.assets.iter().find(|a| a.name == sig_name) else {
            continue;
        };

        let candidate = UpgradeInfo {
            version: version.clone(),
            download_url: binary_asset.browser_download_url.clone(),
            signature_url: sig_asset.browser_download_url.clone(),
            release_notes: release.body.clone(),
        };

        let should_replace = best.as_ref().is_none_or(|b| candidate.version > b.version);

        if should_replace {
            best = Some(candidate);
        }
    }

    best
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
        "x86_64" => vec!["x86_64", "amd64", "x64"],
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
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::case_sensitive_file_extension_comparisons
)]
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
            "WithAutonomi/ant-node".to_string(),
            UpgradeChannel::Stable,
            24,
        );

        let beta_version = Version::parse("1.0.0-beta.1").unwrap();
        assert!(!monitor.version_matches_channel(&beta_version));

        let stable_version = Version::parse("1.0.0").unwrap();
        assert!(monitor.version_matches_channel(&stable_version));
    }

    /// Test 5b: Stable rejects release candidates too
    #[test]
    fn test_stable_channel_filters_rc() {
        let monitor = UpgradeMonitor::new(
            "WithAutonomi/ant-node".to_string(),
            UpgradeChannel::Stable,
            24,
        );

        assert!(!monitor.version_matches_channel(&Version::parse("1.0.0-rc.1").unwrap()));
        assert!(monitor.version_matches_channel(&Version::parse("1.0.0").unwrap()));
    }

    /// Test 6: Channel filtering - beta includes beta
    #[test]
    fn test_beta_channel_accepts_beta() {
        let monitor = UpgradeMonitor::new(
            "WithAutonomi/ant-node".to_string(),
            UpgradeChannel::Beta,
            24,
        );

        let beta_version = Version::parse("1.0.0-beta.1").unwrap();
        assert!(monitor.version_matches_channel(&beta_version));

        let stable_version = Version::parse("1.0.0").unwrap();
        assert!(monitor.version_matches_channel(&stable_version));
    }

    /// Test 6b: Beta rejects release candidates and any other pre-release suffix
    #[test]
    fn test_beta_channel_rejects_rc() {
        let monitor = UpgradeMonitor::new(
            "WithAutonomi/ant-node".to_string(),
            UpgradeChannel::Beta,
            24,
        );

        assert!(!monitor.version_matches_channel(&Version::parse("1.0.0-rc.1").unwrap()));
        assert!(!monitor.version_matches_channel(&Version::parse("1.0.0-alpha.1").unwrap()));
        // Only an exact `beta` identifier qualifies, not a prefix match.
        assert!(!monitor.version_matches_channel(&Version::parse("1.0.0-betax.1").unwrap()));
        assert!(monitor.version_matches_channel(&Version::parse("1.0.0-beta").unwrap()));
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
                    "name": "ant-node-x86_64-unknown-linux-gnu",
                    "browser_download_url": "https://example.com/binary"
                },
                {
                    "name": "ant-node-x86_64-unknown-linux-gnu.sig",
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
                name: "ant-node-cli-linux-x64.tar.gz".to_string(),
                browser_download_url: "https://example.com/linux".to_string(),
            },
            Asset {
                name: "ant-node-cli-linux-x64.tar.gz.sig".to_string(),
                browser_download_url: "https://example.com/linux.sig".to_string(),
            },
            Asset {
                name: "ant-node-cli-macos-arm64.tar.gz".to_string(),
                browser_download_url: "https://example.com/macos".to_string(),
            },
            Asset {
                name: "ant-node-cli-macos-arm64.tar.gz.sig".to_string(),
                browser_download_url: "https://example.com/macos.sig".to_string(),
            },
            Asset {
                name: "ant-node-cli-windows-x64.zip".to_string(),
                browser_download_url: "https://example.com/windows".to_string(),
            },
            Asset {
                name: "ant-node-cli-windows-x64.zip.sig".to_string(),
                browser_download_url: "https://example.com/windows.sig".to_string(),
            },
        ];

        let asset = find_platform_asset(&assets);
        assert!(asset.is_some(), "Should find platform asset");
        let asset = asset.unwrap();
        // Should not be a .sig file
        assert!(!asset.name.to_lowercase().ends_with(".sig"));
        // Should be an archive
        let lower = asset.name.to_lowercase();
        assert!(
            lower.ends_with(".tar.gz") || lower.ends_with(".zip"),
            "Should be an archive format"
        );
    }

    /// Test: `is_binary_asset` correctly identifies binaries and archives
    #[test]
    fn test_is_binary_asset() {
        // Archive formats should be identified (CLI releases)
        assert!(is_binary_asset("ant-node-cli-linux-x64.tar.gz"));
        assert!(is_binary_asset("ant-node-cli-macos-arm64.tar.gz"));
        assert!(is_binary_asset("ant-node-cli-windows-x64.zip"));

        // Signature and metadata files should be excluded
        assert!(!is_binary_asset("ant-node.sig"));
        assert!(!is_binary_asset("ant-node.sha256"));
        assert!(!is_binary_asset("ant-node.md5"));
        assert!(!is_binary_asset("RELEASE_NOTES.txt"));
        assert!(!is_binary_asset("README.md"));

        // Installer packages should be excluded (handled separately)
        assert!(!is_binary_asset("ant-node.deb"));
        assert!(!is_binary_asset("ant-node.rpm"));
        assert!(!is_binary_asset("ant-node.msi"));
    }

    /// Test 10: Monitor check interval
    #[test]
    fn test_check_interval() {
        let monitor = UpgradeMonitor::new("test/repo".to_string(), UpgradeChannel::Stable, 24);
        assert_eq!(monitor.check_interval(), Duration::from_hours(24));

        let monitor2 = UpgradeMonitor::new("test/repo".to_string(), UpgradeChannel::Stable, 6);
        assert_eq!(monitor2.check_interval(), Duration::from_hours(6));
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
        let archive_name = format!("ant-node-cli-{friendly_os}-{friendly_arch}.{archive_ext}");

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
            "WithAutonomi/ant-node".to_string(),
            UpgradeChannel::Stable,
            24,
        );
        assert_eq!(monitor.repo(), "WithAutonomi/ant-node");
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
        assert!(patterns.iter().any(|p| p.contains("x64")));
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

    #[test]
    fn test_select_upgrade_stable_ignores_prerelease() {
        let current = Version::new(1, 0, 0);
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        // On Windows, binary assets require .exe extension
        #[cfg(windows)]
        let bin_name = format!("ant-node-{arch}-{os}.exe");
        #[cfg(not(windows))]
        let bin_name = format!("ant-node-{arch}-{os}");
        let releases = vec![
            GitHubRelease {
                tag_name: "v1.1.0-beta.1".to_string(),
                name: "beta".to_string(),
                body: "beta".to_string(),
                prerelease: true,
                assets: vec![
                    Asset {
                        name: bin_name.clone(),
                        browser_download_url: "https://example.com/beta".to_string(),
                    },
                    Asset {
                        name: format!("{bin_name}.sig"),
                        browser_download_url: "https://example.com/beta.sig".to_string(),
                    },
                ],
            },
            GitHubRelease {
                tag_name: "v1.1.0".to_string(),
                name: "stable".to_string(),
                body: "stable".to_string(),
                prerelease: false,
                assets: vec![
                    Asset {
                        name: bin_name.clone(),
                        browser_download_url: "https://example.com/stable".to_string(),
                    },
                    Asset {
                        name: format!("{bin_name}.sig"),
                        browser_download_url: "https://example.com/stable.sig".to_string(),
                    },
                ],
            },
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Stable, None)
                .unwrap();
        assert_eq!(upgrade.version, Version::new(1, 1, 0));
        assert!(upgrade.download_url.contains("stable"));
    }

    #[test]
    fn test_select_upgrade_beta_accepts_prerelease_if_newest() {
        let current = Version::new(1, 0, 0);
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        // On Windows, binary assets require .exe extension
        #[cfg(windows)]
        let bin_name = format!("ant-node-{arch}-{os}.exe");
        #[cfg(not(windows))]
        let bin_name = format!("ant-node-{arch}-{os}");
        let releases = vec![
            GitHubRelease {
                tag_name: "v1.1.0".to_string(),
                name: "stable".to_string(),
                body: "stable".to_string(),
                prerelease: false,
                assets: vec![
                    Asset {
                        name: bin_name.clone(),
                        browser_download_url: "https://example.com/stable".to_string(),
                    },
                    Asset {
                        name: format!("{bin_name}.sig"),
                        browser_download_url: "https://example.com/stable.sig".to_string(),
                    },
                ],
            },
            GitHubRelease {
                tag_name: "v1.2.0-beta.1".to_string(),
                name: "beta".to_string(),
                body: "beta".to_string(),
                prerelease: true,
                assets: vec![
                    Asset {
                        name: bin_name.clone(),
                        browser_download_url: "https://example.com/beta".to_string(),
                    },
                    Asset {
                        name: format!("{bin_name}.sig"),
                        browser_download_url: "https://example.com/beta.sig".to_string(),
                    },
                ],
            },
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(upgrade.version, Version::parse("1.2.0-beta.1").unwrap());
        assert!(upgrade.download_url.contains("beta"));
    }

    /// Build a release fixture carrying the platform binary and its signature, so that
    /// `select_upgrade_from_releases` does not skip it for missing assets.
    fn release_with_assets(tag: &str) -> GitHubRelease {
        let arch = std::env::consts::ARCH;
        let os = std::env::consts::OS;
        #[cfg(windows)]
        let bin_name = format!("ant-node-{arch}-{os}.exe");
        #[cfg(not(windows))]
        let bin_name = format!("ant-node-{arch}-{os}");

        GitHubRelease {
            tag_name: tag.to_string(),
            name: tag.to_string(),
            body: format!("notes for {tag}"),
            prerelease: tag.contains('-'),
            assets: vec![
                Asset {
                    name: bin_name.clone(),
                    browser_download_url: format!("https://example.com/{tag}"),
                },
                Asset {
                    name: format!("{bin_name}.sig"),
                    browser_download_url: format!("https://example.com/{tag}.sig"),
                },
            ],
        }
    }

    /// Mixed release list: stable takes the final, beta takes the beta, neither takes the rc.
    #[test]
    fn test_select_upgrade_never_picks_rc() {
        let current = Version::parse("0.15.0").unwrap();
        let releases = vec![
            release_with_assets("v0.16.0"),
            release_with_assets("v0.17.0-beta.1"),
            release_with_assets("v0.17.0-rc.1"),
        ];

        let stable =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Stable, None)
                .unwrap();
        assert_eq!(stable.version, Version::parse("0.16.0").unwrap());

        let beta =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(beta.version, Version::parse("0.17.0-beta.1").unwrap());
    }

    /// A beta node does not restart onto the promotion of the build it is already running:
    /// `0.18.0-beta.1` -> `0.18.0` re-tags the same code.
    #[test]
    fn test_select_upgrade_beta_skips_own_promotion() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![release_with_assets("v0.18.0")];

        assert!(
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).is_none(),
            "beta node should stay on 0.18.0-beta.1 when only its own promotion is published"
        );
    }

    /// A node part-way through its staged rollout for `0.19.0-beta.1` holds that target when the
    /// promoted `0.19.0` appears, instead of being retargeted onto the final.
    #[test]
    fn test_select_upgrade_beta_holds_pending_beta_against_its_promotion() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let pending = Version::parse("0.19.0-beta.1").unwrap();
        let releases = vec![
            release_with_assets("v0.19.0-beta.1"),
            release_with_assets("v0.19.0"),
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, Some(&pending))
                .unwrap();
        assert_eq!(upgrade.version, Version::parse("0.19.0-beta.1").unwrap());
    }

    /// Without a pending target the same release pair resolves to the final: the node is running
    /// `0.18.0-beta.1`, whose core differs from `0.19.0`, so nothing marks the final redundant.
    /// This is what makes threading the pending target through necessary.
    #[test]
    fn test_select_upgrade_beta_without_pending_takes_the_final() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![
            release_with_assets("v0.19.0-beta.1"),
            release_with_assets("v0.19.0"),
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(upgrade.version, Version::parse("0.19.0").unwrap());
    }

    /// The skip is narrow: a genuinely newer final is still taken, so a beta node does not
    /// stagnate if the beta line stalls.
    #[test]
    fn test_select_upgrade_beta_takes_newer_final() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![
            release_with_assets("v0.18.0"),
            release_with_assets("v0.19.0"),
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(upgrade.version, Version::parse("0.19.0").unwrap());
    }

    /// With its own promotion and a newer beta both published, the beta wins and the promotion is
    /// skipped rather than taken first.
    #[test]
    fn test_select_upgrade_beta_prefers_next_beta_over_own_promotion() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![
            release_with_assets("v0.18.0"),
            release_with_assets("v0.19.0-beta.1"),
        ];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(upgrade.version, Version::parse("0.19.0-beta.1").unwrap());
    }

    /// The skip is beta-channel only. A node running a beta build but configured for stable takes
    /// the final, since that is its route back onto the stable line.
    #[test]
    fn test_select_upgrade_stable_takes_promotion_of_running_beta() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![release_with_assets("v0.18.0")];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Stable, None)
                .unwrap();
        assert_eq!(upgrade.version, Version::parse("0.18.0").unwrap());
    }

    /// A later beta of the same version is still an upgrade — the skip only covers finals.
    #[test]
    fn test_select_upgrade_beta_takes_later_beta_of_same_version() {
        let current = Version::parse("0.18.0-beta.1").unwrap();
        let releases = vec![release_with_assets("v0.18.0-beta.2")];

        let upgrade =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(upgrade.version, Version::parse("0.18.0-beta.2").unwrap());
    }

    /// Ship-and-promote on the same day: a node soaking `0.16.0-beta.1` sees both the promoted
    /// `0.16.0` and the next cut `0.17.0-beta.1`, and hops straight to the new beta.
    #[test]
    fn test_select_upgrade_beta_ship_and_promote_same_day() {
        let current = Version::parse("0.16.0-beta.1").unwrap();
        let releases = vec![
            release_with_assets("v0.16.0"),
            release_with_assets("v0.17.0-beta.1"),
        ];

        let beta =
            select_upgrade_from_releases(&releases, &current, UpgradeChannel::Beta, None).unwrap();
        assert_eq!(beta.version, Version::parse("0.17.0-beta.1").unwrap());
    }
}
