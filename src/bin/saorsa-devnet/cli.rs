//! CLI definition for saorsa-devnet.

use clap::Parser;
use std::path::PathBuf;

/// Local devnet runner for saorsa-node.
#[derive(Parser, Debug)]
#[command(name = "saorsa-devnet")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Node count to spawn.
    #[arg(long)]
    pub nodes: Option<usize>,

    /// Bootstrap node count (first N nodes).
    #[arg(long)]
    pub bootstrap_count: Option<usize>,

    /// Base port for node allocation (0 for auto).
    #[arg(long)]
    pub base_port: Option<u16>,

    /// Data directory for node state.
    #[arg(long)]
    pub data_dir: Option<PathBuf>,

    /// Remove data directory on shutdown.
    #[arg(long, default_value_t = true)]
    pub cleanup: bool,

    /// Spawn delay in milliseconds.
    #[arg(long)]
    pub spawn_delay_ms: Option<u64>,

    /// Stabilization timeout in seconds.
    #[arg(long)]
    pub stabilization_timeout_secs: Option<u64>,

    /// Preset: minimal, small, default.
    #[arg(long)]
    pub preset: Option<String>,

    /// Path to write a devnet manifest JSON.
    #[arg(long)]
    pub manifest: Option<PathBuf>,

    /// Log level for devnet process.
    #[arg(long, default_value = "info")]
    pub log_level: String,
}
