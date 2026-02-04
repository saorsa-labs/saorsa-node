//! CLI definition for saorsa-client.

use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

/// Client CLI for chunk operations.
#[derive(Parser, Debug)]
#[command(name = "saorsa-client")]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Bootstrap peer addresses.
    #[arg(long, short)]
    pub bootstrap: Vec<SocketAddr>,

    /// Path to devnet manifest JSON (output of saorsa-devnet).
    #[arg(long)]
    pub devnet_manifest: Option<PathBuf>,

    /// Timeout for network operations (seconds).
    #[arg(long, default_value_t = 30)]
    pub timeout_secs: u64,

    /// Log level for client process.
    #[arg(long, default_value = "info")]
    pub log_level: String,

    /// Command to run.
    #[command(subcommand)]
    pub command: ClientCommand,
}

/// Client commands.
#[derive(Subcommand, Debug)]
pub enum ClientCommand {
    /// Put a chunk. Reads from --file or stdin.
    Put {
        /// Input file (defaults to stdin if omitted).
        #[arg(long)]
        file: Option<PathBuf>,
    },
    /// Get a chunk. Writes to --out or stdout.
    Get {
        /// Hex-encoded chunk address (64 hex chars).
        address: String,
        /// Output file (defaults to stdout if omitted).
        #[arg(long)]
        out: Option<PathBuf>,
    },
}
