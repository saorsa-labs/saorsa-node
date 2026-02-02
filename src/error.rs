//! Error types for saorsa-node.

use thiserror::Error;

/// Result type alias using the crate's Error type.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in saorsa-node.
#[derive(Error, Debug)]
pub enum Error {
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Node startup error.
    #[error("node startup failed: {0}")]
    Startup(String),

    /// Network error from saorsa-core.
    #[error("network error: {0}")]
    Network(String),

    /// Storage error.
    #[error("storage error: {0}")]
    Storage(String),

    /// Payment error.
    #[error("payment error: {0}")]
    Payment(String),

    /// Upgrade error.
    #[error("upgrade error: {0}")]
    Upgrade(String),

    /// Cryptographic error.
    #[error("crypto error: {0}")]
    Crypto(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Protocol error.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Invalid chunk error.
    #[error("invalid chunk: {0}")]
    InvalidChunk(String),

    /// Node is shutting down.
    #[error("node is shutting down")]
    ShuttingDown,
}
