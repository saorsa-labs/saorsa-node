//! Shared browser-client discovery types.
//!
//! These types describe the public read and paid immutable-write capabilities
//! exposed by browser-enabled nodes. Wallet secrets never form part of these
//! records: browsers sign EVM transactions locally and send only payment
//! receipts to nodes.

pub use saorsa_webrtc::{BrowserEndpoint, BrowserPaymentNetwork, WebRtcDirectEndpoint};
use serde::{Deserialize, Serialize};

/// Version of the local browser bootstrap manifest.
pub const BROWSER_MANIFEST_VERSION: u16 = 5;

/// A bootstrap node that a browser can authenticate and contact directly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserBootstrapNode {
    /// Self-contained browser endpoint for this node.
    #[serde(flatten)]
    pub endpoint: BrowserEndpoint,
}

/// Metadata for immutable content published into a browser-enabled devnet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserPublicFile {
    /// Human-readable filename suggested to the browser.
    pub name: String,
    /// Address of the publicly stored `MessagePack` `DataMap`.
    pub address: String,
    /// Plaintext content length in bytes.
    pub size: usize,
    /// MIME type used by the browser when saving the content.
    pub content_type: String,
    /// BLAKE3 hash of the fully reconstructed plaintext file.
    pub blake3: String,
    /// Size of the publicly stored `MessagePack` `DataMap` chunk.
    pub data_map_size: usize,
    /// Resolved root `DataMap` used to reconstruct the file.
    pub chunks: Vec<BrowserChunkInfo>,
    /// Minimum number of devnet nodes that admitted every required record.
    pub replicas: usize,
}

/// One resolved self-encryption chunk descriptor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserChunkInfo {
    /// Zero-based plaintext order.
    pub index: usize,
    /// Address of the encrypted chunk stored by nodes.
    pub dst_hash: String,
    /// BLAKE3 hash of the plaintext chunk and self-encryption key input.
    pub src_hash: String,
    /// Expected plaintext chunk size.
    pub src_size: usize,
}

pub(crate) fn browser_payment_network(network: &evmlib::Network) -> BrowserPaymentNetwork {
    BrowserPaymentNetwork {
        rpc_url: network.rpc_url().to_string(),
        payment_token_address: format!("{:?}", network.payment_token_address()),
        payment_vault_address: format!("{:?}", network.payment_vault_address()),
    }
}

/// Local-devnet handoff consumed by the browser application.
///
/// This manifest is intentionally a local testnet bootstrap artifact. The
/// production design replaces it with the ML-DSA-signed endpoint records from
/// ADR-0009.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserDevnetManifest {
    /// Manifest schema version.
    pub version: u16,
    /// Opaque identifier that distinguishes concurrent local devnets.
    pub network_id: String,
    /// Creation time in RFC 3339 form.
    pub created_at: String,
    /// Direct node endpoints available as initial browser contacts.
    pub endpoints: Vec<BrowserBootstrapNode>,
    /// Public payment contracts and RPC used by browser uploads.
    pub payment: BrowserPaymentNetwork,
    /// Immutable files published when the devnet started.
    pub files: Vec<BrowserPublicFile>,
}

impl BrowserDevnetManifest {
    /// Construct a versioned local browser manifest.
    #[must_use]
    pub fn new(
        network_id: String,
        created_at: String,
        endpoints: Vec<BrowserBootstrapNode>,
        payment: BrowserPaymentNetwork,
        files: Vec<BrowserPublicFile>,
    ) -> Self {
        Self {
            version: BROWSER_MANIFEST_VERSION,
            network_id,
            created_at,
            endpoints,
            payment,
            files,
        }
    }
}
