//! E2E test infrastructure for saorsa-node.
//!
//! This module provides a complete testing framework for running E2E tests
//! against a local testnet of 25 saorsa nodes with optional EVM payment
//! verification via a local Anvil testnet.
//!
//! ## Architecture
//!
//! ```text
//! TestHarness
//!     ├── TestNetwork (25 nodes)
//!     │       ├── Nodes 0-2: Bootstrap
//!     │       └── Nodes 3-24: Regular
//!     ├── TestAnvil (EVM testnet)
//!     └── PaymentHelpers
//! ```
//!
//! ## Usage
//!
//! ```rust,no_run
//! use saorsa_node::tests::e2e::TestHarness;
//!
//! #[tokio::test]
//! async fn test_chunk_storage() {
//!     let harness = TestHarness::setup().await.unwrap();
//!
//!     // Store data via node 5
//!     let data = b"test data";
//!     let address = harness.node(5).unwrap().store(data).await.unwrap();
//!
//!     // Retrieve from node 20
//!     let retrieved = harness.node(20).unwrap().retrieve(&address).await.unwrap();
//!     assert_eq!(data, retrieved);
//!
//!     harness.teardown().await.unwrap();
//! }
//! ```

mod anvil;
mod data_types;
mod harness;
mod testnet;
mod testnet_data_ops;

#[cfg(test)]
mod integration_tests;

pub use anvil::TestAnvil;
pub use harness::TestHarness;
pub use testnet::{NetworkState, NodeState, TestNetwork, TestNetworkConfig, TestNode};
