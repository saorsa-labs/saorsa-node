//! ANT protocol implementation for the saorsa network.
//!
//! This module implements the wire protocol for storing and retrieving
//! data on the saorsa network, compatible with the autonomi network protocol.
//!
//! # Data Types
//!
//! The ANT protocol supports multiple data types:
//!
//! - **Chunk**: Immutable, content-addressed data (hash == address)
//! - *Scratchpad*: Mutable, owner-indexed data (planned)
//! - *Pointer*: Lightweight mutable references (planned)
//! - *`GraphEntry`*: DAG entries with parent links (planned)
//!
//! # Protocol Overview
//!
//! The protocol uses postcard serialization for compact, fast encoding.
//! Each data type has its own message types for PUT/GET operations.
//!
//! ## Chunk Messages
//!
//! - `ChunkPutRequest` / `ChunkPutResponse` - Store chunks
//! - `ChunkGetRequest` / `ChunkGetResponse` - Retrieve chunks
//! - `ChunkQuoteRequest` / `ChunkQuoteResponse` - Request storage quotes
//!
//! ## Payment Flow
//!
//! 1. Client requests a quote via `ChunkQuoteRequest`
//! 2. Node returns signed `PaymentQuote` in `ChunkQuoteResponse`
//! 3. Client pays on Arbitrum via `PaymentVault.payForQuotes()`
//! 4. Client sends `ChunkPutRequest` with `payment_proof`
//! 5. Node verifies payment and stores chunk
//!
//! # Example
//!
//! ```rust,ignore
//! use saorsa_node::ant_protocol::{ChunkMessage, ChunkPutRequest, ChunkGetRequest};
//!
//! // Create a PUT request
//! let address = compute_address(&data);
//! let request = ChunkPutRequest::with_payment(address, data, payment_proof);
//! let message = ChunkMessage::PutRequest(request);
//! let bytes = message.encode()?;
//!
//! // Decode a response
//! let response = ChunkMessage::decode(&response_bytes)?;
//! ```

pub mod chunk;

// Re-export chunk types for convenience
pub use chunk::{
    ChunkGetRequest, ChunkGetResponse, ChunkMessage, ChunkMessageBody, ChunkPutRequest,
    ChunkPutResponse, ChunkQuoteRequest, ChunkQuoteResponse, ProtocolError, XorName,
    CHUNK_PROTOCOL_ID, DATA_TYPE_CHUNK, MAX_CHUNK_SIZE, PROTOCOL_VERSION,
};
