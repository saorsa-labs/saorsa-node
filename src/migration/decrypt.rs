//! AES-256-GCM-SIV decryption for ant-node record data.
//!
//! ant-node uses AES-256-GCM-SIV with HKDF-SHA256 key derivation to encrypt
//! stored records. This module provides the decryption functionality needed
//! to migrate data from ant-node to saorsa-node.
//!
//! ## Record Encryption Format
//!
//! ant-node records are encrypted with:
//! - Algorithm: AES-256-GCM-SIV (AEAD)
//! - Key derivation: HKDF-SHA256
//! - Nonce: 12 bytes, typically derived or stored with the record
//!
//! ## Security Notes
//!
//! This is read-only decryption for migration purposes. The decrypted data
//! is immediately re-encrypted using saorsa-node's quantum-resistant
//! cryptography before being stored.

use aes_gcm_siv::{
    aead::{Aead, KeyInit},
    Aes256GcmSiv, Nonce,
};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{Error, Result};

/// Nonce size for AES-256-GCM-SIV (12 bytes).
pub const NONCE_SIZE: usize = 12;

/// Key size for AES-256 (32 bytes).
pub const KEY_SIZE: usize = 32;

/// Decrypt ant-node record data using AES-256-GCM-SIV.
///
/// # Arguments
///
/// * `encrypted` - The encrypted data (ciphertext + tag)
/// * `key` - The 256-bit decryption key
/// * `nonce` - The 12-byte nonce
///
/// # Errors
///
/// Returns an error if:
/// - The key is not 32 bytes
/// - The nonce is not 12 bytes
/// - Decryption fails (wrong key, corrupted data, or authentication failure)
pub fn decrypt_record(encrypted: &[u8], key: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if key.len() != KEY_SIZE {
        return Err(Error::Migration(format!(
            "Invalid key size: expected {KEY_SIZE}, got {}",
            key.len()
        )));
    }

    if nonce.len() != NONCE_SIZE {
        return Err(Error::Migration(format!(
            "Invalid nonce size: expected {NONCE_SIZE}, got {}",
            nonce.len()
        )));
    }

    let cipher = Aes256GcmSiv::new_from_slice(key)
        .map_err(|e| Error::Migration(format!("Failed to create cipher: {e}")))?;

    let nonce = Nonce::from_slice(nonce);

    cipher
        .decrypt(nonce, encrypted)
        .map_err(|e| Error::Migration(format!("Decryption failed: {e}")))
}

/// Derive an encryption key from a master key using HKDF-SHA256.
///
/// ant-node uses HKDF to derive record-specific keys from a master secret.
///
/// # Arguments
///
/// * `master_key` - The master secret (input keying material)
/// * `salt` - Optional salt value
/// * `info` - Context and application-specific info
/// * `output` - Buffer to write the derived key (must be `KEY_SIZE` bytes)
///
/// # Errors
///
/// Returns an error if:
/// - The output buffer is not `KEY_SIZE` bytes
/// - HKDF expansion fails
pub fn derive_key(
    master_key: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    if output.len() != KEY_SIZE {
        return Err(Error::Migration(format!(
            "Invalid output size: expected {KEY_SIZE}, got {}",
            output.len()
        )));
    }

    let hkdf = Hkdf::<Sha256>::new(salt, master_key);

    hkdf.expand(info, output)
        .map_err(|e| Error::Migration(format!("HKDF expansion failed: {e}")))?;

    Ok(())
}

/// Derive a record-specific key from a master key and `XorName`.
///
/// This matches ant-node's key derivation pattern for stored records.
///
/// # Arguments
///
/// * `master_key` - The node's master secret
/// * `xorname` - The 32-byte `XorName` of the record
///
/// # Returns
///
/// The derived 32-byte AES-256 key.
///
/// # Errors
///
/// Returns an error if key derivation fails.
pub fn derive_record_key(master_key: &[u8], xorname: &[u8; 32]) -> Result<[u8; KEY_SIZE]> {
    let mut key = [0u8; KEY_SIZE];
    derive_key(
        master_key,
        Some(xorname),
        b"ant-node-record-encryption",
        &mut key,
    )?;
    Ok(key)
}

/// Extract nonce from encrypted record format.
///
/// ant-node records typically store the nonce at the start of the encrypted data.
/// Format: [nonce (12 bytes)][ciphertext + tag]
///
/// # Arguments
///
/// * `data` - The full encrypted record data
///
/// # Returns
///
/// A tuple of (nonce slice, ciphertext + tag slice).
///
/// # Errors
///
/// Returns an error if the data is too short to contain a nonce.
pub fn extract_nonce(data: &[u8]) -> Result<(&[u8], &[u8])> {
    if data.len() < NONCE_SIZE {
        return Err(Error::Migration(format!(
            "Data too short to contain nonce: {} bytes (need at least {NONCE_SIZE})",
            data.len()
        )));
    }

    let (nonce, ciphertext) = data.split_at(NONCE_SIZE);
    Ok((nonce, ciphertext))
}

/// Decrypt an ant-node record with embedded nonce.
///
/// This is a convenience function that extracts the nonce and decrypts in one step.
///
/// # Arguments
///
/// * `data` - The encrypted record with embedded nonce: `[nonce][ciphertext+tag]`
/// * `key` - The 256-bit decryption key
///
/// # Errors
///
/// Returns an error if extraction or decryption fails.
pub fn decrypt_with_embedded_nonce(data: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let (nonce, ciphertext) = extract_nonce(data)?;
    decrypt_record(ciphertext, key, nonce)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
mod tests {
    use super::*;
    use aes_gcm_siv::aead::OsRng;
    use aes_gcm_siv::{AeadCore, KeyInit};

    /// Test 1: Basic encryption/decryption roundtrip
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);

        let plaintext = b"test data for encryption";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let decrypted = decrypt_record(&ciphertext, key.as_slice(), nonce.as_slice()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test 2: Wrong key fails decryption
    #[test]
    fn test_wrong_key_fails() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let wrong_key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);

        let plaintext = b"test data";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let result = decrypt_record(&ciphertext, wrong_key.as_slice(), nonce.as_slice());
        assert!(result.is_err());
    }

    /// Test 3: Wrong nonce fails decryption
    #[test]
    fn test_wrong_nonce_fails() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);
        let wrong_nonce = Aes256GcmSiv::generate_nonce(OsRng);

        let plaintext = b"test data";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let result = decrypt_record(&ciphertext, key.as_slice(), wrong_nonce.as_slice());
        assert!(result.is_err());
    }

    /// Test 4: Invalid key size rejected
    #[test]
    fn test_invalid_key_size() {
        let short_key = [0u8; 16]; // Should be 32
        let nonce = [0u8; NONCE_SIZE];
        let ciphertext = [0u8; 32];

        let result = decrypt_record(&ciphertext, &short_key, &nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("key size"));
    }

    /// Test 5: Invalid nonce size rejected
    #[test]
    fn test_invalid_nonce_size() {
        let key = [0u8; KEY_SIZE];
        let short_nonce = [0u8; 8]; // Should be 12
        let ciphertext = [0u8; 32];

        let result = decrypt_record(&ciphertext, &key, &short_nonce);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("nonce size"));
    }

    /// Test 6: HKDF key derivation
    #[test]
    fn test_hkdf_key_derivation() {
        let master = b"master secret key material";
        let salt = b"optional salt";
        let info = b"context info";

        let mut key1 = [0u8; KEY_SIZE];
        let mut key2 = [0u8; KEY_SIZE];

        derive_key(master, Some(salt), info, &mut key1).unwrap();
        derive_key(master, Some(salt), info, &mut key2).unwrap();

        // Same inputs should produce same key
        assert_eq!(key1, key2);

        // Different info should produce different key
        let mut key3 = [0u8; KEY_SIZE];
        derive_key(master, Some(salt), b"different info", &mut key3).unwrap();
        assert_ne!(key1, key3);
    }

    /// Test 7: Record key derivation
    #[test]
    fn test_derive_record_key() {
        let master = b"node master secret";
        let xorname = [0xABu8; 32];

        let key1 = derive_record_key(master, &xorname).unwrap();
        let key2 = derive_record_key(master, &xorname).unwrap();

        // Deterministic
        assert_eq!(key1, key2);

        // Different XorName = different key
        let other_xorname = [0xCDu8; 32];
        let key3 = derive_record_key(master, &other_xorname).unwrap();
        assert_ne!(key1, key3);
    }

    /// Test 8: Extract nonce from data
    #[test]
    fn test_extract_nonce() {
        let nonce = [1u8; NONCE_SIZE];
        let ciphertext = b"encrypted data here";

        let mut data = Vec::new();
        data.extend_from_slice(&nonce);
        data.extend_from_slice(ciphertext);

        let (extracted_nonce, extracted_ciphertext) = extract_nonce(&data).unwrap();
        assert_eq!(extracted_nonce, &nonce);
        assert_eq!(extracted_ciphertext, ciphertext);
    }

    /// Test 9: Extract nonce fails with short data
    #[test]
    fn test_extract_nonce_too_short() {
        let short_data = [0u8; 8]; // Less than NONCE_SIZE
        let result = extract_nonce(&short_data);
        assert!(result.is_err());
    }

    /// Test 10: Decrypt with embedded nonce
    #[test]
    fn test_decrypt_with_embedded_nonce() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);

        let plaintext = b"data with embedded nonce";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        // Combine nonce + ciphertext
        let mut combined = Vec::new();
        combined.extend_from_slice(nonce.as_slice());
        combined.extend_from_slice(&ciphertext);

        let decrypted = decrypt_with_embedded_nonce(&combined, key.as_slice()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test 11: Empty plaintext
    #[test]
    fn test_empty_plaintext() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);

        let plaintext = b"";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let decrypted = decrypt_record(&ciphertext, key.as_slice(), nonce.as_slice()).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Test 12: Large data
    #[test]
    fn test_large_data() {
        let key = Aes256GcmSiv::generate_key(OsRng);
        let cipher = Aes256GcmSiv::new(&key);
        let nonce = Aes256GcmSiv::generate_nonce(OsRng);

        // 1MB of data
        let plaintext: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();

        let decrypted = decrypt_record(&ciphertext, key.as_slice(), nonce.as_slice()).unwrap();
        assert_eq!(decrypted, plaintext);
    }
}
