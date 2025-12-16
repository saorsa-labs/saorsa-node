//! Build script for saorsa-node.
//!
//! Emits compile-time warnings about attestation security configuration.

fn main() {
    // Rerun if feature configuration changes
    println!("cargo:rerun-if-changed=build.rs");

    // Emit warnings about attestation feature configuration
    emit_attestation_warnings();
}

/// Emit compile-time warnings about attestation security implications.
fn emit_attestation_warnings() {
    // Check if zkvm-prover is enabled (best security)
    #[cfg(feature = "zkvm-prover")]
    {
        println!("cargo:warning=attestation: STARK verification enabled (post-quantum secure)");
    }

    // Check if only Groth16 is enabled (not PQ-secure)
    #[cfg(all(feature = "zkvm-verifier-groth16", not(feature = "zkvm-prover")))]
    {
        println!(
            "cargo:warning=SECURITY WARNING: Groth16 verification is NOT post-quantum secure. \
             Consider using zkvm-prover feature for production deployments."
        );
    }

    // No verification feature enabled - DANGER
    #[cfg(not(any(feature = "zkvm-prover", feature = "zkvm-verifier-groth16")))]
    {
        println!("cargo:warning=SECURITY WARNING: No attestation verification feature enabled!");
        println!(
            "cargo:warning=If you enable attestation, proofs will use mock verification \
             with NO CRYPTOGRAPHIC SECURITY."
        );
        println!("cargo:warning=For production: cargo build --features zkvm-prover");
    }
}
