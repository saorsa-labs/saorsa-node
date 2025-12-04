//! ML-DSA-65 key management utility for saorsa-node release signing.
//!
//! This utility provides:
//! - Keypair generation for release signing
//! - Binary signing with ML-DSA-65
//! - Signature verification
//!
//! Usage:
//!   saorsa-keygen generate [output-dir]    Generate a new keypair
//!   saorsa-keygen sign --key <key> --input <file> --output <sig>
//!   saorsa-keygen verify --key <key> --input <file> --signature <sig>

// This is a standalone CLI tool that exits on any error, so expect/unwrap is acceptable
#![allow(clippy::unwrap_used, clippy::expect_used)]

use clap::{Parser, Subcommand};
use saorsa_pqc::api::sig::{
    ml_dsa_65, MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature, MlDsaVariant,
};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process;

/// Signing context for domain separation (prevents cross-protocol attacks).
const SIGNING_CONTEXT: &[u8] = b"saorsa-node-release-v1";

#[derive(Parser)]
#[command(name = "saorsa-keygen")]
#[command(about = "ML-DSA-65 key management for saorsa-node releases")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ML-DSA-65 keypair
    Generate {
        /// Output directory for keys
        #[arg(default_value = ".")]
        output_dir: PathBuf,
    },
    /// Sign a file with ML-DSA-65
    Sign {
        /// Path to the secret key file
        #[arg(short, long)]
        key: PathBuf,
        /// Path to the file to sign
        #[arg(short, long)]
        input: PathBuf,
        /// Path to write the signature
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Verify a signature
    Verify {
        /// Path to the public key file
        #[arg(short, long)]
        key: PathBuf,
        /// Path to the file that was signed
        #[arg(short, long)]
        input: PathBuf,
        /// Path to the signature file
        #[arg(short, long)]
        signature: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate { output_dir } => generate_keypair(&output_dir),
        Commands::Sign { key, input, output } => sign_file(&key, &input, &output),
        Commands::Verify {
            key,
            input,
            signature,
        } => verify_signature(&key, &input, &signature),
    }
}

fn generate_keypair(output_dir: &PathBuf) {
    println!("ML-DSA-65 Keypair Generator for saorsa-node releases\n");

    // Create output directory if it doesn't exist
    fs::create_dir_all(output_dir).expect("Failed to create output directory");

    println!("Generating ML-DSA-65 keypair...");

    // Generate keypair
    let dsa = ml_dsa_65();
    let (public_key, secret_key) = dsa.generate_keypair().expect("Failed to generate keypair");

    let pk_bytes = public_key.to_bytes();
    let sk_bytes = secret_key.to_bytes();

    println!("  Public key size: {} bytes", pk_bytes.len());
    println!("  Secret key size: {} bytes", sk_bytes.len());

    // Save secret key to file (KEEP THIS SECURE!)
    let sk_path = output_dir.join("release-signing-key.secret");
    fs::write(&sk_path, sk_bytes).expect("Failed to write secret key");
    println!("\nSecret key saved to: {}", sk_path.display());
    println!("  WARNING: Keep this file secure! It's needed for signing releases.");

    // Save public key to file
    let pk_path = output_dir.join("release-signing-key.pub");
    fs::write(&pk_path, &pk_bytes).expect("Failed to write public key");
    println!("Public key saved to: {}", pk_path.display());

    // Generate Rust code for embedding
    let rust_code_path = output_dir.join("release_key_embed.rs");
    let mut rust_file = fs::File::create(&rust_code_path).expect("Failed to create Rust file");

    writeln!(
        rust_file,
        "/// Embedded release signing public key (ML-DSA-65)."
    )
    .unwrap();
    writeln!(rust_file, "///").unwrap();
    writeln!(
        rust_file,
        "/// This key is used to verify signatures on released binaries."
    )
    .unwrap();
    writeln!(
        rust_file,
        "/// The corresponding private key is held by authorized release signers."
    )
    .unwrap();
    writeln!(
        rust_file,
        "/// Generated: {}",
        chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")
    )
    .unwrap();
    writeln!(rust_file, "const RELEASE_SIGNING_KEY: &[u8] = &[").unwrap();

    // Write bytes in rows of 16 for readability
    for (i, byte) in pk_bytes.iter().enumerate() {
        if i % 16 == 0 {
            write!(rust_file, "    ").unwrap();
        }
        write!(rust_file, "0x{byte:02x},").unwrap();
        if i % 16 == 15 {
            writeln!(rust_file).unwrap();
        } else {
            write!(rust_file, " ").unwrap();
        }
    }

    // Handle last line if not complete
    if pk_bytes.len() % 16 != 0 {
        writeln!(rust_file).unwrap();
    }

    writeln!(rust_file, "];").unwrap();

    println!("Rust embed code saved to: {}", rust_code_path.display());

    // Also print to stdout for convenience
    println!("\n--- Rust code for signature.rs ---\n");
    println!("const RELEASE_SIGNING_KEY: &[u8] = &[");
    for (i, byte) in pk_bytes.iter().enumerate() {
        if i % 16 == 0 {
            print!("    ");
        }
        print!("0x{byte:02x},");
        if i % 16 == 15 {
            println!();
        } else {
            print!(" ");
        }
    }
    if pk_bytes.len() % 16 != 0 {
        println!();
    }
    println!("];");

    println!("\n--- End of Rust code ---");
    println!("\nDone! Copy the above code to src/upgrade/signature.rs");
}

fn sign_file(key_path: &PathBuf, input_path: &PathBuf, output_path: &PathBuf) {
    println!("Signing {} with ML-DSA-65...", input_path.display());

    // Load secret key
    let sk_bytes = fs::read(key_path).expect("Failed to read secret key");

    // Parse secret key
    let secret_key = MlDsaSecretKey::from_bytes(MlDsaVariant::MlDsa65, &sk_bytes)
        .expect("Failed to parse secret key");

    // Load file to sign
    let data = fs::read(input_path).expect("Failed to read input file");

    // Create DSA instance and sign with context
    let dsa = ml_dsa_65();
    let signature = dsa
        .sign_with_context(&secret_key, &data, SIGNING_CONTEXT)
        .expect("Failed to create signature");

    let sig_bytes = signature.to_bytes();

    // Write signature
    fs::write(output_path, &sig_bytes).expect("Failed to write signature");

    println!("Signature written to: {}", output_path.display());
    println!("  Signature size: {} bytes", sig_bytes.len());
}

fn verify_signature(key_path: &PathBuf, input_path: &PathBuf, sig_path: &PathBuf) {
    println!("Verifying signature for {}...", input_path.display());

    // Load public key
    let pk_bytes = fs::read(key_path).expect("Failed to read public key");

    // Parse public key
    let public_key = MlDsaPublicKey::from_bytes(MlDsaVariant::MlDsa65, &pk_bytes)
        .expect("Failed to parse public key");

    // Load file that was signed
    let data = fs::read(input_path).expect("Failed to read input file");

    // Load signature
    let sig_bytes = fs::read(sig_path).expect("Failed to read signature");

    // Parse signature
    let signature = MlDsaSignature::from_bytes(MlDsaVariant::MlDsa65, &sig_bytes)
        .expect("Failed to parse signature");

    // Create DSA instance and verify with context
    let dsa = ml_dsa_65();
    match dsa.verify_with_context(&public_key, &data, &signature, SIGNING_CONTEXT) {
        Ok(true) => {
            println!("Signature is VALID");
        }
        Ok(false) => {
            eprintln!("Signature is INVALID");
            process::exit(1);
        }
        Err(e) => {
            eprintln!("Signature verification error: {e}");
            process::exit(1);
        }
    }
}
