//! # Hanzo Crypto
//!
//! Modern post-quantum cryptography library with NIST-standardized algorithms.
//!
//! Pure Rust implementations for ARM compatibility (M1/M2/M3 Mac compatible).

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(unsafe_code)]

// Re-export post-quantum crypto directly from crates
pub use ml_kem;
pub use ml_dsa;
pub use pqcrypto_hqc as hqc;

// Re-export symmetric crypto
pub use blake3;
pub use chacha20poly1305;
pub use aes_gcm;

// Additional useful crypto
pub use argon2;
pub use x25519_dalek;
pub use ed25519_dalek;

// Common traits and utilities
pub use rand;
pub use rand_core;
pub use zeroize;

pub mod symmetric;
pub mod hash;
pub mod error;
pub mod prelude;

pub use error::{CryptoError, Result};

/// Common security levels for PQC
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// NIST Level 1 (128-bit)
    Level1,
    /// NIST Level 3 (192-bit)
    Level3,
    /// NIST Level 5 (256-bit)
    Level5,
}