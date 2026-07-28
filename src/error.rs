//! # Error Types

use thiserror::Error;

/// Cryptographic errors
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid ciphertext")]
    InvalidCiphertext,

    #[error("Invalid input")]
    InvalidInput,

    #[error("Invalid key")]
    InvalidKey,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Signing failed")]
    SigningFailed,

    #[error("Verification failed")]
    VerificationFailed,

    #[error("Key generation failed")]
    KeyGenerationFailed,

    #[error("Encapsulation failed")]
    EncapsulationFailed,

    #[error("Decapsulation failed")]
    DecapsulationFailed,

    #[error("Self-test failed")]
    SelfTestFailed,

    #[error("Not implemented")]
    NotImplemented,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// Result type for crypto operations
pub type Result<T> = std::result::Result<T, CryptoError>;