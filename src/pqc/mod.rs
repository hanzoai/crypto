//! Post-quantum cryptographic algorithms
//!
//! This module implements NIST-standardized post-quantum algorithms:
//! - ML-KEM (FIPS 203) - formerly Kyber
//! - ML-DSA (FIPS 204) - formerly Dilithium
//! - SLH-DSA (FIPS 205) - formerly SPHINCS+

pub mod ml_kem;
pub mod ml_dsa;
pub mod slh_dsa;

use crate::Result;

/// Security levels for post-quantum algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityLevel {
    /// 128-bit security (Level 1)
    Level1,
    /// 192-bit security (Level 3)
    Level3,
    /// 256-bit security (Level 5)
    Level5,
}

/// Post-quantum key encapsulation mechanism trait
pub trait KeyEncapsulation {
    /// Generate a key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Encapsulate a shared secret
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Decapsulate a shared secret
    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>;

    /// Get the security level
    fn security_level(&self) -> SecurityLevel;
}

/// Post-quantum digital signature trait
pub trait DigitalSignature {
    /// Generate a signing key pair
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)>;

    /// Sign a message
    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>>;

    /// Verify a signature
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool>;

    /// Get the security level
    fn security_level(&self) -> SecurityLevel;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert_ne!(SecurityLevel::Level1, SecurityLevel::Level3);
        assert_ne!(SecurityLevel::Level3, SecurityLevel::Level5);
    }
}