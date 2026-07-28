//! # Cryptographic Hashing
//!
//! BLAKE3 and SHA-3 hashing functions.

use blake3;

/// BLAKE3 hashing (256-bit output by default)
pub mod blake {
    use super::*;

    /// Hash data with BLAKE3
    pub fn hash(data: &[u8]) -> [u8; 32] {
        *blake3::hash(data).as_bytes()
    }

    /// Create a BLAKE3 hasher for incremental hashing
    pub fn hasher() -> blake3::Hasher {
        blake3::Hasher::new()
    }

    /// Keyed BLAKE3 hashing (MAC)
    pub fn keyed_hash(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
        *blake3::keyed_hash(key, data).as_bytes()
    }

    /// Derive key material with BLAKE3
    pub fn derive_key(context: &str, key_material: &[u8]) -> [u8; 32] {
        blake3::derive_key(context, key_material)
    }
}

/// SHA-3 hashing functions
pub mod sha3_hash {

    /// SHA3-256 hash
    pub fn sha3_256(data: &[u8]) -> [u8; 32] {
        use ::sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// SHA3-384 hash
    pub fn sha3_384(data: &[u8]) -> [u8; 48] {
        use ::sha3::{Digest, Sha3_384};
        let mut hasher = Sha3_384::new();
        hasher.update(data);
        hasher.finalize().into()
    }

    /// SHA3-512 hash
    pub fn sha3_512(data: &[u8]) -> [u8; 64] {
        use ::sha3::{Digest, Sha3_512};
        let mut hasher = Sha3_512::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

/// Quantum-resistant fingerprinting
pub fn quantum_fingerprint(data: &[u8]) -> Vec<u8> {
    // Combine BLAKE3 with domain separation
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"QuDAG-FINGERPRINT-v1");
    hasher.update(data);
    hasher.finalize().as_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3() {
        let data = b"Hello, BLAKE3!";
        let hash1 = blake::hash(data);
        let hash2 = blake::hash(data);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_blake3_keyed() {
        let key = [0x42; 32];
        let data = b"Hello, keyed BLAKE3!";
        let hash = blake::keyed_hash(&key, data);
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_sha3() {
        let data = b"Hello, SHA-3!";

        let hash256 = sha3_hash::sha3_256(data);
        assert_eq!(hash256.len(), 32);

        let hash384 = sha3_hash::sha3_384(data);
        assert_eq!(hash384.len(), 48);

        let hash512 = sha3_hash::sha3_512(data);
        assert_eq!(hash512.len(), 64);
    }

    #[test]
    fn test_quantum_fingerprint() {
        let data = b"Test fingerprint data";
        let fingerprint = quantum_fingerprint(data);
        assert_eq!(fingerprint.len(), 32);
    }
}