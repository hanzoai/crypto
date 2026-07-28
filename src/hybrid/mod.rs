//! Hybrid classical-quantum cryptography
//!
//! This module provides hybrid cryptographic schemes that combine
//! classical algorithms with post-quantum algorithms for defense-in-depth.

use crate::{Result, Error};
use crate::pqc::{MlKem, MlDsa, SecurityLevel};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use ed25519_dalek::{SigningKey, Signature as Ed25519Signature, Signer, Verifier};
use rand::rngs::OsRng;
use sha3::{Sha3_256, Digest};

/// Hybrid key exchange combining X25519 and ML-KEM
pub struct HybridKeyExchange {
    ml_kem: MlKem,
}

impl HybridKeyExchange {
    /// Create a new hybrid key exchange with specified security level
    pub fn new(level: SecurityLevel) -> Self {
        HybridKeyExchange {
            ml_kem: MlKem::new(level),
        }
    }

    /// Generate hybrid keypair (X25519 + ML-KEM)
    pub fn generate_keypair(&self) -> Result<HybridKeypair> {
        // Generate X25519 keypair
        let x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let x25519_public = X25519PublicKey::from(&x25519_secret);

        // Generate ML-KEM keypair
        let (ml_kem_public, ml_kem_secret) = self.ml_kem.generate_keypair()?;

        Ok(HybridKeypair {
            x25519_public: x25519_public.as_bytes().to_vec(),
            x25519_secret: x25519_secret.as_bytes().to_vec(),
            ml_kem_public,
            ml_kem_secret,
        })
    }

    /// Perform hybrid key exchange (initiator side)
    pub fn exchange_initiator(
        &self,
        their_x25519_public: &[u8],
        their_ml_kem_public: &[u8],
    ) -> Result<HybridExchangeResult> {
        // X25519 exchange
        let our_x25519_secret = EphemeralSecret::random_from_rng(OsRng);
        let our_x25519_public = X25519PublicKey::from(&our_x25519_secret);

        let their_x25519_pk = X25519PublicKey::from(<[u8; 32]>::try_from(their_x25519_public)
            .map_err(|_| Error::Crypto("Invalid X25519 public key".to_string()))?);

        let x25519_shared = our_x25519_secret.diffie_hellman(&their_x25519_pk);

        // ML-KEM encapsulation
        let (ml_kem_ciphertext, ml_kem_shared) = self.ml_kem.encapsulate(their_ml_kem_public)?;

        // Combine shared secrets with KDF
        let combined = Self::combine_secrets(x25519_shared.as_bytes(), &ml_kem_shared)?;

        Ok(HybridExchangeResult {
            our_x25519_public: our_x25519_public.as_bytes().to_vec(),
            ml_kem_ciphertext,
            shared_secret: combined,
        })
    }

    /// Complete hybrid key exchange (responder side)
    pub fn exchange_responder(
        &self,
        our_x25519_secret: &[u8],
        their_x25519_public: &[u8],
        our_ml_kem_secret: &[u8],
        ml_kem_ciphertext: &[u8],
    ) -> Result<Vec<u8>> {
        // X25519 exchange
        let our_x25519_sk = <[u8; 32]>::try_from(our_x25519_secret)
            .map_err(|_| Error::Crypto("Invalid X25519 secret key".to_string()))?;
        let their_x25519_pk = X25519PublicKey::from(<[u8; 32]>::try_from(their_x25519_public)
            .map_err(|_| Error::Crypto("Invalid X25519 public key".to_string()))?);

        let x25519_shared = EphemeralSecret::from(our_x25519_sk)
            .diffie_hellman(&their_x25519_pk);

        // ML-KEM decapsulation
        let ml_kem_shared = self.ml_kem.decapsulate(ml_kem_ciphertext, our_ml_kem_secret)?;

        // Combine shared secrets
        Self::combine_secrets(x25519_shared.as_bytes(), &ml_kem_shared)
    }

    /// Combine two shared secrets using a KDF
    fn combine_secrets(classical: &[u8], post_quantum: &[u8]) -> Result<Vec<u8>> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"HANZO_HYBRID_KE_v1");
        hasher.update(classical);
        hasher.update(post_quantum);
        Ok(hasher.finalize().to_vec())
    }
}

/// Hybrid signature combining Ed25519 and ML-DSA
pub struct HybridSignature {
    ml_dsa: MlDsa,
}

impl HybridSignature {
    /// Create a new hybrid signature scheme with specified security level
    pub fn new(level: SecurityLevel) -> Self {
        HybridSignature {
            ml_dsa: MlDsa::new(level),
        }
    }

    /// Generate hybrid signing keypair (Ed25519 + ML-DSA)
    pub fn generate_keypair(&self) -> Result<HybridSigningKeypair> {
        // Generate Ed25519 keypair
        let ed25519_signing = SigningKey::generate(&mut OsRng);
        let ed25519_verifying = ed25519_signing.verifying_key();

        // Generate ML-DSA keypair
        let (ml_dsa_public, ml_dsa_secret) = self.ml_dsa.generate_keypair()?;

        Ok(HybridSigningKeypair {
            ed25519_public: ed25519_verifying.as_bytes().to_vec(),
            ed25519_secret: ed25519_signing.as_bytes().to_vec(),
            ml_dsa_public,
            ml_dsa_secret,
        })
    }

    /// Create hybrid signature
    pub fn sign(
        &self,
        message: &[u8],
        ed25519_secret: &[u8],
        ml_dsa_secret: &[u8],
    ) -> Result<Vec<u8>> {
        // Ed25519 signature
        let ed25519_sk = SigningKey::from_bytes(ed25519_secret.try_into()
            .map_err(|_| Error::Crypto("Invalid Ed25519 secret key".to_string()))?);
        let ed25519_sig = ed25519_sk.sign(message);

        // ML-DSA signature
        let ml_dsa_sig = self.ml_dsa.sign(message, ml_dsa_secret)?;

        // Combine signatures
        let mut combined = Vec::new();
        combined.extend_from_slice(ed25519_sig.to_bytes().as_ref());
        combined.extend_from_slice(&(ml_dsa_sig.len() as u32).to_le_bytes());
        combined.extend_from_slice(&ml_dsa_sig);

        Ok(combined)
    }

    /// Verify hybrid signature
    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        ed25519_public: &[u8],
        ml_dsa_public: &[u8],
    ) -> Result<bool> {
        if signature.len() < 68 {
            return Ok(false);
        }

        // Extract Ed25519 signature
        let ed25519_sig = Ed25519Signature::from_bytes(signature[..64].try_into()
            .map_err(|_| Error::Crypto("Invalid Ed25519 signature".to_string()))?);

        // Extract ML-DSA signature
        let ml_dsa_len = u32::from_le_bytes(signature[64..68].try_into()
            .map_err(|_| Error::Crypto("Invalid signature format".to_string()))?) as usize;

        if signature.len() != 68 + ml_dsa_len {
            return Ok(false);
        }

        let ml_dsa_sig = &signature[68..];

        // Verify Ed25519
        let ed25519_pk = ed25519_dalek::VerifyingKey::from_bytes(ed25519_public.try_into()
            .map_err(|_| Error::Crypto("Invalid Ed25519 public key".to_string()))?)?;

        if ed25519_pk.verify(message, &ed25519_sig).is_err() {
            return Ok(false);
        }

        // Verify ML-DSA
        self.ml_dsa.verify(message, ml_dsa_sig, ml_dsa_public)
    }
}

/// Hybrid keypair for key exchange
pub struct HybridKeypair {
    pub x25519_public: Vec<u8>,
    pub x25519_secret: Vec<u8>,
    pub ml_kem_public: Vec<u8>,
    pub ml_kem_secret: Vec<u8>,
}

/// Result of hybrid key exchange
pub struct HybridExchangeResult {
    pub our_x25519_public: Vec<u8>,
    pub ml_kem_ciphertext: Vec<u8>,
    pub shared_secret: Vec<u8>,
}

/// Hybrid keypair for signing
pub struct HybridSigningKeypair {
    pub ed25519_public: Vec<u8>,
    pub ed25519_secret: Vec<u8>,
    pub ml_dsa_public: Vec<u8>,
    pub ml_dsa_secret: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hybrid_key_exchange() {
        let hke = HybridKeyExchange::new(SecurityLevel::Level3);

        // Bob generates keypair
        let bob_keys = hke.generate_keypair().unwrap();

        // Alice performs exchange (initiator)
        let alice_result = hke.exchange_initiator(
            &bob_keys.x25519_public,
            &bob_keys.ml_kem_public,
        ).unwrap();

        // Bob completes exchange (responder)
        let bob_shared = hke.exchange_responder(
            &bob_keys.x25519_secret,
            &alice_result.our_x25519_public,
            &bob_keys.ml_kem_secret,
            &alice_result.ml_kem_ciphertext,
        ).unwrap();

        // Shared secrets should match
        assert_eq!(alice_result.shared_secret, bob_shared);
    }

    #[test]
    fn test_hybrid_signature() {
        let hsig = HybridSignature::new(SecurityLevel::Level3);
        let message = b"Hybrid crypto for quantum resistance";

        // Generate keypair
        let keys = hsig.generate_keypair().unwrap();

        // Sign message
        let signature = hsig.sign(
            message,
            &keys.ed25519_secret,
            &keys.ml_dsa_secret,
        ).unwrap();

        // Verify signature
        let is_valid = hsig.verify(
            message,
            &signature,
            &keys.ed25519_public,
            &keys.ml_dsa_public,
        ).unwrap();

        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let is_valid = hsig.verify(
            wrong_message,
            &signature,
            &keys.ed25519_public,
            &keys.ml_dsa_public,
        ).unwrap();

        assert!(!is_valid);
    }
}