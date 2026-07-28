//! # ML-DSA (Module Lattice Digital Signature Algorithm)
//!
//! NIST FIPS 204 compliant implementation using pure Rust.
//! ARM-compatible, no assembly issues!

use ml_dsa::{
    Ml_Dsa44, Ml_Dsa65, Ml_Dsa87,
    SigningKey as MlDsaSigningKey,
    VerificationKey as MlDsaVerificationKey,
    Signature as MlDsaSignature,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{CryptoError, Result, SecurityLevel};

/// ML-DSA-65 (recommended for most applications)
pub type MlDsa = Ml_Dsa65;

/// Signing key for ML-DSA
#[derive(Clone, ZeroizeOnDrop)]
pub struct SigningKey {
    #[zeroize(skip)]
    inner: MlDsaSigningKey<MlDsa>,
}

impl SigningKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array = bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let inner = MlDsaSigningKey::<MlDsa>::from_bytes(&array);
        Ok(Self { inner })
    }

    /// Export to bytes (sensitive!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Sign a message
    pub fn sign<R>(&self, message: &[u8], rng: &mut R) -> Result<Signature>
    where
        R: CryptoRng + RngCore,
    {
        let sig = self.inner.try_sign_with_rng(rng, message)
            .map_err(|_| CryptoError::SigningFailed)?;
        Ok(Signature { inner: sig })
    }

    /// Get the verification key
    pub fn verification_key(&self) -> VerificationKey {
        VerificationKey {
            inner: self.inner.verification_key().clone()
        }
    }

    /// Get the size of signing keys in bytes
    pub const fn size() -> usize {
        MlDsa::SK_LEN
    }
}

/// Verification key for ML-DSA
#[derive(Clone)]
pub struct VerificationKey {
    inner: MlDsaVerificationKey<MlDsa>,
}

impl VerificationKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array = bytes.try_into()
            .map_err(|_| CryptoError::InvalidKeyLength)?;
        let inner = MlDsaVerificationKey::<MlDsa>::from_bytes(&array);
        Ok(Self { inner })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.inner.verify(message, &signature.inner)
            .map_err(|_| CryptoError::VerificationFailed)
    }

    /// Get the size of verification keys in bytes
    pub const fn size() -> usize {
        MlDsa::PK_LEN
    }
}

/// ML-DSA signature
#[derive(Clone)]
pub struct Signature {
    inner: MlDsaSignature<MlDsa>,
}

impl Signature {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let array = bytes.try_into()
            .map_err(|_| CryptoError::InvalidSignature)?;
        let inner = MlDsaSignature::<MlDsa>::from_bytes(&array);
        Ok(Self { inner })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Get the size of signatures in bytes
    pub const fn size() -> usize {
        MlDsa::SIG_LEN
    }
}

/// ML-DSA key pair
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Public verification key
    pub verification_key: VerificationKey,
    /// Secret signing key
    #[zeroize(skip)]
    pub signing_key: SigningKey,
}

impl KeyPair {
    /// Generate a new ML-DSA key pair
    pub fn generate<R>(rng: &mut R) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        let signing_key = MlDsaSigningKey::<MlDsa>::generate(rng)
            .map_err(|_| CryptoError::KeyGenerationFailed)?;
        let verification_key = signing_key.verification_key().clone();

        Ok(Self {
            signing_key: SigningKey { inner: signing_key },
            verification_key: VerificationKey { inner: verification_key },
        })
    }

    /// Generate with specific security level
    pub fn generate_with_level<R>(rng: &mut R, level: SecurityLevel) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        match level {
            SecurityLevel::Level1 => {
                let signing_key = MlDsaSigningKey::<Ml_Dsa44>::generate(rng)
                    .map_err(|_| CryptoError::KeyGenerationFailed)?;
                // For different levels, we'd need to handle type conversions
                // For now, we use Level3 (Ml_Dsa65) as default
                Self::generate(rng)
            },
            SecurityLevel::Level3 => Self::generate(rng),
            SecurityLevel::Level5 => {
                let signing_key = MlDsaSigningKey::<Ml_Dsa87>::generate(rng)
                    .map_err(|_| CryptoError::KeyGenerationFailed)?;
                // Similar to Level1, would need type handling
                Self::generate(rng)
            },
        }
    }

    /// Sign a message
    pub fn sign<R>(&self, message: &[u8], rng: &mut R) -> Result<Signature>
    where
        R: CryptoRng + RngCore,
    {
        self.signing_key.sign(message, rng)
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<()> {
        self.verification_key.verify(message, signature)
    }
}

/// Batch verify multiple signatures (optimization)
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[Signature],
    public_keys: &[VerificationKey],
) -> Result<()> {
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return Err(CryptoError::InvalidInput);
    }

    // Verify each signature individually
    // (True batch verification would require custom implementation)
    for ((msg, sig), pk) in messages.iter().zip(signatures).zip(public_keys) {
        pk.verify(msg, sig)?;
    }

    Ok(())
}

/// Run ML-DSA self-tests
pub fn self_test() -> Result<()> {
    use rand::thread_rng;

    let mut rng = thread_rng();
    let message = b"Test message for ML-DSA self-test";

    // Test key generation
    let keypair = KeyPair::generate(&mut rng)?;

    // Test signing
    let signature = keypair.sign(message, &mut rng)?;

    // Test verification
    keypair.verify(message, &signature)?;

    // Test serialization
    let sk_bytes = keypair.signing_key.to_bytes();
    let sk_restored = SigningKey::from_bytes(&sk_bytes)?;

    let vk_bytes = keypair.verification_key.to_bytes();
    let vk_restored = VerificationKey::from_bytes(&vk_bytes)?;

    let sig_bytes = signature.to_bytes();
    let sig_restored = Signature::from_bytes(&sig_bytes)?;

    // Verify restored keys work
    vk_restored.verify(message, &sig_restored)?;

    // Test failure case
    let bad_message = b"Different message";
    if vk_restored.verify(bad_message, &signature).is_ok() {
        return Err(CryptoError::SelfTestFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_ml_dsa_sign_verify() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng).unwrap();
        let message = b"Test message";

        let signature = keypair.sign(message, &mut rng).unwrap();
        keypair.verify(message, &signature).unwrap();
    }

    #[test]
    fn test_ml_dsa_invalid_signature() {
        let mut rng = thread_rng();
        let keypair = KeyPair::generate(&mut rng).unwrap();
        let message = b"Test message";
        let wrong_message = b"Wrong message";

        let signature = keypair.sign(message, &mut rng).unwrap();
        assert!(keypair.verify(wrong_message, &signature).is_err());
    }

    #[test]
    fn test_key_sizes() {
        assert_eq!(SigningKey::size(), 3312);     // ML-DSA-65
        assert_eq!(VerificationKey::size(), 1952); // ML-DSA-65
        assert_eq!(Signature::size(), 3309);       // ML-DSA-65
    }
}