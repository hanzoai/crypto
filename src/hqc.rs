//! # HQC (Hamming Quasi-Cyclic) Code-Based Cryptography
//!
//! Post-quantum code-based encryption scheme.

use pqcrypto_hqc::{hqc128, hqc192, hqc256};
use pqcrypto_traits::kem::{
    PublicKey as PqPublicKey,
    SecretKey as PqSecretKey,
    SharedSecret as PqSharedSecret,
    Ciphertext as PqCiphertext,
};
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::{CryptoError, Result, SecurityLevel};

/// HQC security level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HqcLevel {
    /// 128-bit security
    Hqc128,
    /// 192-bit security
    Hqc192,
    /// 256-bit security
    Hqc256,
}

impl From<SecurityLevel> for HqcLevel {
    fn from(level: SecurityLevel) -> Self {
        match level {
            SecurityLevel::Level1 => HqcLevel::Hqc128,
            SecurityLevel::Level3 => HqcLevel::Hqc192,
            SecurityLevel::Level5 => HqcLevel::Hqc256,
        }
    }
}

/// HQC public key
#[derive(Clone)]
pub struct PublicKey {
    level: HqcLevel,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: HqcLevel) -> Result<Self> {
        // Verify size based on level
        let expected_size = match level {
            HqcLevel::Hqc128 => hqc128::public_key_bytes(),
            HqcLevel::Hqc192 => hqc192::public_key_bytes(),
            HqcLevel::Hqc256 => hqc256::public_key_bytes(),
        };

        if bytes.len() != expected_size {
            return Err(CryptoError::InvalidKeyLength);
        }

        Ok(Self {
            level,
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Encapsulate a shared secret
    pub fn encapsulate<R>(&self, rng: &mut R) -> Result<(Vec<u8>, SharedSecret)>
    where
        R: CryptoRng + RngCore,
    {
        let mut seed = [0u8; 48];
        rng.fill_bytes(&mut seed);

        let (shared_secret, ciphertext) = match self.level {
            HqcLevel::Hqc128 => {
                let pk = hqc128::PublicKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let (ss, ct) = hqc128::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            },
            HqcLevel::Hqc192 => {
                let pk = hqc192::PublicKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let (ss, ct) = hqc192::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            },
            HqcLevel::Hqc256 => {
                let pk = hqc256::PublicKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let (ss, ct) = hqc256::encapsulate(&pk);
                (ss.as_bytes().to_vec(), ct.as_bytes().to_vec())
            },
        };

        Ok((ciphertext, SharedSecret { bytes: shared_secret }))
    }
}

/// HQC secret key
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretKey {
    level: HqcLevel,
    #[zeroize(skip)]
    bytes: Vec<u8>,
}

impl SecretKey {
    /// Create from bytes
    pub fn from_bytes(bytes: &[u8], level: HqcLevel) -> Result<Self> {
        let expected_size = match level {
            HqcLevel::Hqc128 => hqc128::secret_key_bytes(),
            HqcLevel::Hqc192 => hqc192::secret_key_bytes(),
            HqcLevel::Hqc256 => hqc256::secret_key_bytes(),
        };

        if bytes.len() != expected_size {
            return Err(CryptoError::InvalidKeyLength);
        }

        Ok(Self {
            level,
            bytes: bytes.to_vec(),
        })
    }

    /// Export to bytes (sensitive!)
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Decapsulate a ciphertext
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SharedSecret> {
        let shared_secret = match self.level {
            HqcLevel::Hqc128 => {
                let sk = hqc128::SecretKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let ct = hqc128::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::InvalidCiphertext)?;
                let ss = hqc128::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            },
            HqcLevel::Hqc192 => {
                let sk = hqc192::SecretKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let ct = hqc192::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::InvalidCiphertext)?;
                let ss = hqc192::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            },
            HqcLevel::Hqc256 => {
                let sk = hqc256::SecretKey::from_bytes(&self.bytes)
                    .map_err(|_| CryptoError::InvalidKey)?;
                let ct = hqc256::Ciphertext::from_bytes(ciphertext)
                    .map_err(|_| CryptoError::InvalidCiphertext)?;
                let ss = hqc256::decapsulate(&ct, &sk);
                ss.as_bytes().to_vec()
            },
        };

        Ok(SharedSecret { bytes: shared_secret })
    }
}

/// HQC key pair
#[derive(Clone, ZeroizeOnDrop)]
pub struct KeyPair {
    /// Public key
    pub public_key: PublicKey,
    /// Secret key
    #[zeroize(skip)]
    pub secret_key: SecretKey,
    /// Security level
    pub level: HqcLevel,
}

impl KeyPair {
    /// Generate a new HQC key pair
    pub fn generate<R>(rng: &mut R, level: HqcLevel) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        let (pk_bytes, sk_bytes) = match level {
            HqcLevel::Hqc128 => {
                let (pk, sk) = hqc128::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            },
            HqcLevel::Hqc192 => {
                let (pk, sk) = hqc192::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            },
            HqcLevel::Hqc256 => {
                let (pk, sk) = hqc256::keypair();
                (pk.as_bytes().to_vec(), sk.as_bytes().to_vec())
            },
        };

        Ok(Self {
            public_key: PublicKey { level, bytes: pk_bytes },
            secret_key: SecretKey { level, bytes: sk_bytes },
            level,
        })
    }

    /// Generate with default level (HQC-192)
    pub fn generate_default<R>(rng: &mut R) -> Result<Self>
    where
        R: CryptoRng + RngCore,
    {
        Self::generate(rng, HqcLevel::Hqc192)
    }
}

/// Shared secret from HQC
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Get the shared secret bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Run HQC self-tests
pub fn self_test() -> Result<()> {
    use rand::thread_rng;

    let mut rng = thread_rng();

    // Test all security levels
    for level in [HqcLevel::Hqc128, HqcLevel::Hqc192, HqcLevel::Hqc256] {
        // Generate key pair
        let keypair = KeyPair::generate(&mut rng, level)?;

        // Encapsulate
        let (ciphertext, secret1) = keypair.public_key.encapsulate(&mut rng)?;

        // Decapsulate
        let secret2 = keypair.secret_key.decapsulate(&ciphertext)?;

        // Verify shared secrets match
        if secret1.as_bytes() != secret2.as_bytes() {
            return Err(CryptoError::SelfTestFailed);
        }

        // Test serialization
        let pk = PublicKey::from_bytes(&keypair.public_key.to_bytes(), level)?;
        let sk = SecretKey::from_bytes(&keypair.secret_key.to_bytes(), level)?;

        // Verify restored keys work
        let (ct2, _) = pk.encapsulate(&mut rng)?;
        let _ = sk.decapsulate(&ct2)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_hqc_all_levels() {
        let mut rng = thread_rng();

        for level in [HqcLevel::Hqc128, HqcLevel::Hqc192, HqcLevel::Hqc256] {
            let keypair = KeyPair::generate(&mut rng, level).unwrap();
            let (ciphertext, secret1) = keypair.public_key.encapsulate(&mut rng).unwrap();
            let secret2 = keypair.secret_key.decapsulate(&ciphertext).unwrap();
            assert_eq!(secret1.as_bytes(), secret2.as_bytes());
        }
    }
}