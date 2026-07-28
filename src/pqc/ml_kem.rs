//! ML-KEM (Module-Lattice Key Encapsulation Mechanism) implementation
//! FIPS 203 compliant - formerly known as Kyber

use ml_kem::{MlKem512, MlKem768, MlKem1024};
use ml_kem::{EncapsulationKey, DecapsulationKey, Ciphertext, SharedSecret};
use rand::rngs::OsRng;
use crate::{Result, Error};
use super::{KeyEncapsulation, SecurityLevel};

/// ML-KEM implementation with configurable security level
pub struct MlKem {
    level: SecurityLevel,
}

impl MlKem {
    /// Create a new ML-KEM instance with specified security level
    pub fn new(level: SecurityLevel) -> Self {
        MlKem { level }
    }

    /// Generate ML-KEM-512 keypair (128-bit security)
    pub fn generate_512() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem512::generate(&mut OsRng);
        Ok((ek.as_bytes().to_vec(), dk.as_bytes().to_vec()))
    }

    /// Generate ML-KEM-768 keypair (192-bit security)
    pub fn generate_768() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem768::generate(&mut OsRng);
        Ok((ek.as_bytes().to_vec(), dk.as_bytes().to_vec()))
    }

    /// Generate ML-KEM-1024 keypair (256-bit security)
    pub fn generate_1024() -> Result<(Vec<u8>, Vec<u8>)> {
        let (dk, ek) = MlKem1024::generate(&mut OsRng);
        Ok((ek.as_bytes().to_vec(), dk.as_bytes().to_vec()))
    }
}

impl KeyEncapsulation for MlKem {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.level {
            SecurityLevel::Level1 => Self::generate_512(),
            SecurityLevel::Level3 => Self::generate_768(),
            SecurityLevel::Level5 => Self::generate_1024(),
        }
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.level {
            SecurityLevel::Level1 => {
                let ek = EncapsulationKey::<MlKem512>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-512 public key".to_string()))?);
                let (ct, ss) = ek.encapsulate(&mut OsRng)
                    .map_err(|e| Error::PostQuantum(format!("ML-KEM-512 encapsulation failed: {:?}", e)))?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            },
            SecurityLevel::Level3 => {
                let ek = EncapsulationKey::<MlKem768>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-768 public key".to_string()))?);
                let (ct, ss) = ek.encapsulate(&mut OsRng)
                    .map_err(|e| Error::PostQuantum(format!("ML-KEM-768 encapsulation failed: {:?}", e)))?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            },
            SecurityLevel::Level5 => {
                let ek = EncapsulationKey::<MlKem1024>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-1024 public key".to_string()))?);
                let (ct, ss) = ek.encapsulate(&mut OsRng)
                    .map_err(|e| Error::PostQuantum(format!("ML-KEM-1024 encapsulation failed: {:?}", e)))?;
                Ok((ct.as_bytes().to_vec(), ss.as_bytes().to_vec()))
            },
        }
    }

    fn decapsulate(&self, ciphertext: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        match self.level {
            SecurityLevel::Level1 => {
                let dk = DecapsulationKey::<MlKem512>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-512 secret key".to_string()))?);
                let ct = Ciphertext::<MlKem512>::from_bytes(ciphertext.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-512 ciphertext".to_string()))?);
                let ss = dk.decapsulate(&ct);
                Ok(ss.as_bytes().to_vec())
            },
            SecurityLevel::Level3 => {
                let dk = DecapsulationKey::<MlKem768>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-768 secret key".to_string()))?);
                let ct = Ciphertext::<MlKem768>::from_bytes(ciphertext.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-768 ciphertext".to_string()))?);
                let ss = dk.decapsulate(&ct);
                Ok(ss.as_bytes().to_vec())
            },
            SecurityLevel::Level5 => {
                let dk = DecapsulationKey::<MlKem1024>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-1024 secret key".to_string()))?);
                let ct = Ciphertext::<MlKem1024>::from_bytes(ciphertext.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-KEM-1024 ciphertext".to_string()))?);
                let ss = dk.decapsulate(&ct);
                Ok(ss.as_bytes().to_vec())
            },
        }
    }

    fn security_level(&self) -> SecurityLevel {
        self.level
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ml_kem_768_key_exchange() {
        let kem = MlKem::new(SecurityLevel::Level3);

        // Generate keypair
        let (public_key, secret_key) = kem.generate_keypair().unwrap();

        // Encapsulate
        let (ciphertext, shared_secret1) = kem.encapsulate(&public_key).unwrap();

        // Decapsulate
        let shared_secret2 = kem.decapsulate(&ciphertext, &secret_key).unwrap();

        // Shared secrets should match
        assert_eq!(shared_secret1, shared_secret2);
    }

    #[test]
    fn test_all_security_levels() {
        for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
            let kem = MlKem::new(level);
            let (pk, sk) = kem.generate_keypair().unwrap();
            let (ct, ss1) = kem.encapsulate(&pk).unwrap();
            let ss2 = kem.decapsulate(&ct, &sk).unwrap();
            assert_eq!(ss1, ss2);
        }
    }
}