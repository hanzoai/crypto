//! ML-DSA (Module-Lattice Digital Signature Algorithm) implementation
//! FIPS 204 compliant - formerly known as Dilithium

use ml_dsa::{ML_DSA_44, ML_DSA_65, ML_DSA_87};
use ml_dsa::{SigningKey, VerificationKey};
use rand::rngs::OsRng;
use crate::{Result, Error};
use super::{DigitalSignature, SecurityLevel};

/// ML-DSA implementation with configurable security level
pub struct MlDsa {
    level: SecurityLevel,
}

impl MlDsa {
    /// Create a new ML-DSA instance with specified security level
    pub fn new(level: SecurityLevel) -> Self {
        MlDsa { level }
    }

    /// Generate ML-DSA-44 keypair (128-bit security)
    pub fn generate_44() -> Result<(Vec<u8>, Vec<u8>)> {
        let signing_key = SigningKey::<ML_DSA_44>::generate(&mut OsRng);
        let verification_key = signing_key.verification_key();
        Ok((
            verification_key.as_bytes().to_vec(),
            signing_key.as_bytes().to_vec()
        ))
    }

    /// Generate ML-DSA-65 keypair (192-bit security)
    pub fn generate_65() -> Result<(Vec<u8>, Vec<u8>)> {
        let signing_key = SigningKey::<ML_DSA_65>::generate(&mut OsRng);
        let verification_key = signing_key.verification_key();
        Ok((
            verification_key.as_bytes().to_vec(),
            signing_key.as_bytes().to_vec()
        ))
    }

    /// Generate ML-DSA-87 keypair (256-bit security)
    pub fn generate_87() -> Result<(Vec<u8>, Vec<u8>)> {
        let signing_key = SigningKey::<ML_DSA_87>::generate(&mut OsRng);
        let verification_key = signing_key.verification_key();
        Ok((
            verification_key.as_bytes().to_vec(),
            signing_key.as_bytes().to_vec()
        ))
    }
}

impl DigitalSignature for MlDsa {
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>)> {
        match self.level {
            SecurityLevel::Level1 => Self::generate_44(),
            SecurityLevel::Level3 => Self::generate_65(),
            SecurityLevel::Level5 => Self::generate_87(),
        }
    }

    fn sign(&self, message: &[u8], secret_key: &[u8]) -> Result<Vec<u8>> {
        match self.level {
            SecurityLevel::Level1 => {
                let signing_key = SigningKey::<ML_DSA_44>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-44 secret key".to_string()))?);
                let signature = signing_key.sign(&mut OsRng, message);
                Ok(signature.to_vec())
            },
            SecurityLevel::Level3 => {
                let signing_key = SigningKey::<ML_DSA_65>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-65 secret key".to_string()))?);
                let signature = signing_key.sign(&mut OsRng, message);
                Ok(signature.to_vec())
            },
            SecurityLevel::Level5 => {
                let signing_key = SigningKey::<ML_DSA_87>::from_bytes(secret_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-87 secret key".to_string()))?);
                let signature = signing_key.sign(&mut OsRng, message);
                Ok(signature.to_vec())
            },
        }
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<bool> {
        match self.level {
            SecurityLevel::Level1 => {
                let verification_key = VerificationKey::<ML_DSA_44>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-44 public key".to_string()))?);
                verification_key.verify(message, signature.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-44 signature".to_string()))?)
                    .map(|_| true)
                    .or(Ok(false))
            },
            SecurityLevel::Level3 => {
                let verification_key = VerificationKey::<ML_DSA_65>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-65 public key".to_string()))?);
                verification_key.verify(message, signature.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-65 signature".to_string()))?)
                    .map(|_| true)
                    .or(Ok(false))
            },
            SecurityLevel::Level5 => {
                let verification_key = VerificationKey::<ML_DSA_87>::from_bytes(public_key.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-87 public key".to_string()))?);
                verification_key.verify(message, signature.try_into()
                    .map_err(|_| Error::PostQuantum("Invalid ML-DSA-87 signature".to_string()))?)
                    .map(|_| true)
                    .or(Ok(false))
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
    fn test_ml_dsa_65_sign_verify() {
        let dsa = MlDsa::new(SecurityLevel::Level3);
        let message = b"Hello, post-quantum world!";

        // Generate keypair
        let (public_key, secret_key) = dsa.generate_keypair().unwrap();

        // Sign message
        let signature = dsa.sign(message, &secret_key).unwrap();

        // Verify signature
        let is_valid = dsa.verify(message, &signature, &public_key).unwrap();
        assert!(is_valid);

        // Verify with wrong message should fail
        let wrong_message = b"Wrong message";
        let is_valid = dsa.verify(wrong_message, &signature, &public_key).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_all_dsa_levels() {
        let message = b"Test message for all security levels";

        for level in [SecurityLevel::Level1, SecurityLevel::Level3, SecurityLevel::Level5] {
            let dsa = MlDsa::new(level);
            let (pk, sk) = dsa.generate_keypair().unwrap();
            let sig = dsa.sign(message, &sk).unwrap();
            let valid = dsa.verify(message, &sig, &pk).unwrap();
            assert!(valid);
        }
    }
}