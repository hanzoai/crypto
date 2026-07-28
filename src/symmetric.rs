//! # Symmetric Cryptography
//!
//! AES-256-GCM and ChaCha20-Poly1305 authenticated encryption.

use zeroize::ZeroizeOnDrop;
use crate::{CryptoError, Result};

/// Secure key wrapper with automatic zeroization
#[derive(ZeroizeOnDrop)]
pub struct SecureKey {
    bytes: Vec<u8>,
}

impl SecureKey {
    /// Create a new secure key
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Re-export AES-GCM functionality
pub mod aes {
    pub use aes_gcm::{
        Aes256Gcm,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };
}

/// Re-export ChaCha20-Poly1305 functionality
pub mod chacha {
    pub use chacha20poly1305::{
        ChaCha20Poly1305,
        aead::{Aead, AeadCore, KeyInit, OsRng},
    };
}

/// Self-test symmetric crypto
pub fn self_test() -> Result<()> {
    use aes_gcm::{Aes256Gcm, aead::{Aead, AeadCore, KeyInit, OsRng}};
    use chacha20poly1305::ChaCha20Poly1305;

    // Test AES-256-GCM
    {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let plaintext = b"Test message for AES-256-GCM";

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if decrypted != plaintext {
            return Err(CryptoError::SelfTestFailed);
        }
    }

    // Test ChaCha20-Poly1305
    {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = b"Test message for ChaCha20-Poly1305";

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref())
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        if decrypted != plaintext {
            return Err(CryptoError::SelfTestFailed);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes_gcm::{Aes256Gcm, aead::{Aead, AeadCore, KeyInit, OsRng}};
    use chacha20poly1305::ChaCha20Poly1305;

    #[test]
    fn test_aes_gcm() {
        let key = Aes256Gcm::generate_key(&mut OsRng);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let plaintext = b"Hello, AES-256-GCM!";

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_chacha20poly1305() {
        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = b"Hello, ChaCha20-Poly1305!";

        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(decrypted, plaintext);
    }
}