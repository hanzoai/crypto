//! Basic usage example of Hanzo Crypto

use hanzo_crypto::prelude::*;
use hanzo_crypto::{ml_kem, ml_dsa, blake3, chacha20poly1305, aes_gcm};

fn main() -> Result<()> {
    println!("Hanzo Crypto Example\n");

    // ML-KEM (NIST FIPS 203) - Post-quantum key encapsulation
    println!("1. ML-KEM-768 (formerly Kyber):");
    {
        use ml_kem::{MlKem768, Encapsulate, Decapsulate};

        let mut rng = rand::thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);

        let (ct, ss_sender) = ek.encapsulate(&mut rng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();

        assert_eq!(ss_sender, ss_receiver);
        println!("   ✓ Key encapsulation successful");
    }

    // ML-DSA (NIST FIPS 204) - Post-quantum signatures
    println!("\n2. ML-DSA-65 (formerly Dilithium):");
    {
        use ml_dsa::{Ml_Dsa65, SigningKey, VerificationKey};

        let mut rng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut rng).unwrap();
        let verification_key = signing_key.verification_key();

        let message = b"Hello, post-quantum world!";
        let signature = signing_key.try_sign_with_rng(&mut rng, message).unwrap();

        verification_key.verify(message, &signature).unwrap();
        println!("   ✓ Signature verification successful");
    }

    // BLAKE3 hashing
    println!("\n3. BLAKE3 Hashing:");
    {
        let data = b"Hash this data with BLAKE3";
        let hash = blake3::hash(data);
        println!("   Hash: {}", hash.to_hex());
        println!("   ✓ BLAKE3 hash computed");
    }

    // ChaCha20-Poly1305 authenticated encryption
    println!("\n4. ChaCha20-Poly1305:");
    {
        use chacha20poly1305::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            ChaCha20Poly1305,
        };

        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

        let cipher = ChaCha20Poly1305::new(&key);
        let plaintext = b"Secret message";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted);
        println!("   ✓ Encryption/decryption successful");
    }

    // AES-256-GCM authenticated encryption
    println!("\n5. AES-256-GCM:");
    {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
        };

        let key = Aes256Gcm::generate_key(&mut OsRng);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

        let cipher = Aes256Gcm::new(&key);
        let plaintext = b"Another secret";
        let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
        let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

        assert_eq!(plaintext.as_ref(), decrypted);
        println!("   ✓ AES-256-GCM successful");
    }

    // HQC code-based cryptography
    println!("\n6. HQC-192:");
    {
        use hanzo_crypto::hqc::hqc192::*;

        let (pk, sk) = keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);

        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        println!("   ✓ HQC key encapsulation successful");
    }

    println!("\n✅ All cryptographic operations completed successfully!");
    println!("   This library is ARM-compatible (M1/M2/M3 Mac ready)");

    Ok(())
}