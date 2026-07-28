//! Integration tests for Hanzo Crypto

use hanzo_crypto::{ml_kem, ml_dsa, blake3, chacha20poly1305, aes_gcm};
use pqcrypto_traits::kem::SharedSecret;
use rand::thread_rng;

#[test]
fn test_ml_kem_integration() {
    use ml_kem::{MlKem768, Encapsulate, Decapsulate};

    let mut rng = thread_rng();
    let (dk, ek) = MlKem768::generate(&mut rng);

    // Test multiple encapsulations
    for _ in 0..10 {
        let (ct, ss_sender) = ek.encapsulate(&mut rng).unwrap();
        let ss_receiver = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss_sender, ss_receiver);
    }
}

#[test]
fn test_ml_dsa_integration() {
    use ml_dsa::{Ml_Dsa65, SigningKey};

    let mut rng = thread_rng();
    let signing_key = SigningKey::generate(&mut rng).unwrap();
    let verification_key = signing_key.verification_key();

    // Test multiple messages
    let messages = [
        b"Message 1",
        b"Message 2 with more content",
        b"",
        &[0u8; 1000],
    ];

    for msg in &messages {
        let signature = signing_key.try_sign_with_rng(&mut rng, *msg).unwrap();
        verification_key.verify(*msg, &signature).unwrap();
    }
}

#[test]
fn test_blake3_integration() {
    let data1 = b"Test data 1";
    let data2 = b"Test data 2";

    let hash1a = blake3::hash(data1);
    let hash1b = blake3::hash(data1);
    let hash2 = blake3::hash(data2);

    // Same input produces same output
    assert_eq!(hash1a, hash1b);
    // Different input produces different output
    assert_ne!(hash1a, hash2);
}

#[test]
fn test_chacha20_poly1305_integration() {
    use chacha20poly1305::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        ChaCha20Poly1305,
    };

    let key = ChaCha20Poly1305::generate_key(&mut OsRng);
    let cipher = ChaCha20Poly1305::new(&key);

    // Test various message sizes
    let messages = vec![
        vec![0u8; 0],
        vec![1u8; 1],
        vec![2u8; 16],
        vec![3u8; 1024],
        vec![4u8; 65536],
    ];

    for msg in messages {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let ct = cipher.encrypt(&nonce, msg.as_ref()).unwrap();
        let pt = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(msg, pt);
    }
}

#[test]
fn test_aes_256_gcm_integration() {
    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit, OsRng},
        Aes256Gcm,
    };

    let key = Aes256Gcm::generate_key(&mut OsRng);
    let cipher = Aes256Gcm::new(&key);

    // Test with associated data
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = b"Secret message";
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_ref()).unwrap();
    let decrypted = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();

    assert_eq!(plaintext.as_ref(), decrypted);

    // Verify tampering is detected
    let mut tampered = ciphertext.clone();
    tampered[0] ^= 0xFF;
    assert!(cipher.decrypt(&nonce, tampered.as_ref()).is_err());
}

#[test]
fn test_hqc_all_levels() {
    use hanzo_crypto::hqc::{hqc128, hqc192, hqc256};

    // Test HQC-128
    {
        let (pk, sk) = hqc128::keypair();
        let (ss1, ct) = hqc128::encapsulate(&pk);
        let ss2 = hqc128::decapsulate(&ct, &sk);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    // Test HQC-192
    {
        let (pk, sk) = hqc192::keypair();
        let (ss1, ct) = hqc192::encapsulate(&pk);
        let ss2 = hqc192::decapsulate(&ct, &sk);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }

    // Test HQC-256
    {
        let (pk, sk) = hqc256::keypair();
        let (ss1, ct) = hqc256::encapsulate(&pk);
        let ss2 = hqc256::decapsulate(&ct, &sk);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
    }
}