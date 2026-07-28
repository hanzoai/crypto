//! Test all crypto functionality on ARM Mac

fn main() {
    println!("🔐 Hanzo Crypto - ARM Mac (M1/M2/M3) Test\n");

    // Test ML-KEM (Pure Rust - no AVX2 issues!)
    println!("✓ ML-KEM-768 (FIPS 203):");
    {
        use ml_kem::{MlKem768, KemCore};
        use rand::thread_rng;

        let mut rng = thread_rng();
        let (dk, ek) = MlKem768::generate(&mut rng);
        let (ct, ss1) = ek.encapsulate(&mut rng).unwrap();
        let ss2 = dk.decapsulate(&ct).unwrap();
        assert_eq!(ss1, ss2);
        println!("  ✅ Key encapsulation works!");
    }

    // Test ML-DSA (Pure Rust)
    println!("\n✓ ML-DSA-65 (FIPS 204):");
    {
        use ml_dsa::MlDsa65;
        use rand::thread_rng;

        let mut rng = thread_rng();
        let (sk, vk) = MlDsa65::generate(&mut rng).unwrap();
        let message = b"Quantum-resistant on ARM!";
        let signature = sk.try_sign(&message[..]).unwrap();
        vk.verify(&message[..], &signature).unwrap();
        println!("  ✅ Digital signatures work!");
    }

    // Test HQC
    println!("\n✓ HQC-192:");
    {
        use pqcrypto_hqc::hqc192::*;
        use pqcrypto_traits::kem::SharedSecret;

        let (pk, sk) = keypair();
        let (ss1, ct) = encapsulate(&pk);
        let ss2 = decapsulate(&ct, &sk);
        assert_eq!(ss1.as_bytes(), ss2.as_bytes());
        println!("  ✅ Code-based crypto works!");
    }

    // Test BLAKE3
    println!("\n✓ BLAKE3:");
    {
        let hash = blake3::hash(b"Fast hashing!");
        println!("  ✅ Hash: {}", hash.to_hex()[..16].to_string());
    }

    // Test ChaCha20-Poly1305
    println!("\n✓ ChaCha20-Poly1305:");
    {
        use chacha20poly1305::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            ChaCha20Poly1305,
        };

        let key = ChaCha20Poly1305::generate_key(&mut OsRng);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let cipher = ChaCha20Poly1305::new(&key);
        let ct = cipher.encrypt(&nonce, b"Secret".as_ref()).unwrap();
        let pt = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(pt, b"Secret");
        println!("  ✅ Stream cipher works!");
    }

    // Test AES-256-GCM
    println!("\n✓ AES-256-GCM:");
    {
        use aes_gcm::{
            aead::{Aead, AeadCore, KeyInit, OsRng},
            Aes256Gcm,
        };

        let key = Aes256Gcm::generate_key(&mut OsRng);
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let cipher = Aes256Gcm::new(&key);
        let ct = cipher.encrypt(&nonce, b"Top Secret".as_ref()).unwrap();
        let pt = cipher.decrypt(&nonce, ct.as_ref()).unwrap();
        assert_eq!(pt, b"Top Secret");
        println!("  ✅ Block cipher works!");
    }

    println!("\n🎉 All crypto algorithms work perfectly on ARM Mac!");
    println!("   No AVX2 issues - Pure Rust FTW!");
}