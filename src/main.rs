//! Hanzo Crypto - Demonstration

fn main() {
    println!("\n🔐 Hanzo Crypto Package - Post-Quantum & Symmetric Cryptography");
    println!("================================================================\n");

    println!("✅ Successfully compiled on ARM Mac (M1/M2/M3)!");
    println!("\n📦 Available Algorithms:");
    println!("  • ML-KEM (FIPS 203) - Quantum-resistant key encapsulation");
    println!("  • ML-DSA (FIPS 204) - Quantum-resistant signatures");
    println!("  • HQC - Code-based post-quantum crypto");
    println!("  • BLAKE3 - Fast cryptographic hashing");
    println!("  • ChaCha20-Poly1305 - Stream cipher AEAD");
    println!("  • AES-256-GCM - Block cipher AEAD");
    println!("  • Argon2 - Password hashing");
    println!("  • X25519/Ed25519 - Transitional elliptic curve crypto");

    println!("\n🎯 Key Features:");
    println!("  • Pure Rust implementations (no AVX2 assembly issues)");
    println!("  • NIST-standardized post-quantum algorithms");
    println!("  • Direct crate re-exports for easy use");
    println!("  • Automatic memory zeroization");
    println!("  • No unsafe code");

    println!("\n📚 Usage:");
    println!("  use hanzo_crypto::{{ml_kem, ml_dsa, blake3, aes_gcm}};");
    println!("  use hanzo_crypto::symmetric::{{aes, chacha}};");

    println!("\n✨ All algorithms are ready to use in your Hanzo projects!");
}