use post_quantum_crypto_lib::kem::{KyberKeyPair, kyber_encapsulate, kyber_decapsulate};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let kyber_keys = KyberKeyPair::generate()?;
    let (ciphertext, shared_secret_enc) = kyber_encapsulate(&kyber_keys.public_key)?;
    let shared_secret_dec = kyber_decapsulate(&ciphertext, &kyber_keys.secret_key)?;
    assert_eq!(
        shared_secret_enc, shared_secret_dec,
        "Shared secrets do not match"
    );
    println!("Kyber KEM example executed successfully.");
    Ok(())
}
