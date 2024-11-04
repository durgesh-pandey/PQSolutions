use pqcrypto_kyber::kyber512::{
    self,
    Ciphertext as KyberCiphertext,
    PublicKey as KyberPublicKey,
    SecretKey as KyberSecretKey,
};
use pqcrypto_ntru::ntruhps2048509::{
    self,
    Ciphertext as NtruCiphertext,
    PublicKey as NtruPublicKey,
    SecretKey as NtruSecretKey,
};
use crate::CryptoError;
use pqcrypto_traits::kem::SharedSecret;

pub struct KyberKeyPair {
    pub public_key: KyberPublicKey,
    pub secret_key: KyberSecretKey,
}

pub struct NtruKeyPair {
    pub public_key: NtruPublicKey,
    pub secret_key: NtruSecretKey,
}

impl KyberKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = kyber512::keypair();
        Ok(Self { public_key, secret_key })
    }
}

impl NtruKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = ntruhps2048509::keypair();
        Ok(Self { public_key, secret_key })
    }
}

pub fn kyber_encapsulate(
    public_key: &KyberPublicKey,
) -> Result<(KyberCiphertext, Vec<u8>), CryptoError> {
    let (shared_secret, ciphertext) = kyber512::encapsulate(public_key);
    Ok((ciphertext, shared_secret.as_bytes().to_vec()))
}

pub fn kyber_decapsulate(
    ciphertext: &KyberCiphertext,
    secret_key: &KyberSecretKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_secret = kyber512::decapsulate(ciphertext, secret_key);
    Ok(shared_secret.as_bytes().to_vec())
}

pub fn ntru_encapsulate(
    public_key: &NtruPublicKey,
) -> Result<(NtruCiphertext, Vec<u8>), CryptoError> {
    let (shared_secret, ciphertext) = ntruhps2048509::encapsulate(public_key);
    Ok((ciphertext, shared_secret.as_bytes().to_vec()))
}

pub fn ntru_decapsulate(
    ciphertext: &NtruCiphertext,
    secret_key: &NtruSecretKey,
) -> Result<Vec<u8>, CryptoError> {
    let shared_secret = ntruhps2048509::decapsulate(ciphertext, secret_key);
    Ok(shared_secret.as_bytes().to_vec())
}
