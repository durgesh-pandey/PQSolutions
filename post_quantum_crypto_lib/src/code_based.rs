use pqcrypto_classicmceliece::mceliece348864f::{
    self,
    Ciphertext as McElieceCiphertext,
    PublicKey as McEliecePublicKey,
    SecretKey as McElieceSecretKey,
};
use crate::CryptoError;
use pqcrypto_traits::kem::SharedSecret;

pub struct McElieceKeyPair {
    pub public_key: Box<McEliecePublicKey>,
    pub secret_key: Box<McElieceSecretKey>,
}

impl McElieceKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = mceliece348864f::keypair();
        Ok(Self {
            public_key: Box::new(public_key),
            secret_key: Box::new(secret_key),
        })
    }
}

pub fn mceliece_encapsulate(
    public_key: &Box<McEliecePublicKey>,
) -> Result<(Box<McElieceCiphertext>, Vec<u8>), CryptoError> {
    let (shared_secret, ciphertext) = mceliece348864f::encapsulate(public_key);
    Ok((Box::new(ciphertext), shared_secret.as_bytes().to_vec()))
}

pub fn mceliece_decapsulate(
    ciphertext: &Box<McElieceCiphertext>,
    secret_key: &Box<McElieceSecretKey>,
) -> Result<Vec<u8>, CryptoError> {
    let shared_secret = mceliece348864f::decapsulate(ciphertext, secret_key);
    Ok(shared_secret.as_bytes().to_vec())
}
