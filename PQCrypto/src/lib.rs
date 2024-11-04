pub mod kem;
pub mod signatures;
pub mod code_based;
pub mod multivariate;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Verification failed")]
    VerificationFailed,
    #[error("Key generation failed")]
    KeyGenerationFailed,
    #[error("Encryption failed")]
    EncryptionFailed,
    #[error("Decryption failed")]
    DecryptionFailed,
    #[error("Algorithm not implemented")]
    NotImplemented,
}
