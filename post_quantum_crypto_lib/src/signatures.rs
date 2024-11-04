use pqcrypto_dilithium::dilithium2::{
    self,
    PublicKey as DilithiumPublicKey,
    SecretKey as DilithiumSecretKey,
    SignedMessage as DilithiumSignedMessage,
};
use pqcrypto_falcon::falcon512::{
    self,
    PublicKey as FalconPublicKey,
    SecretKey as FalconSecretKey,
    SignedMessage as FalconSignedMessage,
};
use pqcrypto_sphincsplus::sphincssha2128fsimple::{
    self,
    PublicKey as SphincsPublicKey,
    SecretKey as SphincsSecretKey,
    SignedMessage as SphincsSignedMessage,
};
use crate::CryptoError;

pub struct DilithiumKeyPair {
    pub public_key: DilithiumPublicKey,
    pub secret_key: DilithiumSecretKey,
}

pub struct FalconKeyPair {
    pub public_key: FalconPublicKey,
    pub secret_key: FalconSecretKey,
}

pub struct SphincsPlusKeyPair {
    pub public_key: SphincsPublicKey,
    pub secret_key: SphincsSecretKey,
}

impl DilithiumKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = dilithium2::keypair();
        Ok(Self { public_key, secret_key })
    }
}

impl FalconKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = falcon512::keypair();
        Ok(Self { public_key, secret_key })
    }
}

impl SphincsPlusKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        let (public_key, secret_key) = sphincssha2128fsimple::keypair();
        Ok(Self { public_key, secret_key })
    }
}

// Dilithium signature functions
pub fn dilithium_sign(
    message: &[u8],
    secret_key: &DilithiumSecretKey,
) -> Result<DilithiumSignedMessage, CryptoError> {
    Ok(dilithium2::sign(message, secret_key))
}

pub fn dilithium_verify(
    signed_message: &DilithiumSignedMessage,
    public_key: &DilithiumPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    dilithium2::open(signed_message, public_key)
        .map_err(|_| CryptoError::VerificationFailed)
}

// Falcon signature functions
pub fn falcon_sign(
    message: &[u8],
    secret_key: &FalconSecretKey,
) -> Result<FalconSignedMessage, CryptoError> {
    Ok(falcon512::sign(message, secret_key))
}

pub fn falcon_verify(
    signed_message: &FalconSignedMessage,
    public_key: &FalconPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    falcon512::open(signed_message, public_key)
        .map_err(|_| CryptoError::VerificationFailed)
}

// SPHINCS+ signature functions
pub fn sphincsplus_sign(
    message: &[u8],
    secret_key: &SphincsSecretKey,
) -> Result<SphincsSignedMessage, CryptoError> {
    Ok(sphincssha2128fsimple::sign(message, secret_key))
}

pub fn sphincsplus_verify(
    signed_message: &SphincsSignedMessage,
    public_key: &SphincsPublicKey,
) -> Result<Vec<u8>, CryptoError> {
    sphincssha2128fsimple::open(signed_message, public_key)
        .map_err(|_| CryptoError::VerificationFailed)
}
