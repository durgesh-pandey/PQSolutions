use post_quantum_crypto_lib::{
    kem::{
        kyber_decapsulate,
        kyber_encapsulate,
        KyberKeyPair,
        ntru_decapsulate,
        ntru_encapsulate,
        NtruKeyPair,
    },
    signatures::{
        dilithium_sign,
        dilithium_verify,
        DilithiumKeyPair,
        falcon_sign,
        falcon_verify,
        FalconKeyPair,
        sphincsplus_sign,
        sphincsplus_verify,
        SphincsPlusKeyPair,
    },
    code_based::{
        mceliece_encapsulate,
        mceliece_decapsulate,
        McElieceKeyPair,
    },
    multivariate::{
        LUOVKeyPair,
    },
    CryptoError,
};
use assert_matches::assert_matches;

#[test]
fn test_kyber_kem() {
    let kyber_keys = KyberKeyPair::generate().expect("Kyber key generation failed");
    let (ciphertext, shared_secret_enc) =
        kyber_encapsulate(&kyber_keys.public_key).expect("Kyber encapsulation failed");
    let shared_secret_dec =
        kyber_decapsulate(&ciphertext, &kyber_keys.secret_key).expect("Kyber decapsulation failed");
    assert_eq!(
        shared_secret_enc, shared_secret_dec,
        "Kyber shared secrets do not match"
    );
}

#[test]
fn test_ntru_kem() {
    let ntru_keys = NtruKeyPair::generate().expect("NTRU key generation failed");
    let (ciphertext, shared_secret_enc) =
        ntru_encapsulate(&ntru_keys.public_key).expect("NTRU encapsulation failed");
    let shared_secret_dec =
        ntru_decapsulate(&ciphertext, &ntru_keys.secret_key).expect("NTRU decapsulation failed");
    assert_eq!(
        shared_secret_enc, shared_secret_dec,
        "NTRU shared secrets do not match"
    );
}

#[test]
fn test_dilithium_signature() {
    let dilithium_keys = DilithiumKeyPair::generate().expect("Dilithium key generation failed");
    let message = b"Test message for Dilithium";
    let signed_message = dilithium_sign(message, &dilithium_keys.secret_key)
        .expect("Dilithium signing failed");
    let verified_message = dilithium_verify(&signed_message, &dilithium_keys.public_key)
        .expect("Dilithium verification failed");
    assert_eq!(
        verified_message, message,
        "Dilithium verified message does not match original"
    );
}

#[test]
fn test_falcon_signature() {
    let falcon_keys = FalconKeyPair::generate().expect("Falcon key generation failed");
    let message = b"Test message for Falcon";
    let signed_message = falcon_sign(message, &falcon_keys.secret_key)
        .expect("Falcon signing failed");
    let verified_message = falcon_verify(&signed_message, &falcon_keys.public_key)
        .expect("Falcon verification failed");
    assert_eq!(
        verified_message, message,
        "Falcon verified message does not match original"
    );
}

#[test]
fn test_sphincsplus_signature() {
    let sphincs_keys = SphincsPlusKeyPair::generate().expect("SPHINCS+ key generation failed");
    let message = b"Test message for SPHINCS+";
    let signed_message = sphincsplus_sign(message, &sphincs_keys.secret_key)
        .expect("SPHINCS+ signing failed");
    let verified_message = sphincsplus_verify(&signed_message, &sphincs_keys.public_key)
        .expect("SPHINCS+ verification failed");
    assert_eq!(
        verified_message, message,
        "SPHINCS+ verified message does not match original"
    );
}

#[test]
fn test_mceliece_kem() {
    let result = std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024) // 64 MB stack
        .spawn(|| {
            let mceliece_keys = McElieceKeyPair::generate().expect("McEliece key generation failed");
            let (ciphertext, shared_secret_enc) =
                mceliece_encapsulate(&mceliece_keys.public_key).expect("McEliece encapsulation failed");
            let shared_secret_dec = mceliece_decapsulate(&ciphertext, &mceliece_keys.secret_key)
                .expect("McEliece decapsulation failed");
            assert_eq!(
                shared_secret_enc, shared_secret_dec,
                "McEliece shared secrets do not match"
            );
        })
        .unwrap()
        .join();
    assert!(result.is_ok());
}

#[test]
fn test_luov_signature() {
    let result = LUOVKeyPair::generate();
    assert_matches!(result, Err(CryptoError::NotImplemented));
}
