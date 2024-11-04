#!/bin/bash

# Set the project name
PROJECT_NAME="post_quantum_crypto_lib"

# Function to check and install Rust
install_rust() {
    if ! command -v rustc &> /dev/null; then
        echo "Rust is not installed. Installing Rust using rustup..."
        # Install Rust using rustup (the official installer)
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        # Add Rust to the current shell
        source "$HOME/.cargo/env"
    else
        echo "Rust is already installed."
    fi
}

# Function to check and install Cargo (should be installed with Rust)
install_cargo() {
    if ! command -v cargo &> /dev/null; then
        echo "Cargo is not installed. Please ensure Rust is installed correctly."
        exit 1
    else
        echo "Cargo is already installed."
    fi
}

# Function to install rustfmt
install_rustfmt() {
    if ! rustup component list | grep 'rustfmt.*installed' &> /dev/null; then
        echo "Installing rustfmt..."
        rustup component add rustfmt
    else
        echo "rustfmt is already installed."
    fi
}

# Function to install clippy
install_clippy() {
    if ! rustup component list | grep 'clippy.*installed' &> /dev/null; then
        echo "Installing clippy..."
        rustup component add clippy
    else
        echo "clippy is already installed."
    fi
}

# Function to install cargo-criterion
install_criterion() {
    if ! cargo install --list | grep -q '^cargo-criterion v'; then
        echo "Installing cargo-criterion..."
        cargo install cargo-criterion
    else
        echo "cargo-criterion is already installed."
    fi
}

# Function to install cargo-tarpaulin
install_tarpaulin() {
    if ! cargo install --list | grep -q '^cargo-tarpaulin v'; then
        echo "Installing cargo-tarpaulin..."
        cargo install cargo-tarpaulin
    else
        echo "cargo-tarpaulin is already installed."
    fi
}

# Function to install other dependencies if necessary
install_other_dependencies() {
    # Update package lists
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        # Install build-essential if not installed
        if ! dpkg -s build-essential &> /dev/null; then
            echo "Installing build-essential..."
            sudo apt-get install -y build-essential
        fi
        # Install pkg-config and libssl-dev (required for some crates)
        if ! dpkg -s pkg-config &> /dev/null; then
            echo "Installing pkg-config..."
            sudo apt-get install -y pkg-config
        fi
        if ! dpkg -s libssl-dev &> /dev/null; then
            echo "Installing libssl-dev..."
            sudo apt-get install -y libssl-dev
        fi
    fi
}

# Install Rust and Cargo
install_rust
install_cargo

# Install additional dependencies
install_other_dependencies

# Check if the project directory already exists
if [ -d "$PROJECT_NAME" ]; then
    echo "Error: Directory '$PROJECT_NAME' already exists."
    echo "Please remove it or choose a different project name."
    exit 1
fi

# Create the project using cargo new
cargo new "$PROJECT_NAME" --lib

# Navigate to the project directory
cd "$PROJECT_NAME"

# Create necessary subdirectories
mkdir -p tests examples benches .github/workflows

# Update Cargo.toml with required dependencies
cat << 'EOF' > Cargo.toml
[package]
name = "post_quantum_crypto_lib"
version = "0.5.0"
edition = "2021"

[dependencies]
pqcrypto-kyber = "0.7.3"
pqcrypto-dilithium = "0.5.0"
pqcrypto-falcon = "0.3.0"
pqcrypto-sphincsplus = "0.7.0"
pqcrypto-classicmceliece = "0.2.0"
pqcrypto-ntru = "0.5.8"
pqcrypto-traits = "0.3.5"
serde = { version = "1.0", features = ["derive"] }
uuid = { version = "1.4", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
rand = "0.8"
thiserror = "1.0"

[dev-dependencies]
assert_matches = "1.5"
criterion = "0.4"
EOF

# Create rustfmt.toml for code formatting configuration
cat << 'EOF' > rustfmt.toml
max_width = 100
EOF

# Create src/lib.rs with updated modules
mkdir -p src
cat << 'EOF' > src/lib.rs
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
EOF

# Create src/kem.rs
cat << 'EOF' > src/kem.rs
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
EOF

# Create src/signatures.rs
cat << 'EOF' > src/signatures.rs
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
EOF

# Create src/code_based.rs
cat << 'EOF' > src/code_based.rs
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
EOF

# Create src/multivariate.rs
cat << 'EOF' > src/multivariate.rs
use crate::CryptoError;

#[derive(Debug)]
pub struct LUOVKeyPair {
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

impl LUOVKeyPair {
    pub fn generate() -> Result<Self, CryptoError> {
        // Placeholder implementation
        Err(CryptoError::NotImplemented)
    }
}

pub fn luov_sign(
    _message: &[u8],
    _secret_key: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    // Placeholder implementation
    Err(CryptoError::NotImplemented)
}

pub fn luov_verify(
    _signature: &[u8],
    _message: &[u8],
    _public_key: &[u8],
) -> Result<(), CryptoError> {
    // Placeholder implementation
    Err(CryptoError::NotImplemented)
}
EOF

# Create tests/integration_tests.rs
cat << 'EOF' > tests/integration_tests.rs
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
EOF

# Create examples/kyber_example.rs
cat << 'EOF' > examples/kyber_example.rs
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
EOF

# Create benches/benchmark.rs
cat << 'EOF' > benches/benchmark.rs
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use post_quantum_crypto_lib::kem::{KyberKeyPair, kyber_encapsulate, kyber_decapsulate};

fn benchmark_kyber(c: &mut Criterion) {
    c.bench_function("kyber key generation", |b| {
        b.iter(|| {
            KyberKeyPair::generate().expect("Kyber key generation failed");
        })
    });

    let kyber_keys = KyberKeyPair::generate().expect("Kyber key generation failed");
    c.bench_function("kyber encapsulation", |b| {
        b.iter(|| {
            kyber_encapsulate(black_box(&kyber_keys.public_key)).expect("Kyber encapsulation failed");
        })
    });

    let (ciphertext, _) =
        kyber_encapsulate(&kyber_keys.public_key).expect("Kyber encapsulation failed");
    c.bench_function("kyber decapsulation", |b| {
        b.iter(|| {
            kyber_decapsulate(black_box(&ciphertext), black_box(&kyber_keys.secret_key))
                .expect("Kyber decapsulation failed");
        })
    });
}

criterion_group!(benches, benchmark_kyber);
criterion_main!(benches);
EOF

# Create .github/workflows/ci.yml
mkdir -p .github/workflows
cat << 'EOF' > .github/workflows/ci.yml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  build-and-test:
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v3

      - name: Set up Rust
        uses: actions-rs/toolchain@v1
        with:
          toolchain: stable
          override: true

      - name: Install Dependencies
        run: rustup component add clippy rustfmt

      - name: Build
        run: cargo build --verbose

      - name: Run Tests
        run: cargo test --verbose

      - name: Run Clippy
        run: cargo clippy -- -D warnings

      - name: Run Rustfmt
        run: cargo fmt -- --check

      - name: Generate Code Coverage
        run: cargo tarpaulin --out Xml

      - name: Upload Coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          files: coverage.xml
EOF

# Include the full text of the MIT License in the LICENSE file
cat << 'EOF' > LICENSE
MIT License

Copyright (c) 2023 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
...

[Include the rest of the MIT License text here]
EOF

# Replace the placeholder with the actual MIT License text
sed -i '/\[Include the rest of the MIT License text here\]/r /dev/stdin' LICENSE << 'CONTENT_EOF'
of the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

[Include the rest of the MIT License text here]

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
CONTENT_EOF

# Update README.md with enhanced instructions
cat << 'EOF' > README.md
# Post Quantum Crypto Library

A Rust-based library implementing various post-quantum cryptographic algorithms, including:

- **Key Encapsulation Mechanisms (KEM)**
  - **CRYSTALS-Kyber** (NIST-selected)
  - **NTRU** (alternative lattice-based KEM)
  - **Classic McEliece** (code-based KEM)

- **Digital Signatures**
  - **CRYSTALS-Dilithium** (NIST-selected)
  - **FALCON** (NIST-selected)
  - **SPHINCS+** (NIST-selected)
  - **LUOV** (Multivariate, placeholder)

## **Getting Started**

### **Prerequisites**

- **Rust and Cargo** installed (Rust 1.56.0 or newer)
- **Criterion** for benchmarking:
  ```bash
  cargo install cargo-criterion
EOF
