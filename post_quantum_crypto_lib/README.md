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
