# pqc

![ci](https://img.shields.io/github/actions/workflow/status/mjovanc/pqc/ci.yml?branch=master)
![mlkem_rs](https://img.shields.io/crates/v/mlkem_rs.svg)

The post-quantum cryptographic library in pure Rust. Currently experimental, use it with caution! ⚠️

## Motivation

The post-quantum cryptographic library built to bring quantum-safe tools to Rust developers with an easy-to-use API. As quantum computing advances, it threatens to break classical encryption (like RSA and ECC) via algorithms like Shor’s, making post-quantum solutions critical for future-proofing applications. Existing PQC libraries in Rust, such as `pqcrypto`, are powerful but low-level and complex, leaving a gap for a straightforward, practical tool. We try to fill that gap by offering a high-level interface for algorithms such as ML-KEM and Dilithium (and more), that is designed for real-world tasks—think secure messaging, file encryption, or API authentication—without much cognitive overhead.

Rust’s rise in systems programming, with its focus on safety and speed, makes it a perfect fit for PQC, yet accessible options are scarce. This library aims to change that, starting with simple encryption and signing primitives that anyone can use. Why PQC now? Quantum threats might be years away, but systems (e.g., IoT, blockchain, HTTPS) need to transition early. We aim to provide a lightweight, hybrid-ready bridge to that future. Our goal is a library that scales from hobbyists to enterprise, keeping security simple and robust as quantum computers loom.

## Get Started

This guide reflects the current MVP and may evolve, focused on ML-KEM (which we have started working on). Check unit tests for the latest usage. APIs might shift as the library evolves.

Add `mlkem_rs` to your project:

```toml
[dependencies]
mlkem_rs = "0.1.0-aplha.1"
```

To test the latest code directly from the Git repository (recommended for trying out in-development features), use the following dependency instead:

```toml
[dependencies]
mlkem_rs = { git = "https://github.com/mjovanc/pqc.git", branch = "master" }
```

The Git version pulls the most recent updates from the master branch at [https://github.com/mjovanc/pqc](https://github.com/mjovanc/pqc).

### Basic Example

Here’s a quick example of using `mlkem_rs` crate for shared secret encapsulation and decapsulation:

```rust
use mlkem_rs::{algorithms::MlKem512, decapsulate, encapsulate, generate_keypair, QryptoError};

fn main() -> Result<(), QryptoError> {
    // Generate a MlKem512 keypair
    let mlkem = MlKem::<MlKem512>::new();

    // Encapsulate a shared secret using the public key
    let (ciphertext, shared_secret_bob) = mlkem.encapsulate(keypair.public_key())?;

    // Decapsulate the ciphertext to recover the shared secret
    let shared_secret_alice = mlkem.decapsulate(&keypair.secret_key(), &ciphertext)?;

    // Verify the shared secrets match
    assert_eq!(shared_secret_alice, shared_secret_bob, "Shared secrets do not match");

    Ok(())
}
```

## Supported Features

Below is a table of currently supported features and planned additions, designed to make it a fully featured post-quantum cryptography collection of crates.

| Feature                    | Description                                              | Status | Notes                                                                                   |
|----------------------------|----------------------------------------------------------|------|-----------------------------------------------------------------------------------------|
| **ML-KEM**            | Key Encapsulation Mechanism (NIST-standard)              | 🏗️ | Supports ML-KEM 512, ML-KEM 768, ML-KEM 1024 for varying security levels (FIPS 203).          |
| **ML-DSA (Signatures)** | Digital signature scheme (NIST-standard)                 | 🚧 | Includes ML-DSA 2, ML-DSA 3, ML-DSA 5 variants (FIPS 204).                        |
| **SLH-DSA (Signatures)**  | Stateless hash-based signature scheme (NIST-standard)    | 🚧 | Supports SLH-DSA-128s, 128f, 256s, 256f for stateless signing (FIPS 205).              |


## Peer Reviewing

Our library are currently experimental and **not recommended for production use**. As a post-quantum cryptography tool, its security and reliability depend heavily on peer review and testing, which has not yet been conducted. We are actively developing the features listed above, and they are marked as planned "🏗️" in the Supported Features table until fully implemented and tested.

We invite the community to participate in peer reviewing specific aspects of our crates once they are considered done in the status column of the table.
Features marked "✅" will have completed implementation and initial testing by the development team, making them ready for external scrutiny.
Peer review is critical to ensure cryptographic soundness, side-channel resistance, and practical usability. If you’re interested in contributing,
please send us a message on [GitHub Discussions](https://github.com/mjovanc/pqc/discussions),
and watch the table for updates as features move to "✅" status.

## Roadmap

Our planned milestones:

- **Version 0.2.0**: Implement full ML-KEM support (ML-KEM 512, ML-KEM 768, ML-KEM 1024) for key exchange (NIST FIPS 203).
- **Version 0.3.0**: Add full Dilithium support (Dilithium2, Dilithium3, Dilithium5) for digital signatures (NIST FIPS 204).
- **Version 0.4.0**: Add full SPHINCS+ support (SPHINCS+-128s, 128f, 256s, 256f) and hybrid encryption with AES-256-GCM (NIST FIPS 205).

_Check the [GitHub Issues](https://github.com/mjovanc/qrypto/issues) for the latest priorities and to suggest features._

## Acknowledgements

Our library are (will be) built on multiple [NIST](https://www.nist.gov) post-quantum cryptography standards (FIPS 203, 204, 205) and it leverages the Rust ecosystem,
including the rand crate (and other) for secure RNG. Thanks to the Rust community and PQC researchers for paving the way!

## License

The MIT License.
