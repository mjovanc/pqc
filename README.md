# qrypto

![ci](https://img.shields.io/github/actions/workflow/status/mjovanc/qrypto/ci.yml?branch=master)
![crates.io](https://img.shields.io/crates/v/qrypto.svg)
[![documentation](https://img.shields.io/badge/docs-qrypto-blue?logo=rust)](https://docs.rs/qrypto/latest/)

The post-quantum cryptography library in pure Rust. Currently experimental, use it with caution!

## Motivation

`qrypto` is a post-quantum cryptography library built to bring quantum-safe security to Rust developers with an easy-to-use API. As quantum computing advances, it threatens to break classical encryption (like RSA and ECC) via algorithms like Shor’s, making post-quantum solutions critical for future-proofing applications. Existing PQC libraries in Rust, such as `pqcrypto`, are powerful but low-level and complex, leaving a gap for a straightforward, practical tool. `qrypto` fills this by offering a high-level interface built on NIST-standard algorithms like Kyber and Dilithium, designed for real-world tasks—think secure messaging, file encryption, or API authentication—without the crypto PhD.

Rust’s rise in systems programming, with its focus on safety and speed, makes it a perfect fit for PQC, yet accessible options are scarce. `qrypto` aims to change that, starting with simple encryption and signing primitives that anyone can use. Why PQC now? Quantum threats might be years away, but systems (e.g., IoT, blockchain, HTTPS) need to transition early—`qrypto` provides a lightweight, hybrid-ready bridge to that future. Our goal is a library that scales from hobbyists to enterprise, keeping security simple and robust as quantum computers loom.

## Get Started

This guide reflects the current MVP and may evolve. Check unit tests and the `examples` directory for the latest usage. APIs might shift as `qrypto` grows.

Add `qrypto` to your project:

```toml
[dependencies]
qrypto = "0.1.0"
```

To test the latest code directly from the Git repository (recommended for trying out in-development features), use the following dependency instead:

```toml
[dependencies]
qrypto = { git = "https://github.com/mjovanc/qrypto.git", branch = "master" }
```

The Git version pulls the most recent updates from the master branch at [https://github.com/mjovanc/qrypto](https://github.com/mjovanc/qrypto),
which may include features not yet released in the [crates.io](https://crates.io/crates/qrypto) version (`0.1.0`). Be aware that this is experimental and subject to change!

### Basic Example

Here’s a quick example of using Kyber for shared secret encapsulation and decapsulation:

```rust
use qrypto::{algorithms::Kyber512, decapsulate, encapsulate, generate_keypair};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Alice generates a Kyber512 key pair
    let keypair = generate_keypair::<Kyber512>()?;

    // Bob encapsulates a shared secret using Alice's public key
    let (ciphertext, shared_secret_bob) = encapsulate::<Kyber512>(keypair.public_key())?;

    // Alice decapsulates the ciphertext to get the same shared secret
    let shared_secret_alice = decapsulate::<Kyber512>(&keypair.secret_key(), &ciphertext)?;

    // Verify they match (in a real impl, they will)
    assert_eq!(shared_secret_alice, shared_secret_bob);
    println!("Shared secret (Kyber512): {:?}", shared_secret_alice);

    Ok(())
}
```

## Supported Features

Below is a table of currently supported features and planned additions for `qrypto`, designed to make it a fully featured post-quantum cryptography library.

| Feature                    | Description                                              | Status  | Notes                                                                                   |
|----------------------------|----------------------------------------------------------|---------|-----------------------------------------------------------------------------------------|
| **Kyber (KEM)**            | Key Encapsulation Mechanism (NIST-standard)              | 🏗️ | Supports Kyber512, Kyber768, Kyber1024 for varying security levels (FIPS 203).          |
| **Dilithium (Signatures)** | Digital signature scheme (NIST-standard)                 | 🏗️ | Includes Dilithium2, Dilithium3, Dilithium5 variants (FIPS 204).                        |
| **SPHINCS+ (Signatures)**  | Stateless hash-based signature scheme (NIST-standard)    | 🏗️ | Supports SPHINCS+-128s, 128f, 256s, 256f for stateless signing (FIPS 205).              |
| **HQC (KEM)**              | Code-based Key Encapsulation Mechanism (NIST-standard)   | 🏗️ | Supports HQC-128, HQC-192, HQC-256; added to NIST standards March 11, 2025.             |
| **Hybrid Encryption**      | Combines PQC with classical algorithms                   | 🏗️ | Will support AES-256-GCM or ChaCha20-Poly1305 for authenticated encryption.             |
| **Hybrid Public-Key Crypto** | Combines PQC with RSA/ECC for transitional use         | 🏗️ | Enables dual KEMs or signatures (e.g., Kyber + RSA) for legacy compatibility.           |

## Peer Reviewing

`qrypto` is currently an experimental library (version 0.1.0) and **not recommended for production use**. As a post-quantum cryptography tool, its security and reliability depend heavily on rigorous peer review, which has not yet been conducted. We are actively developing the features listed above, and they are marked as planned "🏗️" in the Supported Features table until fully implemented and tested.

We warmly invite the community to participate in peer reviewing specific aspects of `qrypto` once they are considered done in the status column of the table.
Features marked "✅" will have completed implementation and initial testing by the development team, making them ready for external scrutiny.
Peer review is critical to ensure cryptographic soundness, side-channel resistance, and practical usability. If you’re interested in contributing,
please check the [contribution guide](https://github.com/mjovanc/qrypto/blob/master/CONTRIBUTING.md) for details on how to get involved,
and watch the table for updates as features move to "✅" status. Your expertise can help make `qrypto` a trusted PQC solution!

## Roadmap

We’re working toward a fully featured Rust PQC library. Planned milestones include:

- **Version 0.2.0**: Implement full Kyber support (Kyber512, Kyber768, Kyber1024) for key exchange (NIST FIPS 203).
- **Version 0.3.0**: Add full Dilithium support (Dilithium2, Dilithium3, Dilithium5) for digital signatures (NIST FIPS 204).
- **Version 0.4.0**: Add full SPHINCS+ support (SPHINCS+-128s, 128f, 256s, 256f) and hybrid encryption with AES-256-GCM (NIST FIPS 205).

_Check the [GitHub Issues](https://github.com/mjovanc/qrypto/issues) for the latest priorities and to suggest features._

## Getting Help

Are you having trouble with `qrypto`? We want to help!

- Read through the documentation on our [docs](https://docs.rs/qrypto/latest/qrypto/).

- If you’d like to discuss `qrypto`, head over to [GitHub Discussions](https://github.com/mjovanc/qrypto/discussions) and join the conversation.

- If you are upgrading, read the release notes to be informed about breaking changes.

- Ask a question we monitor stackoverflow.com for questions tagged with `qrypto`.

- Report bugs with `qrypto` at https://github.com/mjovanc/qrypto/issues.

## Reporting Issues

`qrypto` uses GitHub’s integrated issue tracking system to record bugs and feature requests. If you want to raise an issue, please follow the recommendations below:

- Before you log a bug, please search the issue tracker to see if someone has already reported the problem.

- If the issue doesn’t already exist, create a new issue.

- Please provide as much information as possible with the issue report. We like to know the `qrypto` version, operating system, and Rust version version you’re using.

- If you need to paste code or include a stack trace, use Markdown. ``` escapes before and after your text.

- If possible, try to create a test case or project that replicates the problem and attach it to the issue.

## Contributing

Before contributing, please read the [contribution](https://github.com/mjovanc/qrypto/blob/master/CONTRIBUTING.md) guide for useful information how to get started with `qrypto` as well as what should be included when submitting a contribution to the project.

## Acknowledgements

`qrypto` builds on [NIST](https://www.nist.gov)’s post-quantum cryptography standards (FIPS 203, 204, 205) and leverages the Rust ecosystem,
including the rand crate for secure RNG. Thanks to the Rust community and PQC researchers for paving the way!

## License

The MIT License.
