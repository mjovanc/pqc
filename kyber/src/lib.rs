//! # Kyber Post-Quantum KEM (Key Encapsulation Mechanism)
//!
//! This crate implements a clean, idiomatic, and safe Rust interface to the Kyber KEM algorithm,
//! part of the CRYSTALS suite that is included in one the NIST standards. Kyber is designed to be secure
//! against quantum adversaries and supports three security levels: Kyber512, Kyber768, and Kyber1024.
//!
//! The API provides key generation, encapsulation, and decapsulation, with strong typing for
//! public/secret keys and ciphertexts.
//!
//! ## Example
//! ```rust
//! use kyber::{Kyber, KyberError};
//! use kyber::params::Kyber512;
//!
//! fn main() -> Result<(), KyberError> {
//!     let kyber = Kyber::<Kyber512>::new();
//!     let (pk, sk) = kyber.generate_keypair()?;
//!     let (ct, ss1) = kyber.encapsulate(&pk)?;
//!     let ss2 = kyber.decapsulate(&sk, &ct)?;
//!
//!     assert_eq!(ss1.0, ss2.0);
//!     Ok(())
//! }
//! ```
//!
//! ## Errors
//! All cryptographic operations return `KyberError` variants:
//! - `KeyLengthError`: If a key or ciphertext vector is not the correct size.
//! - `EncapsulationError` / `DecapsulationError`: Failures in cryptographic steps.
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod algorithm;
pub mod error;
mod math;
pub mod params;

use error::KyberError;
use params::KyberParams;

/// A Kyber public key used for encapsulation.
///
/// Validated against the expected size (`PK_SIZE`) from a `KyberParams` implementation.
/// Safe to clone and debug, and its memory is securely zeroed on drop.
#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

/// A Kyber secret key used for decapsulation.
///
/// Must be securely stored and never cloned. Implements zeroization on drop to protect memory.
#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

/// A Kyber ciphertext used to carry a shared secret.
///
/// Created during encapsulation and required for decapsulation.
#[derive(Clone, Debug)]
pub struct Ciphertext {
    bytes: Vec<u8>,
}

/// A 32-byte shared secret derived from encapsulation or decapsulation.
///
/// The inner array is public but should be handled securely. Zeroed on drop.
#[derive(Clone, Debug, Zeroize)]
pub struct SharedSecret(pub [u8; 32]);

impl PublicKey {
    /// Create a new public key from raw bytes.
    ///
    /// # Errors
    /// Returns `KeyLengthError` if `bytes.len()` does not match `P::PK_SIZE`.
    pub fn new<P: KyberParams>(bytes: Vec<u8>) -> Result<Self, KyberError> {
        if bytes.len() != P::PK_SIZE {
            return Err(KyberError::KeyLengthError {
                expected: P::PK_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(PublicKey { bytes })
    }
}

impl SecretKey {
    /// Create a new secret key from raw bytes.
    ///
    /// # Errors
    /// Returns `KeyLengthError` if `bytes.len()` does not match `P::SK_SIZE`.
    pub fn new<P: KyberParams>(bytes: Vec<u8>) -> Result<Self, KyberError> {
        if bytes.len() != P::SK_SIZE {
            return Err(KyberError::KeyLengthError {
                expected: P::SK_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(SecretKey { bytes })
    }
}

impl Ciphertext {
    /// Create a new ciphertext from raw bytes.
    ///
    /// # Errors
    /// Returns `CiphertextLengthError` if `bytes.len()` does not match `P::CT_SIZE`.
    pub fn new<P: KyberParams>(bytes: Vec<u8>) -> Result<Self, KyberError> {
        if bytes.len() != P::CT_SIZE {
            return Err(KyberError::CiphertextLengthError {
                expected: P::CT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Ciphertext { bytes })
    }
}

/// Main Kyber API interface for a specific security level.
///
/// Constructed via `Kyber::<Kyber512>::new()` or other parameter sets.
/// Provides methods for keypair generation, encapsulation, and decapsulation.
pub struct Kyber<P: KyberParams> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: KyberParams> Kyber<P> {
    /// Create a new instance of the Kyber KEM using parameters `P`.
    pub fn new() -> Self {
        Kyber {
            _phantom: std::marker::PhantomData,
        }
    }

    /// Generate a public/secret keypair.
    ///
    /// # Errors
    /// Returns `KyberError::KeygenError` if entropy or math operations fail.
    pub fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), KyberError> {
        algorithm::generate_keypair::<P>()
    }

    /// Encapsulate a shared secret to the given public key.
    ///
    /// Returns a ciphertext and the shared secret.
    ///
    /// # Errors
    /// Returns `KyberError::EncapsulationError` if encryption fails.
    pub fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KyberError> {
        algorithm::encapsulate::<P>(pk)
    }

    /// Decapsulate a shared secret from the given ciphertext and secret key.
    ///
    /// # Errors
    /// Returns `KyberError::DecapsulationError` if the ciphertext is malformed or authentication fails.
    pub fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, KyberError> {
        algorithm::decapsulate::<P>(sk, ct)
    }
}
