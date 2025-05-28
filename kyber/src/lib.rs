//! # Kyber Post-Quantum KEM (Key Encapsulation Mechanism)
//!
//! This crate implements a clean, idiomatic, and safe Rust interface to the Kyber KEM algorithm,
//! part of the CRYSTALS suite that is included in one the NIST standards. Kyber is designed to be secure
//! against quantum adversaries and supports three security levels: Kyber512, Kyber768, and Kyber1024.
//!
//! The API provides key generation, encapsulation, and decapsulation, with strong typing for
//! public/secret keys and ciphertexts.
use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod algorithm;
pub mod error;
mod math;
pub mod params;

use error::KyberError;
use params::KyberParams;

#[derive(Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct PublicKey {
    bytes: Vec<u8>,
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SecretKey {
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Ciphertext {
    bytes: Vec<u8>,
}

#[derive(Clone, Debug, Zeroize)]
pub struct SharedSecret(pub [u8; 32]);

impl PublicKey {
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

pub struct Kyber<P: KyberParams> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: KyberParams> Kyber<P> {
    pub fn new() -> Self {
        Kyber {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), KyberError> {
        algorithm::generate_keypair::<P>()
    }

    pub fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), KyberError> {
        algorithm::encapsulate::<P>(pk)
    }

    pub fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, KyberError> {
        algorithm::decapsulate::<P>(sk, ct)
    }
}
