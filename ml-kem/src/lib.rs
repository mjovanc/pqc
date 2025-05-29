use zeroize::{Zeroize, ZeroizeOnDrop};

pub mod algorithm;
pub mod error;
mod math;
pub mod params;

use error::MlKemError;
use params::MlKemParams;

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
    pub fn new<P: MlKemParams>(bytes: Vec<u8>) -> Result<Self, MlKemError> {
        if bytes.len() != P::PK_SIZE {
            return Err(MlKemError::KeyLengthError {
                expected: P::PK_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(PublicKey { bytes })
    }
}

impl SecretKey {
    pub fn new<P: MlKemParams>(bytes: Vec<u8>) -> Result<Self, MlKemError> {
        if bytes.len() != P::SK_SIZE {
            return Err(MlKemError::KeyLengthError {
                expected: P::SK_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(SecretKey { bytes })
    }
}

impl Ciphertext {
    pub fn new<P: MlKemParams>(bytes: Vec<u8>) -> Result<Self, MlKemError> {
        if bytes.len() != P::CT_SIZE {
            return Err(MlKemError::CiphertextLengthError {
                expected: P::CT_SIZE,
                actual: bytes.len(),
            });
        }
        Ok(Ciphertext { bytes })
    }
}

pub struct MlKem<P: MlKemParams> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: MlKemParams> MlKem<P> {
    pub fn new() -> Self {
        MlKem {
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn generate_keypair(&self) -> Result<(PublicKey, SecretKey), MlKemError> {
        algorithm::generate_keypair::<P>()
    }

    pub fn encapsulate(&self, pk: &PublicKey) -> Result<(Ciphertext, SharedSecret), MlKemError> {
        algorithm::encapsulate::<P>(pk)
    }

    pub fn decapsulate(&self, sk: &SecretKey, ct: &Ciphertext) -> Result<SharedSecret, MlKemError> {
        algorithm::decapsulate::<P>(sk, ct)
    }
}
