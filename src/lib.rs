use error::QryptoError;
use traits::KEMAlgorithm;

pub mod algorithms;
mod crypto;
pub mod error;
mod math;
pub mod traits;

pub fn generate_keypair<A: KEMAlgorithm>() -> Result<A::KeyPair, QryptoError> {
    A::generate_keypair()
}

pub fn encapsulate<A: KEMAlgorithm>(pk: &A::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    A::encapsulate(pk)
}

pub fn decapsulate<A: KEMAlgorithm>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}
