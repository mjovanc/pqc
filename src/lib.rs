use error::QryptoError;
use traits::Algorithm;

pub mod algorithms;
pub mod error;
mod math;
pub mod traits;
mod util;

pub fn generate_keypair<A: Algorithm>() -> Result<A::KeyPair, QryptoError> {
    A::generate_keypair()
}

pub fn encapsulate<A: Algorithm>(pk: &A::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    A::encapsulate(pk)
}

pub fn decapsulate<A: Algorithm>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}