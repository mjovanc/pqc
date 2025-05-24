use error::QryptoError;
use traits::KEM;

mod crypto;
pub mod error;
pub mod kem;
mod math;
pub mod traits;

pub fn generate_keypair<A: KEM>() -> Result<A::KeyPair, QryptoError> {
    A::generate_keypair()
}

pub fn encapsulate<A: KEM>(pk: &A::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    A::encapsulate(pk)
}

pub fn decapsulate<A: KEM>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}
