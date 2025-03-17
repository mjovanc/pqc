use error::QryptoError;
use traits::KeyEncapsulation;

pub mod algorithms;
pub mod error;
pub mod traits;
mod util;

pub fn generate_keypair<A: KeyEncapsulation>() -> Result<A::KeyPair, QryptoError> {
    A::generate_keypair()
}

pub fn encapsulate<A: KeyEncapsulation>(pk: &A::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    A::encapsulate(pk)
}

pub fn decapsulate<A: KeyEncapsulation>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}
