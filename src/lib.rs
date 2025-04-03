use error::QryptoError;
use traits::Algorithm;

pub mod algorithms;
pub mod error;
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

pub fn serialize_public_key<A: Algorithm>(pk: &A::PublicKey) -> Vec<u8> {
    A::serialize_public_key(pk)
}

pub fn deserialize_public_key<A: Algorithm>(bytes: &[u8]) -> Result<A::PublicKey, QryptoError> {
    A::deserialize_public_key(bytes)
}

pub fn serialize_secret_key<A: Algorithm>(sk: &A::SecretKey) -> Vec<u8> {
    A::serialize_secret_key(sk)
}

pub fn deserialize_secret_key<A: Algorithm>(bytes: &[u8]) -> Result<A::SecretKey, QryptoError> {
    A::deserialize_secret_key(bytes)
}