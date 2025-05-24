use error::QryptoError;
use rand::RngCore;
use traits::KEM;

mod crypto;
pub mod error;
pub mod kem;
mod math;
pub mod traits;

pub fn generate_keypair<A: KEM>(rng: Option<&mut dyn RngCore>) -> Result<A::KeyPair, QryptoError> {
    match rng {
        Some(rng) => A::generate_keypair_with_rng(rng),
        None => A::generate_keypair(),
    }
}

pub fn encapsulate<A: KEM>(pk: &A::PublicKey, rng: Option<&mut dyn RngCore>) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    match rng {
        Some(rng) => A::encapsulate_with_rng(pk, rng),
        None => A::encapsulate(pk),
    }
}

pub fn decapsulate<A: KEM>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}
