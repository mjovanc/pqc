use rand::RngCore;

use crate::error::QryptoError;

pub trait KeyPair {
    type PublicKey;
    type SecretKey;
}

pub trait KEM {
    type KeyPair: KeyPair<PublicKey = Self::PublicKey, SecretKey = Self::SecretKey>;
    type PublicKey;
    type SecretKey;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError>;
    fn generate_keypair_with_seed(seed: &[u8]) -> Result<Self::KeyPair, QryptoError>;
    fn generate_keypair_with_rng(rng: &mut dyn RngCore) -> Result<Self::KeyPair, QryptoError>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError>;
    fn encapsulate_with_rng(pk: &Self::PublicKey, rng: &mut dyn RngCore) -> Result<(Vec<u8>, Vec<u8>), QryptoError>;
    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError>;
}
