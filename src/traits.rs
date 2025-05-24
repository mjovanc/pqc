use crate::error::QryptoError;

pub trait KeyPair {
    type PublicKey;
    type SecretKey;
}

pub trait KEMAlgorithm {
    type KeyPair: KeyPair<PublicKey = Self::PublicKey, SecretKey = Self::SecretKey>;
    type PublicKey;
    type SecretKey;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError>; // (ciphertext, shared_secret)
    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError>; // shared_secret
}
