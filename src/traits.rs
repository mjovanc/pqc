use crate::error::QryptoError;

pub trait KeyPair {
    type PublicKey;
    type SecretKey;
}

pub trait Algorithm {
    type KeyPair: KeyPair<PublicKey = Self::PublicKey, SecretKey = Self::SecretKey>;
    type PublicKey;
    type SecretKey;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError>;
    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError>; // (ciphertext, shared_secret)
    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError>; // shared_secret

    fn serialize_public_key(pk: &Self::PublicKey) -> Vec<u8>;
    fn deserialize_public_key(bytes: &[u8]) -> Result<Self::PublicKey, QryptoError>;
    fn serialize_secret_key(sk: &Self::SecretKey) -> Vec<u8>;
    fn deserialize_secret_key(bytes: &[u8]) -> Result<Self::SecretKey, QryptoError>;
}
