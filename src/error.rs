use thiserror::Error;

#[derive(Error, Debug)]
pub enum QryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Invalid ciphertext")]
    InvalidCiphertext,
}
