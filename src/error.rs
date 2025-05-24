use thiserror::Error;

#[derive(Error, Debug)]
pub enum QryptoError {
    #[error("Invalid key length")]
    InvalidKeyLength,
    #[error("Encapsulation failed")]
    EncapsulationFailed,
    #[error("Decapsulation failed")]
    DecapsulationFailed,
    #[error("Random key generation failed")]
    RandomGenerationFailed,
    #[error("Serialization failed")]
    SerializationError,
    #[error("Invalid parameter")]
    InvalidParameter,
    #[error("Invalid input")]
    InvalidInput,
}
