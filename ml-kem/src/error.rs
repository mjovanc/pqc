use thiserror::Error;

#[derive(Debug, Error)]
pub enum MlKemError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    KeyLengthError { expected: usize, actual: usize },
    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    CiphertextLengthError { expected: usize, actual: usize },
    #[error("Serialization failed: {0}")]
    SerializationError(String),
    #[error("Deserialization failed: {0}")]
    DeserializationError(String),
    #[error("Hash mismatch")]
    HashMismatchError,
    #[error("Parameter error: {0}")]
    ParameterError(String),
    #[error("RNG failure: {0}")]
    RngError(#[from] std::io::Error),
    #[error("Random number generation failed: {0}")]
    RandomError(String),
    #[error("Invalid input: {0}")]
    InputError(String),
}
