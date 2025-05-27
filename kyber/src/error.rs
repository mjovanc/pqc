use thiserror::Error;

#[derive(Debug, Error)]
pub enum QryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    #[error("Invalid ciphertext length: expected {expected}, got {actual}")]
    InvalidCiphertextLength { expected: usize, actual: usize },
    #[error("Serialization failed: {0}")]
    SerializationFailed(String),
    #[error("Deserialization failed: {0}")]
    DeserializationFailed(String),
    #[error("Hash mismatch")]
    HashMismatch,
    #[error("Parameter error: {0}")]
    ParameterError(String),
    #[error("RNG failure: {0}")]
    RngError(#[from] std::io::Error),
    #[error("Random number generation failed: {0}")]
    RandomError(String),
}
