use std::fmt;
use thiserror::Error;

/// Represents all possible errors that can occur in the qrypto library.
/// This enum implements the standard Error trait through thiserror.
#[derive(Error, Debug)]
pub enum QryptoError {
    /// Errors related to cryptographic keys
    #[error("Key error: {kind}")]
    KeyError {
        kind: KeyErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to algorithm operations
    #[error("Algorithm error: {kind}")]
    AlgorithmError {
        kind: AlgorithmErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to parameter validation
    #[error("Parameter error: {kind}")]
    ParameterError {
        kind: ParameterErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to data encoding/decoding
    #[error("Encoding error: {kind}")]
    EncodingError {
        kind: EncodingErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to hybrid cryptography operations
    #[error("Hybrid scheme error: {kind}")]
    HybridError {
        kind: HybridErrorKind,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Errors related to random number generation
    #[error("Random generation error: {0}")]
    RandomError(String),

    /// Generic error for when no specific error type fits
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Specific types of key-related errors
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeyErrorKind {
    /// Key length is invalid for the specified algorithm
    InvalidLength { algorithm: String, expected: usize, actual: usize },
    /// Key format is invalid
    InvalidFormat,
    /// Key generation failed
    GenerationFailed,
    /// Key derivation failed
    DerivationFailed,
    /// Invalid key type for operation
    InvalidKeyType,
}

/// Specific types of algorithm-related errors
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum AlgorithmErrorKind {
    /// Encapsulation operation failed
    EncapsulationFailed,
    /// Decapsulation operation failed
    DecapsulationFailed,
    /// Signature generation failed
    SigningFailed,
    /// Signature verification failed
    VerificationFailed,
    /// Algorithm not supported
    UnsupportedAlgorithm(String),
    /// Invalid algorithm parameters
    InvalidParameters,
}

/// Specific types of parameter-related errors
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ParameterErrorKind {
    /// Invalid security level
    InvalidSecurityLevel { minimum: usize, provided: usize },
    /// Invalid polynomial degree
    InvalidPolynomialDegree,
    /// Invalid modulus
    InvalidModulus,
    /// Invalid noise parameter
    InvalidNoiseParameter,
    /// Invalid vector length for operation
    InvalidVectorLength { expected: usize, actual: usize },
    /// Invalid hash value
    InvalidHash,
    /// Invalid key length
    InvalidKeyLength { expected: usize, actual: usize },
    /// Invalid ciphertext length
    InvalidCiphertextLength { expected: usize, actual: usize },
}

/// Specific types of encoding-related errors
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum EncodingErrorKind {
    /// Serialization failed
    SerializationFailed,
    /// Deserialization failed
    DeserializationFailed,
    /// Compression failed
    CompressionFailed,
    /// Decompression failed
    DecompressionFailed,
    /// Invalid format
    InvalidFormat,
}

/// Specific types of hybrid scheme-related errors
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HybridErrorKind {
    /// Classical algorithm failed
    ClassicalFailed,
    /// Quantum algorithm failed
    QuantumFailed,
    /// Key combination failed
    KeyCombinationFailed,
    /// Incompatible algorithms
    IncompatibleAlgorithms,
}

// Implement Display for all error kinds
impl fmt::Display for KeyErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLength { algorithm, expected, actual } => {
                write!(f, "Invalid key length for {}: expected {}, got {}", algorithm, expected, actual)
            }
            Self::InvalidFormat => write!(f, "Invalid key format"),
            Self::GenerationFailed => write!(f, "Key generation failed"),
            Self::DerivationFailed => write!(f, "Key derivation failed"),
            Self::InvalidKeyType => write!(f, "Invalid key type"),
        }
    }
}

impl fmt::Display for AlgorithmErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EncapsulationFailed => write!(f, "Encapsulation failed"),
            Self::DecapsulationFailed => write!(f, "Decapsulation failed"),
            Self::SigningFailed => write!(f, "Signature generation failed"),
            Self::VerificationFailed => write!(f, "Signature verification failed"),
            Self::UnsupportedAlgorithm(alg) => write!(f, "Unsupported algorithm: {}", alg),
            Self::InvalidParameters => write!(f, "Invalid algorithm parameters"),
        }
    }
}

impl fmt::Display for ParameterErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSecurityLevel { minimum, provided } => {
                write!(f, "Invalid security level: minimum {}, provided {}", minimum, provided)
            }
            Self::InvalidPolynomialDegree => write!(f, "Invalid polynomial degree"),
            Self::InvalidModulus => write!(f, "Invalid modulus"),
            Self::InvalidNoiseParameter => write!(f, "Invalid noise parameter"),
            Self::InvalidVectorLength { expected, actual } => {
                write!(f, "Invalid vector length: expected {}, got {}", expected, actual)
            }
            Self::InvalidHash => write!(f, "Invalid hash value"),
            Self::InvalidKeyLength { expected, actual } => {
                write!(f, "Invalid key length: expected {}, got {}", expected, actual)
            }
            Self::InvalidCiphertextLength { expected, actual } => {
                write!(f, "Invalid ciphertext length: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl fmt::Display for EncodingErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SerializationFailed => write!(f, "Serialization failed"),
            Self::DeserializationFailed => write!(f, "Deserialization failed"),
            Self::CompressionFailed => write!(f, "Compression failed"),
            Self::DecompressionFailed => write!(f, "Decompression failed"),
            Self::InvalidFormat => write!(f, "Invalid format"),
        }
    }
}

impl fmt::Display for HybridErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ClassicalFailed => write!(f, "Classical algorithm failed"),
            Self::QuantumFailed => write!(f, "Quantum algorithm failed"),
            Self::KeyCombinationFailed => write!(f, "Key combination failed"),
            Self::IncompatibleAlgorithms => write!(f, "Incompatible algorithms"),
        }
    }
}

impl QryptoError {
    /// Creates a new key error
    pub fn key_error(kind: KeyErrorKind) -> Self {
        QryptoError::KeyError { kind, source: None }
    }

    /// Creates a new algorithm error
    pub fn algorithm_error(kind: AlgorithmErrorKind) -> Self {
        QryptoError::AlgorithmError { kind, source: None }
    }

    /// Creates a new parameter error
    pub fn parameter_error(kind: ParameterErrorKind) -> Self {
        QryptoError::ParameterError { kind, source: None }
    }

    /// Creates a new encoding error
    pub fn encoding_error(kind: EncodingErrorKind) -> Self {
        QryptoError::EncodingError { kind, source: None }
    }

    /// Creates a new hybrid error
    pub fn hybrid_error(kind: HybridErrorKind) -> Self {
        QryptoError::HybridError { kind, source: None }
    }
}

// Implementation to allow using ? operator with std::io::Error
impl From<std::io::Error> for QryptoError {
    fn from(error: std::io::Error) -> Self {
        QryptoError::EncodingError { kind: EncodingErrorKind::SerializationFailed, source: Some(Box::new(error)) }
    }
}

// Helper Macros
#[macro_export]
macro_rules! encoding_err {
    ($kind:expr) => {
        QryptoError::encoding_error($kind)
    };
}

#[macro_export]
macro_rules! param_err {
    ($kind:expr) => {
        QryptoError::parameter_error($kind)
    };
}

#[macro_export]
macro_rules! algo_err {
    ($kind:expr) => {
        QryptoError::algorithm_error($kind)
    };
}

#[macro_export]
macro_rules! key_err {
    ($kind:expr) => {
        QryptoError::key_error($kind)
    };
}
