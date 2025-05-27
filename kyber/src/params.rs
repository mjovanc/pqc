/// Common polynomial constants shared by all Kyber parameter sets.
pub trait PolynomialParams {
    /// Number of coefficients in a polynomial.
    const N: usize;
    /// Modulus used in polynomial operations.
    const Q: i32;
}

/// Main trait defining parameters for a Kyber security level.
///
/// Each Kyber variant (512/768/1024) implements this trait with fixed constants that determine key sizes,
/// noise sampling bounds, and compression parameters.
pub trait KyberParams: PolynomialParams {
    /// Matrix dimension (2/3/4 for Kyber512/768/1024).
    const K: usize;
    /// Noise parameter for key generation.
    const ETA1: u32;
    /// Noise parameter for encryption.
    const ETA2: u32;
    /// Bit-length for compressing `u` vector.
    const DU: u32;
    /// Bit-length for compressing `v` vector.
    const DV: u32;
    /// Public key size in bytes.
    const PK_SIZE: usize;
    /// Secret key size in bytes.
    const SK_SIZE: usize;
    /// Ciphertext size in bytes.
    const CT_SIZE: usize;
}

/// Parameter set for Kyber512 (NIST Level 1).
///
/// Provides the smallest key and ciphertext sizes, fastest performance, and lowest bandwidth requirements.
/// Suitable for most constrained applications.
pub struct Kyber512;

impl PolynomialParams for Kyber512 {
    const N: usize = 256;
    const Q: i32 = 3329;
}

impl KyberParams for Kyber512 {
    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const PK_SIZE: usize = 800;
    const SK_SIZE: usize = 1632;
    const CT_SIZE: usize = 768;
}

/// Parameter set for Kyber768 (NIST Level 3).
///
/// Offers a balanced trade-off between performance and security. Ideal for most general-purpose use cases.
pub struct Kyber768;

impl PolynomialParams for Kyber768 {
    const N: usize = 256;
    const Q: i32 = 3329;
}

impl KyberParams for Kyber768 {
    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const PK_SIZE: usize = 1184;
    const SK_SIZE: usize = 2400;
    const CT_SIZE: usize = 1088;
}

/// Parameter set for Kyber1024 (NIST Level 5).
///
/// Provides the highest post-quantum security level, at the cost of larger key and ciphertext sizes.
/// Recommended for high-assurance applications.
pub struct Kyber1024;

impl PolynomialParams for Kyber1024 {
    const N: usize = 256;
    const Q: i32 = 3329;
}

impl KyberParams for Kyber1024 {
    const K: usize = 4;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 11;
    const DV: u32 = 5;
    const PK_SIZE: usize = 1568;
    const SK_SIZE: usize = 3168;
    const CT_SIZE: usize = 1568;
}
