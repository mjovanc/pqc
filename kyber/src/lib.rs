use error::QryptoError;
use traits::KEM;

pub mod algorithm;
mod crypto;
pub mod error;
mod math;
pub mod traits;

pub trait PolynomialParams {
    const N: usize; // Polynomial degree
    const Q: i32; // Modulus
}

pub trait KyberParams: PolynomialParams {
    const K: usize; // Module rank
    const ETA1: u32; // Noise parameter for s, e
    const ETA2: u32; // Noise parameter for encapsulation
    const DU: u32; // Compression bits for u
    const DV: u32; // Compression bits for v
    const PK_SIZE: usize; // Public key size
    const SK_SIZE: usize; // Secret key size
    const CT_SIZE: usize; // Ciphertext size
}

pub struct Kyber512Params;
impl PolynomialParams for Kyber512Params {
    const N: usize = 256;
    const Q: i32 = 3329;
}
impl KyberParams for Kyber512Params {
    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const PK_SIZE: usize = 800;
    const SK_SIZE: usize = 1632;
    const CT_SIZE: usize = 768;
}

pub struct Kyber768Params;
impl PolynomialParams for Kyber768Params {
    const N: usize = 256;
    const Q: i32 = 3329;
}
impl KyberParams for Kyber768Params {
    const K: usize = 3;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const PK_SIZE: usize = 1184;
    const SK_SIZE: usize = 2400;
    const CT_SIZE: usize = 1088;
}

pub struct Kyber1024Params;
impl PolynomialParams for Kyber1024Params {
    const N: usize = 256;
    const Q: i32 = 3329;
}
impl KyberParams for Kyber1024Params {
    const K: usize = 4;
    const ETA1: u32 = 2;
    const ETA2: u32 = 2;
    const DU: u32 = 11;
    const DV: u32 = 5;
    const PK_SIZE: usize = 1568;
    const SK_SIZE: usize = 3168;
    const CT_SIZE: usize = 1568;
}

pub fn generate_keypair<A: KEM>() -> Result<A::KeyPair, QryptoError> {
    A::generate_keypair()
}

pub fn encapsulate<A: KEM>(pk: &A::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
    A::encapsulate(pk)
}

pub fn decapsulate<A: KEM>(sk: &A::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
    A::decapsulate(sk, ciphertext)
}
