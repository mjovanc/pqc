pub mod kyber;

pub use kyber::{Kyber1024, Kyber512, Kyber768};

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
    const DT: u32; // Compression bits for t
    const DS: u32; // Compression bits for s
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
    const DT: u32 = 10;
    const DS: u32 = 10;
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
    const DT: u32 = 10;
    const DS: u32 = 10;
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
    const DT: u32 = 11;
    const DS: u32 = 11;
    const PK_SIZE: usize = 1568;
    const SK_SIZE: usize = 3168;
    const CT_SIZE: usize = 1568;
}
