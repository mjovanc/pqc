pub mod kyber;

pub use kyber::Kyber512;

pub trait KyberParams {
    const N: usize; // Polynomial degree
    const Q: i32;   // Modulus
    const K: usize; // Module rank
    const ETA1: u32; // Noise parameter for s, e
    const ETA2: u32; // Noise parameter for encapsulation
    const DU: u32;   // Compression bits for u
    const DV: u32;   // Compression bits for v
    const PK_SIZE: usize; // Public key size
    const SK_SIZE: usize; // Secret key size
    const CT_SIZE: usize; // Ciphertext size
}

pub struct Kyber512Params;
impl KyberParams for Kyber512Params {
    const N: usize = 256;
    const Q: i32 = 3329;
    const K: usize = 2;
    const ETA1: u32 = 3;
    const ETA2: u32 = 2;
    const DU: u32 = 10;
    const DV: u32 = 4;
    const PK_SIZE: usize = 800;
    const SK_SIZE: usize = 1632;
    const CT_SIZE: usize = 768;
}

