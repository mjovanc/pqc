pub trait PolynomialParams {
    const N: usize;
    const Q: i32;
}

pub trait KyberParams: PolynomialParams {
    const K: usize;
    const ETA1: u32;
    const ETA2: u32;
    const DU: u32;
    const DV: u32;
    const PK_SIZE: usize;
    const SK_SIZE: usize;
    const CT_SIZE: usize;
}

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
