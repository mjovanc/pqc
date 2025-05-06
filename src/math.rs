use crate::algorithms::KyberParams;

pub struct Polynomial<P: KyberParams> {
    coeffs: Vec<i16>,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: KyberParams> Clone for Polynomial<P> {
    fn clone(&self) -> Self {
        Polynomial {
            coeffs: self.coeffs.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: KyberParams> Default for Polynomial<P> {
    fn default() -> Self {
        Polynomial::new()
    }
}

impl<P: KyberParams> Polynomial<P> {
    pub fn new() -> Self {
        Polynomial {
            coeffs: vec![0; P::N],
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            result.coeffs[i] = (self.coeffs[i] + other.coeffs[i]) % P::Q as i16;
            if result.coeffs[i] < 0 {
                result.coeffs[i] += P::Q as i16;
            }
        }
        result
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            for j in 0..P::N {
                let k = (i + j) % P::N;
                let sign = if i + j >= P::N { -1 } else { 1 };
                // Use i32 for intermediate calculation to prevent overflow
                let product = sign * self.coeffs[i] as i32 * other.coeffs[j] as i32;
                let reduced = (result.coeffs[k] as i32 + product) % P::Q;
                result.coeffs[k] = reduced as i16;
                if result.coeffs[k] < 0 {
                    result.coeffs[k] += P::Q as i16;
                }
            }
        }
        result
    }

    pub fn compress(&self, d: u32) -> Self {
        let mut result = Polynomial::new();
        let q = P::Q as u64; // Use u64 for modulo
        let d_mask = (1u64 << d) - 1;
        for i in 0..P::N {
            // Handle signed coefficient with u64 to avoid overflow
            let coeff = self.coeffs[i] as i64;
            let shift = 1u64 << d;
            // Convert to u64 for multiplication, add q/2 for rounding
            let scaled = (coeff as u64).wrapping_mul(shift) + q / 2;
            let c = (scaled / q) & d_mask;
            result.coeffs[i] = c as i16;
        }
        result
    }

    pub fn to_compressed_bytes(&self, d: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        let mut buffer = 0u64; // Use u64 to prevent overflow
        let mut bits_in_buffer = 0u32;

        for &coeff in self.coeffs.iter() {
            let coeff = coeff as u64; // Use u64 for shifting
            buffer |= coeff << bits_in_buffer;
            bits_in_buffer += d;

            while bits_in_buffer >= 8 {
                bytes.push((buffer & 0xFF) as u8);
                buffer >>= 8;
                bits_in_buffer -= 8;
            }
        }

        if bits_in_buffer > 0 {
            bytes.push((buffer & 0xFF) as u8);
        }

        bytes
    }
}

pub struct PolyVec<P: KyberParams> {
    vec: Vec<Polynomial<P>>,
}

impl<P: KyberParams> PolyVec<P> {
    pub fn new(size: usize) -> Self {
        let mut vec = Vec::with_capacity(size);
        for _ in 0..size {
            vec.push(Polynomial::new());
        }
        PolyVec { vec }
    }

    pub fn get_vec(&self) -> &Vec<Polynomial<P>> {
        &self.vec
    }

    pub fn get_vec_mut(&mut self) -> &mut Vec<Polynomial<P>> {
        &mut self.vec
    }

    pub fn add(&self, other: &Self) -> Self {
        if self.vec.len() != other.vec.len() {
            panic!("PolyVec size mismatch");
        }
        let mut result = PolyVec::new(self.vec.len());
        for i in 0..self.vec.len() {
            result.vec[i] = self.vec[i].add(&other.vec[i]);
        }
        result
    }

    pub fn to_compressed_bytes(&self, d: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for poly in &self.vec {
            bytes.extend_from_slice(&poly.to_compressed_bytes(d));
        }
        bytes
    }
}

pub struct PolyMatrix<P: KyberParams> {
    matrix: Vec<Vec<Polynomial<P>>>,
}

impl<P: KyberParams> PolyMatrix<P> {
    pub fn new(rows: usize, cols: usize) -> Self {
        let mut matrix = Vec::with_capacity(rows);
        for _ in 0..rows {
            let mut row = Vec::with_capacity(cols);
            for _ in 0..cols {
                row.push(Polynomial::new());
            }
            matrix.push(row);
        }
        PolyMatrix { matrix }
    }

    pub fn get_matrix_mut(&mut self) -> &mut Vec<Vec<Polynomial<P>>> {
        &mut self.matrix
    }

    pub fn mul_vec(&self, vec: &PolyVec<P>) -> PolyVec<P> {
        let rows = self.matrix.len();
        let cols = self.matrix[0].len();
        if cols != vec.vec.len() {
            panic!("Matrix-vector size mismatch");
        }
        let mut result = PolyVec::new(rows);
        for i in 0..rows {
            let mut sum = Polynomial::new();
            for j in 0..cols {
                let prod = self.matrix[i][j].mul(&vec.vec[j]);
                sum = sum.add(&prod);
            }
            result.vec[i] = sum;
        }
        result
    }
}

pub fn sample_cbd<P: KyberParams>(eta: u32, bytes: &[u8]) -> Polynomial<P> {
    let mut coeffs = vec![0i16; P::N];
    let bits_needed = eta as usize * 2;
    let bytes_needed = (bits_needed * P::N + 7) / 8;
    if bytes.len() < bytes_needed {
        panic!("Insufficient random bytes for CBD");
    }
    let mut bit_idx = 0;
    let mut byte_idx = 0;
    for i in 0..P::N {
        let mut sum = 0i16;
        for _ in 0..eta {
            let byte = bytes[byte_idx];
            let a = (byte >> (bit_idx % 8)) & 1;
            let b = (byte >> ((bit_idx + 1) % 8)) & 1;
            sum += a as i16 - b as i16;
            bit_idx += 2;
            if bit_idx >= 8 {
                bit_idx -= 8;
                byte_idx += 1;
            }
        }
        coeffs[i] = sum;
    }
    Polynomial {
        coeffs,
        _phantom: std::marker::PhantomData,
    }
}