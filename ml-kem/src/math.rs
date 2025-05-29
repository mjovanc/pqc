use log::debug;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake128,
};
use std::ops::Sub;

use crate::{error::MlKemError, params::PolynomialParams};

#[derive(Debug)]
pub struct Polynomial<P: PolynomialParams> {
    coeffs: Vec<i16>,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: PolynomialParams> Clone for Polynomial<P> {
    fn clone(&self) -> Self {
        Polynomial {
            coeffs: self.coeffs.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<P: PolynomialParams> Default for Polynomial<P> {
    fn default() -> Self {
        Polynomial::new()
    }
}

impl<P: PolynomialParams> Polynomial<P> {
    pub fn new() -> Self {
        Polynomial {
            coeffs: vec![0; P::N],
            _phantom: std::marker::PhantomData,
        }
    }

    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn get_coeffs(&self) -> &[i16] {
        &self.coeffs
    }

    pub fn reduce_mod_q(&self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            let mut coeff = self.coeffs[i] as i32 % P::Q as i32;
            if coeff < 0 {
                coeff += P::Q as i32;
            }
            result.coeffs[i] = coeff as i16;
        }
        result
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

    pub fn neg(&self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            result.coeffs[i] = (P::Q as i16 - self.coeffs[i]) % P::Q as i16;
        }
        result
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            for j in 0..P::N {
                let k = (i + j) % P::N;
                let sign = if i + j >= P::N { -1 } else { 1 };
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
        let q = P::Q as u64;
        let d_mask = (1u64 << d) - 1;
        for i in 0..P::N {
            let coeff = self.coeffs[i] as i64;
            // Ensure coefficient is in [0, q)
            let coeff = if coeff < 0 {
                coeff + P::Q as i64
            } else {
                coeff
            } % P::Q as i64;
            let c = if d == 1 {
                // Map to 0 if closer to 0, 1 if closer to q/2
                let q = P::Q as i64;
                if coeff < q / 4 {
                    0
                } else {
                    1
                }
            } else {
                let scaled = ((coeff as u64 * (1u64 << d)) + (q / 2)) / q;
                scaled & d_mask
            };
            result.coeffs[i] = c as i16;
        }
        debug!(
            "compress(d={}) output coefficients: {:?}",
            d,
            result.get_coeffs()
        );
        result
    }

    pub fn decompress(bytes: &[u8], d: u32) -> Result<Self, MlKemError> {
        let mut coeffs = vec![0i16; P::N];
        let q = P::Q as u64;
        let bits_per_coeff = d as usize;
        let bytes_needed = (P::N * bits_per_coeff).div_ceil(8);
        if bytes.len() < bytes_needed {
            return Err(MlKemError::DeserializationError(format!(
                "Expected at least {} bytes, got {}",
                bytes_needed,
                bytes.len()
            )));
        }

        let mut bit_idx = 0;
        let mut byte_idx = 0;
        for i in 0..P::N {
            let mut y = 0u64;
            let bits_to_read = bits_per_coeff;
            let mut bits_read = 0;

            while bits_read < bits_to_read {
                if byte_idx >= bytes.len() {
                    return Err(MlKemError::DeserializationError(
                        "Insufficient bytes for decompression".to_string(),
                    ));
                }
                let bits_available = 8 - (bit_idx % 8);
                let bits_needed = bits_to_read - bits_read;
                let bits_to_take = bits_available.min(bits_needed);
                let mask = (1u64 << bits_to_take) - 1;
                let value = ((bytes[byte_idx] as u64) >> (bit_idx % 8)) & mask;
                y |= value << bits_read;
                bits_read += bits_to_take;
                bit_idx += bits_to_take;
                if bit_idx >= 8 {
                    bit_idx -= 8;
                    byte_idx += 1;
                }
            }

            let decompressed = if d == 1 {
                // For d=1, map 0 to 0, 1 to q/2
                if y == 0 {
                    0
                } else {
                    (q / 2) as u64
                }
            } else {
                // General case for d > 1
                (y * q + (1u64 << (d - 1))) >> d
            };
            if decompressed >= q {
                return Err(MlKemError::DeserializationError(
                    "Decompressed coefficient too large".to_string(),
                ));
            }
            coeffs[i] = decompressed as i16;
        }

        Ok(Polynomial {
            coeffs,
            _phantom: std::marker::PhantomData,
        })
    }

    pub fn to_compressed_bytes(&self, d: u32) -> Vec<u8> {
        debug!(
            "to_compressed_bytes(d={}) input coefficients: {:?}",
            d,
            self.get_coeffs()
        );
        let mut bytes = Vec::new();
        let mut buffer = 0u64;
        let mut bits_in_buffer = 0u32;

        for &coeff in self.coeffs.iter() {
            let coeff = coeff as u64;
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

impl<P: PolynomialParams> Sub for Polynomial<P> {
    type Output = Self;

    fn sub(self, other: Self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            result.coeffs[i] = (self.coeffs[i] - other.coeffs[i]) % P::Q as i16;
            if result.coeffs[i] < 0 {
                result.coeffs[i] += P::Q as i16;
            }
        }
        result
    }
}

impl<P: PolynomialParams> Sub<&Self> for Polynomial<P> {
    type Output = Self;

    fn sub(self, other: &Self) -> Self {
        let mut result = Polynomial::new();
        for i in 0..P::N {
            result.coeffs[i] = (self.coeffs[i] - other.coeffs[i]) % P::Q as i16;
            if result.coeffs[i] < 0 {
                result.coeffs[i] += P::Q as i16;
            }
        }
        result
    }
}

#[derive(Default)]
pub struct PolyVec<P: PolynomialParams> {
    vec: Vec<Polynomial<P>>,
}

impl<P: PolynomialParams> PolyVec<P> {
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
            return PolyVec {
                vec: vec![Polynomial::new(); self.vec.len()],
            }; // Silently return a default vector to avoid panic
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

    pub fn decompress(bytes: &[u8], d: u32) -> Result<Self, MlKemError> {
        let bytes_per_poly = (P::N * d as usize).div_ceil(8);
        if bytes.len() % bytes_per_poly != 0 {
            return Err(MlKemError::DeserializationError(
                "Invalid byte length for polyvec".to_string(),
            ));
        }
        let num_polys = bytes.len() / bytes_per_poly;
        let mut vec = Vec::with_capacity(num_polys);
        for i in 0..num_polys {
            let start = i * bytes_per_poly;
            let end = start + bytes_per_poly;
            let poly = Polynomial::<P>::decompress(&bytes[start..end], d)?;
            vec.push(poly);
        }
        Ok(PolyVec { vec })
    }

    pub fn dot_product(&self, other: &Self) -> Result<Polynomial<P>, MlKemError> {
        if self.vec.len() != other.vec.len() {
            return Err(MlKemError::ParameterError(format!(
                "Invalid vector length: expected {}, got {}",
                self.vec.len(),
                other.vec.len()
            )));
        }
        let mut result = Polynomial::new();
        for i in 0..self.vec.len() {
            let prod = self.vec[i].mul(&other.vec[i]);
            result = result.add(&prod);
        }
        Ok(result.reduce_mod_q()) // Ensure result is reduced
    }
}

#[derive(Default)]
pub struct PolyMatrix<P: PolynomialParams> {
    matrix: Vec<Vec<Polynomial<P>>>,
}

impl<P: PolynomialParams> PolyMatrix<P> {
    pub fn new(rows: usize, cols: usize) -> Self {
        let mut matrix = Vec::with_capacity(rows);
        for _ in 0..rows {
            let row = vec![Polynomial::new(); cols];
            matrix.push(row);
        }
        PolyMatrix { matrix }
    }

    pub fn get_matrix_mut(&mut self) -> &mut Vec<Vec<Polynomial<P>>> {
        &mut self.matrix
    }

    pub fn mul_vec(&self, vec: &PolyVec<P>) -> PolyVec<P> {
        let rows = self.matrix.len();
        let cols = if rows > 0 { self.matrix[0].len() } else { 0 };
        if cols != vec.vec.len() {
            return PolyVec::new(rows); // Silently return a default vector
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

    pub fn transpose(&self) -> Self {
        let rows = self.matrix.len();
        let cols = if rows > 0 { self.matrix[0].len() } else { 0 };
        let mut result = PolyMatrix::new(cols, rows);
        for i in 0..rows {
            for j in 0..cols {
                result.matrix[j][i] = self.matrix[i][j].clone();
            }
        }
        result
    }
}

pub fn sample_cbd<P: PolynomialParams>(eta: u32, bytes: &[u8]) -> Polynomial<P> {
    let mut coeffs = vec![0i16; P::N];
    let bits_needed = eta as usize * 2;
    let bytes_needed = (bits_needed * P::N).div_ceil(8);
    if bytes.len() < bytes_needed {
        return Polynomial::new(); // Silently return a default polynomial
    }
    let mut bit_idx = 0;
    let mut byte_idx = 0;
    for i in 0..P::N {
        let mut sum = 0i16;
        for _ in 0..eta {
            if byte_idx >= bytes.len() {
                return Polynomial::new();
            }
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

pub fn sample_uniform<P: PolynomialParams>(reader: &mut dyn XofReader) -> Polynomial<P> {
    let mut coeffs = vec![0i16; P::N];
    let mut byte_buf = [0u8; 2];
    for i in 0..P::N {
        let mut x: u16;
        loop {
            reader.read(&mut byte_buf);
            x = ((byte_buf[0] as u16) | ((byte_buf[1] as u16) << 8)) & 0x1FFF;
            if i32::from(x) < P::Q {
                break;
            }
        }
        coeffs[i] = x as i16;
    }
    Polynomial {
        coeffs,
        _phantom: std::marker::PhantomData,
    }
}

pub fn generate_matrix<P: PolynomialParams>(
    seed: &[u8],
    rows: usize,
    cols: usize,
) -> PolyMatrix<P> {
    let mut a = PolyMatrix::<P>::new(rows, cols);
    for i in 0..rows {
        for j in 0..cols {
            let mut hasher = Shake128::default();
            hasher.update(seed);
            hasher.update(&[i as u8, j as u8]);
            let mut reader = hasher.finalize_xof();
            a.get_matrix_mut()[i][j] = sample_uniform::<P>(&mut reader);
        }
    }
    a
}
