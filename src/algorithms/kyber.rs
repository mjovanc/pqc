use crate::{
    error::QryptoError,
    math::{Polynomial, PolyVec, PolyMatrix, sample_cbd},
    traits::{Algorithm, KeyPair},
    util::generate_random_bytes,
    algorithms::{KyberParams, Kyber512Params},
};
use sha3::{Digest, Sha3_256};

#[derive(Debug)]
pub struct KyberKeyPair {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl KyberKeyPair {
    pub fn public_key(&self) -> &Vec<u8> {
        &self.public_key
    }

    pub fn secret_key(&self) -> &Vec<u8> {
        &self.secret_key
    }
}

impl KeyPair for KyberKeyPair {
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;
}

pub struct Kyber<P: KyberParams> {
    _phantom: std::marker::PhantomData<P>,
}

impl<P: KyberParams> Algorithm for Kyber<P> {
    type KeyPair = KyberKeyPair;
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError> {
        // 1. Generate random 32-byte seed for matrix A
        let seed = generate_random_bytes(32)?;

        // 2. Generate matrix A (k x k) using SHAKE128 (simplified)
        let mut a = PolyMatrix::<P>::new(P::K, P::K);
        for i in 0..P::K {
            for j in 0..P::K {
                a.get_matrix_mut()[i][j] = Polynomial::new(); // Placeholder
            }
        }

        // 3. Sample secret s and error e from CBD with eta1
        let mut s = PolyVec::<P>::new(P::K);
        let mut e = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let noise = generate_random_bytes((P::ETA1 as usize * P::N).div_ceil(4))?;
            s.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
            let noise = generate_random_bytes((P::ETA1 as usize * P::N).div_ceil(4))?;
            e.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }

        // 4. Compute t = A*s + e
        let t = a.mul_vec(&s).add(&e);

        // 5. Compress t to d_t bits per coefficient
        let mut t_compressed = PolyVec::<P>::new(P::K);
        let d_t = match P::K {
            2 => 12, // Kyber512: t compressed to 12 bits
            3 => 12, // Kyber768: t compressed to 12 bits
            4 => 11, // Kyber1024: t compressed to 11 bits
            _ => return Err(QryptoError::InvalidParameter),
        };
        for i in 0..P::K {
            t_compressed.get_vec_mut()[i] = t.get_vec()[i].compress(d_t);
        }

        // 6. Serialize public key: (t_compressed, seed)
        let t_bytes = t_compressed.to_compressed_bytes(d_t);
        let t_bytes_expected = P::K
            .checked_mul(P::N)
            .and_then(|x| x.checked_mul(d_t as usize))
            .map(|x| x / 8)
            .ok_or(QryptoError::SerializationError)?;
        println!("t_bytes: {:?}", t_bytes.len());
        if t_bytes.len() != t_bytes_expected {
            return Err(QryptoError::SerializationError);
        }

        let mut pk = vec![0u8; P::PK_SIZE];
        pk[0..t_bytes_expected].copy_from_slice(&t_bytes);
        pk[t_bytes_expected..P::PK_SIZE].copy_from_slice(&seed);

        // 7. Serialize secret key: s_compressed, pk_hash, z, pk
        let mut sk = vec![0u8; P::SK_SIZE];
        let d_s = match P::K {
            2 => 12, // Kyber512: s compressed to 12 bits (non-standard)
            3 => 12, // Kyber768: s compressed to 12 bits (non-standard)
            4 => 11, // Kyber1024: s compressed to 11 bits (non-standard)
            _ => return Err(QryptoError::InvalidParameter),
        };
        let mut s_compressed = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            s_compressed.get_vec_mut()[i] = s.get_vec()[i].compress(d_s);
        }
        let s_bytes = s_compressed.to_compressed_bytes(d_s);
        let s_bytes_expected = P::K
            .checked_mul(P::N)
            .and_then(|x| x.checked_mul(d_s as usize))
            .map(|x| x / 8)
            .ok_or(QryptoError::SerializationError)?;
        println!("s_bytes: {:?}", s_bytes.len());
        if s_bytes.len() != s_bytes_expected {
            return Err(QryptoError::SerializationError);
        }

        let sk_t_offset = s_bytes_expected;
        let sk_hash_offset = sk_t_offset + 32;
        let sk_z_offset = sk_hash_offset + 32;

        sk[0..sk_t_offset].copy_from_slice(&s_bytes);
        let pk_hash = Sha3_256::digest(&pk);
        sk[sk_t_offset..sk_hash_offset].copy_from_slice(&pk_hash);
        let z = generate_random_bytes(32)?;
        sk[sk_hash_offset..sk_z_offset].copy_from_slice(&z);
        sk[sk_z_offset..P::SK_SIZE].copy_from_slice(&pk);

        Ok(KyberKeyPair {
            public_key: pk,
            secret_key: sk,
        })
    }

    fn encapsulate(_pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
        todo!("Encapsulate: u = A^T*r + e1, v = t^T*r + e2 + Compress(m)")
    }

    fn decapsulate(_sk: &Self::SecretKey, _ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
        todo!("Decapsulate: m' = Decompress(v - s^T*u)")
    }
}

pub type Kyber512 = Kyber<Kyber512Params>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generate_keypair;

    #[test]
    fn kyber512_generate_keypair() {
        let keypair = generate_keypair::<Kyber512>().expect("Keypair generation failed");
        println!("public key length: {:?}", keypair.public_key().len());
        println!("secret key length: {:?}", keypair.secret_key().len());
        assert_eq!(keypair.public_key().len(), Kyber512Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber512Params::SK_SIZE);
    }
}