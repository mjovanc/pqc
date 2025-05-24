use crate::{
    algorithms::{Kyber512Params, KyberParams},
    crypto::{hash::hash_xof, rand::generate_random_bytes},
    error::QryptoError,
    math::{sample_cbd, sample_uniform, PolyMatrix, PolyVec, Polynomial},
    traits::{Algorithm, KeyPair},
};
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512, Shake128, Shake256};

use super::{Kyber1024Params, Kyber768Params};

fn generate_matrix_a<P: KyberParams>(rho: &[u8]) -> PolyMatrix<P> {
    let mut a = PolyMatrix::<P>::new(P::K, P::K);
    for i in 0..P::K {
        for j in 0..P::K {
            let mut hasher = Shake128::default();
            hasher.update(rho);
            hasher.update(&[i as u8, j as u8]);
            let mut reader = hasher.finalize_xof();
            a.get_matrix_mut()[i][j] = sample_uniform::<P>(&mut reader);
        }
    }
    a
}

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
        let seed = generate_random_bytes(32)?;

        let a = generate_matrix_a::<P>(&seed);

        // Sample secret s and error e from CBD with eta1
        let mut s = PolyVec::<P>::new(P::K);
        let mut e = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let noise = generate_random_bytes((P::ETA1 as usize * P::N).div_ceil(4))?;
            s.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
            let noise = generate_random_bytes((P::ETA1 as usize * P::N).div_ceil(4))?;
            e.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }

        // Compute t = A*s + e
        let t = a.mul_vec(&s).add(&e);

        // Compress t to d_t bits per coefficient
        let mut t_compressed = PolyVec::<P>::new(P::K);
        let d_t = 12;
        for i in 0..P::K {
            t_compressed.get_vec_mut()[i] = t.get_vec()[i].compress(d_t);
        }

        // Serialize public key: (t_compressed, seed)
        let t_bytes = t_compressed.to_compressed_bytes(d_t);
        let t_bytes_expected =
            P::K.checked_mul(P::N).and_then(|x| x.checked_mul(d_t as usize)).map(|x| x / 8).ok_or(QryptoError::SerializationError)?;
        if t_bytes.len() != t_bytes_expected {
            return Err(QryptoError::SerializationError);
        }

        let mut pk = vec![0u8; P::PK_SIZE];
        let seed_slice_size = P::PK_SIZE - t_bytes_expected;
        assert_eq!(seed_slice_size, 32, "Expected 32-byte seed space in public key");
        pk[0..t_bytes_expected].copy_from_slice(&t_bytes);
        pk[t_bytes_expected..P::PK_SIZE].copy_from_slice(&seed);

        // Serialize secret key: s, pk_hash, z, pk
        let mut sk = vec![0u8; P::SK_SIZE];
        let d_s = 12; // Full precision for all Kyber variants
        let mut s_compressed = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            s_compressed.get_vec_mut()[i] = s.get_vec()[i].compress(d_s);
        }
        let s_bytes = s_compressed.to_compressed_bytes(d_s);
        let s_bytes_expected = (P::K * P::N * 12) / 8;
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

        Ok(KyberKeyPair { public_key: pk, secret_key: sk })
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
        if pk.len() != P::PK_SIZE {
            return Err(QryptoError::InvalidInput);
        }

        let m = generate_random_bytes(32)?;

        // Compute m̄ = H(m) using SHA3-256
        let m_bar = Sha3_256::digest(&m);

        // Compute (K̄, r) = G(m || H(pk)) using SHA3-512
        let pk_hash = Sha3_256::digest(pk);
        let mut g_input = Vec::with_capacity(32 + 32);
        g_input.extend_from_slice(&m_bar);
        g_input.extend_from_slice(&pk_hash);
        let g_output = Sha3_512::digest(&g_input);
        let (k_bar, r_seed) = g_output.split_at(32);

        // Kyber.CPAPKE.Enc(pk, m, r)
        // Parse pk = (t_compressed, ρ)
        let t_bytes_expected = (P::K * P::N * 12) / 8; // d_t = 12
        if pk.len() < t_bytes_expected + 32 {
            return Err(QryptoError::SerializationError);
        }
        let t_compressed_bytes = &pk[0..t_bytes_expected];
        let rho = hash_xof(&pk[t_bytes_expected..t_bytes_expected + 32], 32);

        // Decompress t to hat_t
        let hat_t = PolyVec::<P>::decompress(t_compressed_bytes, 12)?;

        // Generate matrix A from ρ using SHAKE-128
        let a = generate_matrix_a::<P>(&rho);

        // Sample r from CBD with eta1 using r_seed
        let mut r_vec = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            // Use r_seed to generate noise deterministically
            let mut shake = Shake128::default();
            shake.update(r_seed);
            shake.update(&[i as u8]); // Unique index for each polynomial
            let mut noise = vec![0u8; (P::ETA1 as usize * P::N).div_ceil(4)];
            shake.finalize_xof_into(&mut noise);
            r_vec.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }

        // Sample e1 from CBD with eta2
        let mut e1 = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
            e1.get_vec_mut()[i] = sample_cbd::<P>(P::ETA2, &noise);
        }

        // Sample e2 from CBD with eta2
        let e2_noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
        let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);

        // Compute u = A^T * r + e1
        let a_transpose = a.transpose();
        let u = a_transpose.mul_vec(&r_vec).add(&e1);

        // Compute v = hat_t^T * r + e2 + Decompress(m)
        let m_poly = Polynomial::<P>::decompress(&m, 1)?; // m is 256 bits, decompress to polynomial
        let v = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

        // Compress u to d_u bits and v to d_v bits
        let mut u_compressed = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            u_compressed.get_vec_mut()[i] = u.get_vec()[i].compress(P::DU);
        }
        let v_compressed = v.compress(P::DV);

        // Serialize ciphertext: c = (u_compressed, v_compressed)
        let u_bytes = u_compressed.to_compressed_bytes(P::DU);
        let v_bytes = v_compressed.to_compressed_bytes(P::DV);
        let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
        let v_bytes_expected = (P::N * P::DV as usize) / 8;
        if u_bytes.len() != u_bytes_expected || v_bytes.len() != v_bytes_expected {
            return Err(QryptoError::SerializationError);
        }
        let mut ciphertext = Vec::with_capacity(u_bytes_expected + v_bytes_expected);
        ciphertext.extend_from_slice(&u_bytes);
        ciphertext.extend_from_slice(&v_bytes);

        // Compute K = KDF(K̄ || H(c)) using SHAKE-256
        let c_hash = Sha3_256::digest(&ciphertext);
        let mut kdf_input = Vec::with_capacity(32 + 32);
        kdf_input.extend_from_slice(k_bar);
        kdf_input.extend_from_slice(&c_hash);
        let mut kdf = Shake256::default();
        kdf.update(&kdf_input);
        let mut shared_secret = vec![0u8; 32];
        kdf.finalize_xof_into(&mut shared_secret);

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
        if sk.len() != P::SK_SIZE {
            return Err(QryptoError::InvalidInput);
        }
        if ciphertext.len() != P::CT_SIZE {
            return Err(QryptoError::InvalidInput);
        }

        // Parse secret key: sk = (s_compressed, H(pk), z, pk)
        let s_bytes_expected = (P::K * P::N * 12) / 8; // d_s = 12
        let sk_t_offset = s_bytes_expected;
        let sk_hash_offset = sk_t_offset + 32;
        let sk_z_offset = sk_hash_offset + 32;
        if sk.len() < sk_z_offset + P::PK_SIZE {
            return Err(QryptoError::SerializationError);
        }

        let s_compressed_bytes = &sk[0..sk_t_offset];
        let pk_hash = &sk[sk_t_offset..sk_hash_offset];
        let z = &sk[sk_hash_offset..sk_z_offset];
        let pk = &sk[sk_z_offset..sk_z_offset + P::PK_SIZE];

        // Verify pk_hash
        let computed_pk_hash = Sha3_256::digest(pk);
        if computed_pk_hash.as_slice() != pk_hash {
            return Err(QryptoError::InvalidInput);
        }

        // Parse public key: pk = (t_compressed, ρ)
        let t_bytes_expected = (P::K * P::N * 12) / 8; // d_t = 12
        if pk.len() < t_bytes_expected + 32 {
            return Err(QryptoError::SerializationError);
        }
        let t_compressed_bytes = &pk[0..t_bytes_expected];
        let rho = hash_xof(&pk[t_bytes_expected..t_bytes_expected + 32], 32);

        // Parse ciphertext: c = (u_compressed, v_compressed)
        let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
        let v_bytes_expected = (P::N * P::DV as usize) / 8;
        if ciphertext.len() < u_bytes_expected + v_bytes_expected {
            return Err(QryptoError::SerializationError);
        }
        let u_compressed_bytes = &ciphertext[0..u_bytes_expected];
        let v_compressed_bytes = &ciphertext[u_bytes_expected..u_bytes_expected + v_bytes_expected];

        // Decompress s, u, v
        let s = PolyVec::<P>::decompress(s_compressed_bytes, 12)?;
        let u = PolyVec::<P>::decompress(u_compressed_bytes, P::DU)?;
        let v = Polynomial::<P>::decompress(v_compressed_bytes, P::DV)?;

        // Compute m' = Decompress(v - s^T * u)
        let s_transpose = s; // s is a column vector, so s^T is itself for dot product
        let s_u = s_transpose.dot_product(&u)?;
        let neg_s_u = Polynomial::<P>::new().add(&s_u); // Negation in the ring is same as adding (mod Q)
        let m_prime = v.add(&neg_s_u);
        let m_bytes = m_prime.to_compressed_bytes(1); // Compress to 1 bit per coefficient (binary message)

        // Re-derive K̄, r from m' and H(pk)
        let m_bar = Sha3_256::digest(&m_bytes);
        let mut g_input = Vec::with_capacity(32 + 32);
        g_input.extend_from_slice(&m_bar);
        g_input.extend_from_slice(pk_hash);
        let g_output = Sha3_512::digest(&g_input);
        let (k_bar, r_seed) = g_output.split_at(32);

        // Re-encrypt to check if ciphertext matches
        let hat_t = PolyVec::<P>::decompress(t_compressed_bytes, 12)?;
        let a = generate_matrix_a::<P>(&rho);
        let mut r_vec = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let mut shake = Shake128::default();
            shake.update(r_seed);
            shake.update(&[i as u8]);
            let mut noise = vec![0u8; (P::ETA1 as usize * P::N).div_ceil(4)];
            shake.finalize_xof_into(&mut noise);
            r_vec.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }
        let mut e1 = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
            e1.get_vec_mut()[i] = sample_cbd::<P>(P::ETA2, &noise);
        }
        let e2_noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
        let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);
        let a_transpose = a.transpose();
        let u_prime = a_transpose.mul_vec(&r_vec).add(&e1);
        let m_poly = Polynomial::<P>::decompress(&m_bytes, 1)?;
        let v_prime = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

        // Compress u_prime and v_prime
        let mut u_compressed_prime = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            u_compressed_prime.get_vec_mut()[i] = u_prime.get_vec()[i].compress(P::DU);
        }
        let v_compressed_prime = v_prime.compress(P::DV);

        // Compare ciphertexts
        let u_bytes_prime = u_compressed_prime.to_compressed_bytes(P::DU);
        let v_bytes_prime = v_compressed_prime.to_compressed_bytes(P::DV);
        let mut ciphertext_prime = Vec::with_capacity(u_bytes_expected + v_bytes_expected);
        ciphertext_prime.extend_from_slice(&u_bytes_prime);
        ciphertext_prime.extend_from_slice(&v_bytes_prime);

        let c_hash = Sha3_256::digest(ciphertext);
        let mut kdf_input = Vec::with_capacity(32 + 32);
        if ciphertext == ciphertext_prime {
            // Success: K = KDF(K̄ || H(c))
            kdf_input.extend_from_slice(k_bar);
            kdf_input.extend_from_slice(&c_hash);
        } else {
            // Failure: K = KDF(z || H(c))
            kdf_input.extend_from_slice(z);
            kdf_input.extend_from_slice(&c_hash);
        }

        // Compute shared secret
        let mut kdf = Shake256::default();
        kdf.update(&kdf_input);
        let mut shared_secret = vec![0u8; 32];
        kdf.finalize_xof_into(&mut shared_secret);

        Ok(shared_secret)
    }
}

pub type Kyber512 = Kyber<Kyber512Params>;
pub type Kyber768 = Kyber<Kyber768Params>;
pub type Kyber1024 = Kyber<Kyber1024Params>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{encapsulate, generate_keypair};

    #[test]
    fn kyber512_generate_keypair() {
        let keypair = generate_keypair::<Kyber512>().expect("Keypair generation failed");
        println!("public key length: {:?}", keypair.public_key().len());
        println!("secret key length: {:?}", keypair.secret_key().len());
        assert_eq!(keypair.public_key().len(), Kyber512Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber512Params::SK_SIZE);
    }

    #[test]
    fn kyber768_generate_keypair() {
        let keypair = generate_keypair::<Kyber768>().expect("Keypair generation failed");
        println!("public key length: {:?}", keypair.public_key().len());
        println!("secret key length: {:?}", keypair.secret_key().len());
        assert_eq!(keypair.public_key().len(), Kyber768Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber768Params::SK_SIZE);
    }

    #[test]
    fn kyber1024_generate_keypair() {
        let keypair = generate_keypair::<Kyber1024>().expect("Keypair generation failed");
        println!("public key length: {:?}", keypair.public_key().len());
        println!("secret key length: {:?}", keypair.secret_key().len());
        assert_eq!(keypair.public_key().len(), Kyber1024Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber1024Params::SK_SIZE);
    }

    #[test]
    fn kyber512_encapsulate() {
        let keypair = generate_keypair::<Kyber512>().expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber512>(keypair.public_key()).expect("msg");
        assert_eq!(ciphertext.len(), Kyber512Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }

    #[test]
    fn kyber768_encapsulate() {
        let keypair = generate_keypair::<Kyber768>().expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber768>(keypair.public_key()).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), Kyber768Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }

    #[test]
    fn kyber1024_encapsulate() {
        let keypair = generate_keypair::<Kyber1024>().expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber1024>(keypair.public_key()).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), Kyber1024Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }
}
