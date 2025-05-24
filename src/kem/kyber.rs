use crate::{
    crypto::hash::hash_xof,
    encoding_err,
    error::{EncodingErrorKind, ParameterErrorKind, QryptoError, RandomErrorKind},
    kem::{Kyber512Params, KyberParams},
    math::{generate_matrix, sample_cbd, PolyVec, Polynomial},
    param_err, random_err,
    traits::{KeyPair, KEM},
};
use rand::{rng, RngCore};
use sha3::digest::{ExtendableOutput, Update};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512, Shake128, Shake256};

use super::{Kyber1024Params, Kyber768Params};

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

impl<P: KyberParams> Kyber<P> {
    fn sample_polyvec_cbd(eta: u32, k: usize, seed: Option<&[u8]>, mut rng: Option<&mut dyn RngCore>) -> Result<PolyVec<P>, QryptoError> {
        let mut polyvec = PolyVec::<P>::new(k);
        for i in 0..k {
            let noise = if let Some(seed) = seed {
                let mut shake = Shake128::default();
                shake.update(seed);
                shake.update(&[i as u8]);
                let mut noise = vec![0u8; (eta as usize * P::N).div_ceil(4)];
                shake.finalize_xof_into(&mut noise);
                noise
            } else if let Some(ref mut rng) = rng {
                let mut noise = vec![0u8; (eta as usize * P::N).div_ceil(4)];
                rng.fill_bytes(&mut noise);
                noise
            } else {
                return Err(random_err!(RandomErrorKind::GenerationFailed));
            };
            polyvec.get_vec_mut()[i] = sample_cbd::<P>(eta, &noise);
        }
        Ok(polyvec)
    }

    fn compress_polyvec(polyvec: &PolyVec<P>, bits: u32) -> PolyVec<P> {
        let mut compressed = PolyVec::<P>::new(polyvec.get_vec().len());
        for i in 0..polyvec.get_vec().len() {
            compressed.get_vec_mut()[i] = polyvec.get_vec()[i].compress(bits);
        }
        compressed
    }

    fn serialize_public_key(t_compressed: &PolyVec<P>, seed: &[u8], d_t: u32) -> Result<Vec<u8>, QryptoError> {
        let t_bytes = t_compressed.to_compressed_bytes(d_t);
        let t_bytes_expected = P::K
            .checked_mul(P::N)
            .and_then(|x| x.checked_mul(d_t as usize))
            .map(|x| x / 8)
            .ok_or(encoding_err!(EncodingErrorKind::SerializationFailed))?;
        if t_bytes.len() != t_bytes_expected {
            return Err(encoding_err!(EncodingErrorKind::SerializationFailed));
        }

        let mut pk = vec![0u8; P::PK_SIZE];
        let seed_slice_size = P::PK_SIZE - t_bytes_expected;
        if seed_slice_size != 32 {
            return Err(encoding_err!(EncodingErrorKind::SerializationFailed));
        }
        pk[0..t_bytes_expected].copy_from_slice(&t_bytes);
        pk[t_bytes_expected..P::PK_SIZE].copy_from_slice(seed);
        Ok(pk)
    }

    fn serialize_secret_key(s: &PolyVec<P>, pk: &[u8], d_s: u32, rng: &mut dyn RngCore) -> Result<Vec<u8>, QryptoError> {
        let mut z = [0u8; 32];
        rng.fill_bytes(&mut z);
        Self::serialize_secret_key_with_z(s, pk, d_s, &z)
    }

    fn serialize_secret_key_with_z(s: &PolyVec<P>, pk: &[u8], d_s: u32, z: &[u8]) -> Result<Vec<u8>, QryptoError> {
        let s_compressed = Self::compress_polyvec(s, d_s);
        let s_bytes = s_compressed.to_compressed_bytes(d_s);
        let s_bytes_expected = (P::K * P::N * 12) / 8;
        if s_bytes.len() != s_bytes_expected {
            return Err(encoding_err!(EncodingErrorKind::SerializationFailed));
        }

        let mut sk = vec![0u8; P::SK_SIZE];
        let sk_t_offset = s_bytes_expected;
        let sk_hash_offset = sk_t_offset + 32;
        let sk_z_offset = sk_hash_offset + 32;

        sk[0..sk_t_offset].copy_from_slice(&s_bytes);
        let pk_hash = Sha3_256::digest(pk);
        sk[sk_t_offset..sk_hash_offset].copy_from_slice(&pk_hash);
        sk[sk_hash_offset..sk_z_offset].copy_from_slice(z);
        sk[sk_z_offset..P::SK_SIZE].copy_from_slice(pk);
        Ok(sk)
    }

    fn parse_public_key(pk: &[u8]) -> Result<(&[u8], Vec<u8>), QryptoError> {
        let t_bytes_expected = (P::K * P::N * 12) / 8; // d_t = 12
        if pk.len() < t_bytes_expected + 32 {
            return Err(encoding_err!(EncodingErrorKind::DeserializationFailed));
        }
        let t_compressed_bytes = &pk[0..t_bytes_expected];
        let rho = hash_xof(&pk[t_bytes_expected..t_bytes_expected + 32], 32);
        Ok((t_compressed_bytes, rho))
    }

    fn parse_secret_key(sk: &[u8]) -> Result<(&[u8], &[u8], &[u8], &[u8]), QryptoError> {
        let s_bytes_expected = (P::K * P::N * 12) / 8; // d_s = 12
        let sk_t_offset = s_bytes_expected;
        let sk_hash_offset = sk_t_offset + 32;
        let sk_z_offset = sk_hash_offset + 32;
        if sk.len() < sk_z_offset + P::PK_SIZE {
            return Err(encoding_err!(EncodingErrorKind::DeserializationFailed));
        }
        Ok((&sk[0..sk_t_offset], &sk[sk_t_offset..sk_hash_offset], &sk[sk_hash_offset..sk_z_offset], &sk[sk_z_offset..sk_z_offset + P::PK_SIZE]))
    }

    fn parse_ciphertext(ciphertext: &[u8]) -> Result<(&[u8], &[u8]), QryptoError> {
        let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
        let v_bytes_expected = (P::N * P::DV as usize) / 8;
        if ciphertext.len() < u_bytes_expected + v_bytes_expected {
            return Err(encoding_err!(EncodingErrorKind::DeserializationFailed));
        }
        Ok((&ciphertext[0..u_bytes_expected], &ciphertext[u_bytes_expected..u_bytes_expected + v_bytes_expected]))
    }

    fn compute_shared_secret(k_bar_or_z: &[u8], c_hash: &[u8]) -> Result<Vec<u8>, QryptoError> {
        let mut kdf_input = Vec::with_capacity(32 + 32);
        kdf_input.extend_from_slice(k_bar_or_z);
        kdf_input.extend_from_slice(c_hash);
        let mut kdf = Shake256::default();
        kdf.update(&kdf_input);
        let mut shared_secret = vec![0u8; 32];
        kdf.finalize_xof_into(&mut shared_secret);
        Ok(shared_secret)
    }
}

impl<P: KyberParams> KEM for Kyber<P> {
    type KeyPair = KyberKeyPair;
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError> {
        let mut rng = rng();
        Self::generate_keypair_with_rng(&mut rng)
    }

    fn generate_keypair_with_seed(seed: &[u8]) -> Result<Self::KeyPair, QryptoError> {
        // Derive 32-byte rho from the input seed (typically 48 bytes in KATs)
        let rho = hash_xof(seed, 32);
        let a = generate_matrix::<P>(&rho, P::K, P::K);

        let s_seed = hash_xof(&[seed, b"s"].concat(), 32);
        let s = Self::sample_polyvec_cbd(P::ETA1, P::K, Some(&s_seed), None)?;
        let e_seed = hash_xof(&[seed, b"e"].concat(), 32);
        let e = Self::sample_polyvec_cbd(P::ETA1, P::K, Some(&e_seed), None)?;

        let t = a.mul_vec(&s).add(&e);
        let t_compressed = Self::compress_polyvec(&t, 12); // d_t = 12
        let pk = Self::serialize_public_key(&t_compressed, &rho, 12)?;

        let z_seed = hash_xof(&[seed, b"z"].concat(), 32);
        let sk = Self::serialize_secret_key_with_z(&s, &pk, 12, &z_seed)?; // d_s = 12

        Ok(KyberKeyPair { public_key: pk, secret_key: sk })
    }

    fn generate_keypair_with_rng(rng: &mut dyn RngCore) -> Result<Self::KeyPair, QryptoError> {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        let a = generate_matrix::<P>(&seed, P::K, P::K);

        let s = Self::sample_polyvec_cbd(P::ETA1, P::K, None, Some(rng))?;
        let e = Self::sample_polyvec_cbd(P::ETA1, P::K, None, Some(rng))?;

        let t = a.mul_vec(&s).add(&e);
        let t_compressed = Self::compress_polyvec(&t, 12); // d_t = 12
        let pk = Self::serialize_public_key(&t_compressed, &seed, 12)?;

        let sk = Self::serialize_secret_key(&s, &pk, 12, rng)?; // d_s = 12

        Ok(KyberKeyPair { public_key: pk, secret_key: sk })
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
        let mut rng = rng();
        Self::encapsulate_with_rng(pk, &mut rng)
    }

    fn encapsulate_with_rng(pk: &Self::PublicKey, rng: &mut dyn RngCore) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
        if pk.len() != P::PK_SIZE {
            return Err(param_err!(ParameterErrorKind::InvalidVectorLength { expected: P::PK_SIZE, actual: pk.len() }));
        }

        let mut m = [0u8; 32];
        rng.fill_bytes(&mut m);
        let m_bar = Sha3_256::digest(&m);
        let pk_hash = Sha3_256::digest(pk);
        let mut g_input = Vec::with_capacity(32 + 32);
        g_input.extend_from_slice(&m_bar);
        g_input.extend_from_slice(&pk_hash);
        let g_output = Sha3_512::digest(&g_input);
        let (k_bar, r_seed) = g_output.split_at(32);

        let (t_compressed_bytes, rho) = Self::parse_public_key(pk)?;
        let hat_t = PolyVec::<P>::decompress(t_compressed_bytes, 12)?;
        let a = generate_matrix::<P>(&rho, P::K, P::K);

        let mut r_vec = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let mut shake = Shake128::default();
            shake.update(r_seed);
            shake.update(&[i as u8]);
            let mut noise = vec![0u8; (P::ETA1 as usize * P::N).div_ceil(4)];
            shake.finalize_xof_into(&mut noise);
            r_vec.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }

        let e1 = Self::sample_polyvec_cbd(P::ETA2, P::K, None, Some(rng))?;
        let mut e2_noise = vec![0u8; (P::ETA2 as usize * P::N).div_ceil(4)];
        rng.fill_bytes(&mut e2_noise);
        let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);

        let a_transpose = a.transpose();
        let u = a_transpose.mul_vec(&r_vec).add(&e1);
        let m_poly = Polynomial::<P>::decompress(&m, 1)?;
        let v = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

        let u_compressed = Self::compress_polyvec(&u, P::DU);
        let v_compressed = v.compress(P::DV);

        let u_bytes = u_compressed.to_compressed_bytes(P::DU);
        let v_bytes = v_compressed.to_compressed_bytes(P::DV);
        let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
        let v_bytes_expected = (P::N * P::DV as usize) / 8;
        if u_bytes.len() != u_bytes_expected || v_bytes.len() != v_bytes_expected {
            return Err(encoding_err!(EncodingErrorKind::SerializationFailed));
        }
        let mut ciphertext = Vec::with_capacity(u_bytes_expected + v_bytes_expected);
        ciphertext.extend_from_slice(&u_bytes);
        ciphertext.extend_from_slice(&v_bytes);

        let c_hash = Sha3_256::digest(&ciphertext);
        let shared_secret = Self::compute_shared_secret(k_bar, &c_hash)?;

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
        if sk.len() != P::SK_SIZE {
            return Err(param_err!(ParameterErrorKind::InvalidKeyLength { expected: P::SK_SIZE, actual: sk.len() }));
        }
        if ciphertext.len() != P::CT_SIZE {
            return Err(param_err!(ParameterErrorKind::InvalidCiphertextLength { expected: P::CT_SIZE, actual: ciphertext.len() }));
        }

        let (s_compressed_bytes, pk_hash, z, pk) = Self::parse_secret_key(sk)?;
        let computed_pk_hash = Sha3_256::digest(pk);
        if computed_pk_hash.as_slice() != pk_hash {
            return Err(param_err!(ParameterErrorKind::InvalidHash));
        }

        let (t_compressed_bytes, rho) = Self::parse_public_key(pk)?;
        let (u_compressed_bytes, v_compressed_bytes) = Self::parse_ciphertext(ciphertext)?;

        let s = PolyVec::<P>::decompress(s_compressed_bytes, 12)?;
        let u = PolyVec::<P>::decompress(u_compressed_bytes, P::DU)?;
        let v = Polynomial::<P>::decompress(v_compressed_bytes, P::DV)?;

        let s_u = s.dot_product(&u)?;
        let neg_s_u = Polynomial::<P>::new().add(&s_u);
        let m_prime = v.add(&neg_s_u);
        let m_bytes = m_prime.to_compressed_bytes(1);

        let m_bar = Sha3_256::digest(&m_bytes);
        let mut g_input = Vec::with_capacity(32 + 32);
        g_input.extend_from_slice(&m_bar);
        g_input.extend_from_slice(pk_hash);
        let g_output = Sha3_512::digest(&g_input);
        let (k_bar, r_seed) = g_output.split_at(32);

        let hat_t = PolyVec::<P>::decompress(t_compressed_bytes, 12)?;
        let a = generate_matrix::<P>(&rho, P::K, P::K);
        let mut r_vec = PolyVec::<P>::new(P::K);
        for i in 0..P::K {
            let mut shake = Shake128::default();
            shake.update(r_seed);
            shake.update(&[i as u8]);
            let mut noise = vec![0u8; (P::ETA1 as usize * P::N).div_ceil(4)];
            shake.finalize_xof_into(&mut noise);
            r_vec.get_vec_mut()[i] = sample_cbd::<P>(P::ETA1, &noise);
        }
        let e1 = Self::sample_polyvec_cbd(P::ETA2, P::K, None, None)?;
        let mut e2_noise = vec![0u8; (P::ETA2 as usize * P::N).div_ceil(4)];
        let mut rng = rng();
        rng.fill_bytes(&mut e2_noise);
        let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);
        let a_transpose = a.transpose();
        let u_prime = a_transpose.mul_vec(&r_vec).add(&e1);
        let m_poly = Polynomial::<P>::decompress(&m_bytes, 1)?;
        let v_prime = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

        let u_compressed_prime = Self::compress_polyvec(&u_prime, P::DU);
        let v_compressed_prime = v_prime.compress(P::DV);
        let u_bytes_prime = u_compressed_prime.to_compressed_bytes(P::DU);
        let v_bytes_prime = v_compressed_prime.to_compressed_bytes(P::DV);
        let mut ciphertext_prime = Vec::with_capacity(u_bytes_prime.len() + v_bytes_prime.len());
        ciphertext_prime.extend_from_slice(&u_bytes_prime);
        ciphertext_prime.extend_from_slice(&v_bytes_prime);

        let c_hash = Sha3_256::digest(ciphertext);
        let k_bar_or_z = if ciphertext == ciphertext_prime { k_bar } else { z };
        let shared_secret = Self::compute_shared_secret(k_bar_or_z, &c_hash)?;

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
        let keypair = generate_keypair::<Kyber512>(None).expect("Keypair generation failed");
        assert_eq!(keypair.public_key().len(), Kyber512Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber512Params::SK_SIZE);
    }

    #[test]
    fn kyber768_generate_keypair() {
        let keypair = generate_keypair::<Kyber768>(None).expect("Keypair generation failed");
        assert_eq!(keypair.public_key().len(), Kyber768Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber768Params::SK_SIZE);
    }

    #[test]
    fn kyber1024_generate_keypair() {
        let keypair = generate_keypair::<Kyber1024>(None).expect("Keypair generation failed");
        assert_eq!(keypair.public_key().len(), Kyber1024Params::PK_SIZE);
        assert_eq!(keypair.secret_key().len(), Kyber1024Params::SK_SIZE);
    }

    #[test]
    fn kyber512_encapsulate() {
        let keypair = generate_keypair::<Kyber512>(None).expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber512>(keypair.public_key(), None).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), Kyber512Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }

    #[test]
    fn kyber768_encapsulate() {
        let keypair = generate_keypair::<Kyber768>(None).expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber768>(keypair.public_key(), None).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), Kyber768Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }

    #[test]
    fn kyber1024_encapsulate() {
        let keypair = generate_keypair::<Kyber1024>(None).expect("Keypair generation failed");
        let (ciphertext, shared_secret) = encapsulate::<Kyber1024>(keypair.public_key(), None).expect("Encapsulation failed");
        assert_eq!(ciphertext.len(), Kyber1024Params::CT_SIZE, "Ciphertext size incorrect");
        assert_eq!(shared_secret.len(), 32, "Shared secret size incorrect");
    }
}
