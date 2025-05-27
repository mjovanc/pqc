use crate::math::sample_cbd;
use crate::math::{generate_matrix, PolyVec, Polynomial};
use crate::{error::KyberError, params::KyberParams};
use rand::rngs::OsRng;
use rand::TryRngCore;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Digest;
use sha3::{Sha3_256, Sha3_512, Shake128, Shake256};
use std::ops::Sub;

pub fn generate_keypair<P: KyberParams>() -> Result<(super::PublicKey, super::SecretKey), KyberError>
{
    let seed = generate_random_bytes(32)?;
    let a = generate_matrix::<P>(&seed, P::K, P::K);

    let s = sample_polyvec_cbd::<P>(P::ETA1, P::K)?;
    let e = sample_polyvec_cbd::<P>(P::ETA1, P::K)?;

    let t = a.mul_vec(&s).add(&e);
    let t_compressed = compress_polyvec::<P>(&t, 12); // d_t = 12
    let pk_bytes = serialize_public_key::<P>(&t_compressed, &seed, 12)?;
    let sk_bytes = serialize_secret_key::<P>(&s, &pk_bytes, 12)?; // d_s = 12

    Ok((
        super::PublicKey::new::<P>(pk_bytes)?,
        super::SecretKey::new::<P>(sk_bytes)?,
    ))
}

pub fn encapsulate<P: KyberParams>(
    pk: &super::PublicKey,
) -> Result<(super::Ciphertext, super::SharedSecret), KyberError> {
    if pk.bytes.len() != P::PK_SIZE {
        return Err(KyberError::KeyLengthError {
            expected: P::PK_SIZE,
            actual: pk.bytes.len(),
        });
    }

    let m = generate_random_bytes(32)?;
    let m_bar = Sha3_256::digest(&m);
    let pk_hash = Sha3_256::digest(&pk.bytes);
    let mut g_input = Vec::with_capacity(32 + 32);
    g_input.extend_from_slice(&m_bar);
    g_input.extend_from_slice(&pk_hash);
    let g_output = Sha3_512::digest(&g_input);
    let (k_bar, r_seed) = g_output.split_at(32);

    let (t_compressed_bytes, rho) = parse_public_key::<P>(&pk.bytes)?;
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

    let e1 = sample_polyvec_cbd::<P>(P::ETA2, P::K)?;
    let e2_noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
    let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);

    let a_transpose = a.transpose();
    let u = a_transpose.mul_vec(&r_vec).add(&e1);
    let m_poly = Polynomial::<P>::decompress(&m, 1)?;
    let v = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

    let u_compressed = compress_polyvec::<P>(&u, P::DU);
    let v_compressed = v.compress(P::DV);

    let u_bytes = u_compressed.to_compressed_bytes(P::DU);
    let v_bytes = v_compressed.to_compressed_bytes(P::DV);
    let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
    let v_bytes_expected = (P::N * P::DV as usize) / 8;
    if u_bytes.len() != u_bytes_expected || v_bytes.len() != v_bytes_expected {
        return Err(KyberError::SerializationError(
            "Invalid compressed bytes length".to_string(),
        ));
    }
    let mut ciphertext = vec![0u8; P::CT_SIZE];
    ciphertext[0..u_bytes_expected].copy_from_slice(&u_bytes);
    ciphertext[u_bytes_expected..u_bytes_expected + v_bytes_expected].copy_from_slice(&v_bytes);

    let c_hash = Sha3_256::digest(&ciphertext);
    let shared_secret = compute_shared_secret(k_bar, &c_hash)?;

    Ok((
        super::Ciphertext::new::<P>(ciphertext)?,
        super::SharedSecret(shared_secret),
    ))
}

pub fn decapsulate<P: KyberParams>(
    sk: &super::SecretKey,
    ct: &super::Ciphertext,
) -> Result<super::SharedSecret, KyberError> {
    if sk.bytes.len() != P::SK_SIZE {
        return Err(KyberError::KeyLengthError {
            expected: P::SK_SIZE,
            actual: sk.bytes.len(),
        });
    }
    if ct.bytes.len() != P::CT_SIZE {
        return Err(KyberError::CiphertextLengthError {
            expected: P::CT_SIZE,
            actual: ct.bytes.len(),
        });
    }

    let (s_compressed_bytes, pk_hash, z, pk) = parse_secret_key::<P>(&sk.bytes)?;
    let computed_pk_hash = Sha3_256::digest(pk);
    if computed_pk_hash.as_slice() != pk_hash {
        return Err(KyberError::HashMismatchError);
    }

    let (t_compressed_bytes, rho) = parse_public_key::<P>(pk)?;
    let (u_compressed_bytes, v_compressed_bytes) = parse_ciphertext::<P>(&ct.bytes)?;

    let s = PolyVec::<P>::decompress(s_compressed_bytes, 12)?;
    let u = PolyVec::<P>::decompress(u_compressed_bytes, P::DU)?;
    let v = Polynomial::<P>::decompress(v_compressed_bytes, P::DV)?;

    let s_u = s.dot_product(&u)?;
    let neg_s_u = Polynomial::<P>::new().sub(&s_u);
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
    let e1 = sample_polyvec_cbd::<P>(P::ETA2, P::K)?;
    let e2_noise = generate_random_bytes((P::ETA2 as usize * P::N).div_ceil(4))?;
    let e2 = sample_cbd::<P>(P::ETA2, &e2_noise);
    let a_transpose = a.transpose();
    let u_prime = a_transpose.mul_vec(&r_vec).add(&e1);
    let m_poly = Polynomial::<P>::decompress(&m_bytes, 1)?;
    let v_prime = hat_t.dot_product(&r_vec)?.add(&e2).add(&m_poly);

    let u_compressed_prime = compress_polyvec::<P>(&u_prime, P::DU);
    let v_compressed_prime = v_prime.compress(P::DV);
    let u_bytes_prime = u_compressed_prime.to_compressed_bytes(P::DU);
    let v_bytes_prime = v_compressed_prime.to_compressed_bytes(P::DV);
    let mut ciphertext_prime = vec![0u8; u_bytes_prime.len() + v_bytes_prime.len()];
    ciphertext_prime[0..u_bytes_prime.len()].copy_from_slice(&u_bytes_prime);
    ciphertext_prime[u_bytes_prime.len()..].copy_from_slice(&v_bytes_prime);

    let c_hash = Sha3_256::digest(&ct.bytes);
    let k_bar_or_z = if ct.bytes == ciphertext_prime {
        k_bar
    } else {
        z
    };
    let shared_secret = compute_shared_secret(k_bar_or_z, &c_hash)?;

    Ok(super::SharedSecret(shared_secret))
}

fn sample_polyvec_cbd<P: KyberParams>(eta: u32, k: usize) -> Result<PolyVec<P>, KyberError> {
    let mut polyvec = PolyVec::<P>::new(k);
    for i in 0..k {
        let noise = generate_random_bytes((eta as usize * P::N).div_ceil(4))?;
        polyvec.get_vec_mut()[i] = sample_cbd::<P>(eta, &noise);
    }
    Ok(polyvec)
}

fn compress_polyvec<P: KyberParams>(polyvec: &PolyVec<P>, bits: u32) -> PolyVec<P> {
    let mut compressed = PolyVec::<P>::new(polyvec.get_vec().len());
    for i in 0..polyvec.get_vec().len() {
        compressed.get_vec_mut()[i] = polyvec.get_vec()[i].compress(bits);
    }
    compressed
}

fn serialize_public_key<P: KyberParams>(
    t_compressed: &PolyVec<P>,
    seed: &[u8],
    d_t: u32,
) -> Result<Vec<u8>, KyberError> {
    let t_bytes = t_compressed.to_compressed_bytes(d_t);
    let t_bytes_expected = P::K
        .checked_mul(P::N)
        .and_then(|x| x.checked_mul(d_t as usize))
        .map(|x| x / 8)
        .ok_or(KyberError::SerializationError(
            "Overflow in public key size calculation".to_string(),
        ))?;
    if t_bytes.len() != t_bytes_expected {
        return Err(KyberError::SerializationError(
            "Invalid public key bytes length".to_string(),
        ));
    }

    let mut pk = vec![0u8; P::PK_SIZE];
    let seed_slice_size = P::PK_SIZE - t_bytes_expected;
    if seed_slice_size != 32 {
        return Err(KyberError::SerializationError(
            "Invalid seed slice size".to_string(),
        ));
    }
    pk[0..t_bytes_expected].copy_from_slice(&t_bytes);
    pk[t_bytes_expected..P::PK_SIZE].copy_from_slice(seed);
    Ok(pk)
}

fn serialize_secret_key<P: KyberParams>(
    s: &PolyVec<P>,
    pk: &[u8],
    d_s: u32,
) -> Result<Vec<u8>, KyberError> {
    let s_compressed = compress_polyvec::<P>(s, d_s);
    let s_bytes = s_compressed.to_compressed_bytes(d_s);
    let s_bytes_expected = (P::K * P::N * 12) / 8;
    if s_bytes.len() != s_bytes_expected {
        return Err(KyberError::SerializationError(
            "Invalid secret key bytes length".to_string(),
        ));
    }

    let mut sk = vec![0u8; P::SK_SIZE];
    let sk_t_offset = s_bytes_expected;
    let sk_hash_offset = sk_t_offset + 32;
    let sk_z_offset = sk_hash_offset + 32;

    sk[0..sk_t_offset].copy_from_slice(&s_bytes);
    let pk_hash = Sha3_256::digest(pk);
    sk[sk_t_offset..sk_hash_offset].copy_from_slice(&pk_hash);
    let z = generate_random_bytes(32)?;
    sk[sk_hash_offset..sk_z_offset].copy_from_slice(&z);
    sk[sk_z_offset..P::SK_SIZE].copy_from_slice(pk);
    Ok(sk)
}

fn parse_public_key<P: KyberParams>(pk: &[u8]) -> Result<(&[u8], Vec<u8>), KyberError> {
    let t_bytes_expected = (P::K * P::N * 12) / 8; // d_t = 12
    if pk.len() < t_bytes_expected + 32 {
        return Err(KyberError::DeserializationError(
            "Public key too short".to_string(),
        ));
    }
    let t_compressed_bytes = &pk[0..t_bytes_expected];
    let rho = hash_xof(&pk[t_bytes_expected..t_bytes_expected + 32], 32);
    Ok((t_compressed_bytes, rho))
}

fn parse_secret_key<P: KyberParams>(sk: &[u8]) -> Result<(&[u8], &[u8], &[u8], &[u8]), KyberError> {
    let s_bytes_expected = (P::K * P::N * 12) / 8; // d_s = 12
    let sk_t_offset = s_bytes_expected;
    let sk_hash_offset = sk_t_offset + 32;
    let sk_z_offset = sk_hash_offset + 32;
    if sk.len() < sk_z_offset + P::PK_SIZE {
        return Err(KyberError::DeserializationError(
            "Secret key too short".to_string(),
        ));
    }
    Ok((
        &sk[0..sk_t_offset],
        &sk[sk_t_offset..sk_hash_offset],
        &sk[sk_hash_offset..sk_z_offset],
        &sk[sk_z_offset..sk_z_offset + P::PK_SIZE],
    ))
}

fn parse_ciphertext<P: KyberParams>(ciphertext: &[u8]) -> Result<(&[u8], &[u8]), KyberError> {
    let u_bytes_expected = (P::K * P::N * P::DU as usize) / 8;
    let v_bytes_expected = (P::N * P::DV as usize) / 8;
    if ciphertext.len() < u_bytes_expected + v_bytes_expected {
        return Err(KyberError::DeserializationError(
            "Ciphertext too short".to_string(),
        ));
    }
    Ok((
        &ciphertext[0..u_bytes_expected],
        &ciphertext[u_bytes_expected..u_bytes_expected + v_bytes_expected],
    ))
}

fn compute_shared_secret(k_bar_or_z: &[u8], c_hash: &[u8]) -> Result<[u8; 32], KyberError> {
    let mut kdf_input = Vec::with_capacity(32 + 32);
    kdf_input.extend_from_slice(k_bar_or_z);
    kdf_input.extend_from_slice(c_hash);
    let mut kdf = Shake256::default();
    kdf.update(&kdf_input);
    let mut shared_secret = [0u8; 32];
    kdf.finalize_xof_into(&mut shared_secret);
    Ok(shared_secret)
}

pub fn hash_xof(seed: &[u8], output_len: usize) -> Vec<u8> {
    let mut hasher = Shake128::default();
    hasher.update(seed);
    let mut output = vec![0u8; output_len];
    hasher.finalize_xof_into(&mut output);
    output
}

pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, KyberError> {
    let mut bytes = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|e| KyberError::RandomError(format!("Failed to generate random bytes: {}", e)))?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        params::{Kyber1024, Kyber512, Kyber768},
        Kyber,
    };

    fn generate_keypair<P: KyberParams>() {
        let kyber = Kyber::<P>::new();
        let (pk, sk) = kyber.generate_keypair().expect("Keypair generation failed");

        assert_eq!(
            pk.bytes.len(),
            P::PK_SIZE,
            "Public key size mismatch for {}: expected {}, got {}",
            std::any::type_name::<P>(),
            P::PK_SIZE,
            pk.bytes.len()
        );

        assert_eq!(
            sk.bytes.len(),
            P::SK_SIZE,
            "Secret key size mismatch for {}: expected {}, got {}",
            std::any::type_name::<P>(),
            P::SK_SIZE,
            sk.bytes.len()
        );
    }

    fn encapsulate<P: KyberParams>() {
        let kyber = Kyber::<P>::new();
        let (pk, _) = kyber.generate_keypair().expect("Keypair generation failed");
        let (ct, ss) = kyber.encapsulate(&pk).expect("Encapsulation failed");

        assert_eq!(
            ct.bytes.len(),
            P::CT_SIZE,
            "Ciphertext size mismatch for {}: expected {}, got {}",
            std::any::type_name::<P>(),
            P::CT_SIZE,
            ct.bytes.len()
        );

        assert_eq!(
            ss.0.len(),
            32,
            "Shared secret size mismatch for {}: expected 32, got {}",
            std::any::type_name::<P>(),
            ss.0.len()
        );
    }

    fn decapsulate<P: KyberParams>() {
        let kyber = Kyber::<P>::new();
        let (pk, sk) = kyber.generate_keypair().expect("Keypair generation failed");
        let (ct, ss1) = kyber.encapsulate(&pk).expect("Encapsulation failed");
        let ss2 = kyber.decapsulate(&sk, &ct).expect("Decapsulation failed");

        assert_eq!(
            ss1.0,
            ss2.0,
            "Shared secrets do not match for {}",
            std::any::type_name::<P>()
        );
    }

    #[test]
    fn kyber512_generate_keypair() {
        generate_keypair::<Kyber512>();
    }

    #[test]
    fn kyber768_generate_keypair() {
        generate_keypair::<Kyber768>();
    }

    #[test]
    fn kyber1024_generate_keypair() {
        generate_keypair::<Kyber1024>();
    }

    #[test]
    fn kyber512_encapsulate() {
        encapsulate::<Kyber512>();
    }

    #[test]
    fn kyber768_encapsulate() {
        encapsulate::<Kyber768>();
    }

    #[test]
    fn kyber1024_encapsulate() {
        encapsulate::<Kyber1024>();
    }

    #[test]
    fn kyber512_decapsulate() {
        decapsulate::<Kyber512>();
    }

    #[test]
    fn kyber768_decapsulate() {
        decapsulate::<Kyber768>();
    }

    #[test]
    fn kyber1024_decapsulate() {
        decapsulate::<Kyber1024>();
    }
}
