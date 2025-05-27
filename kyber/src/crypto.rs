pub mod hash {
    use sha3::digest::{ExtendableOutput, Update};
    use sha3::Shake128;

    pub fn hash_xof(seed: &[u8], output_len: usize) -> Vec<u8> {
        let mut hasher = Shake128::default();
        hasher.update(seed);
        let mut output = vec![0u8; output_len];
        hasher.finalize_xof_into(&mut output);
        output
    }
}

pub mod rand {
    use crate::error::QryptoError;
    use ::rand::{rngs::OsRng, TryRngCore};

    pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, QryptoError> {
        let mut bytes = vec![0u8; len];
        OsRng.try_fill_bytes(&mut bytes).map_err(|e| QryptoError::RandomError(format!("Failed to generate random bytes: {}", e)))?;
        Ok(bytes)
    }
}
