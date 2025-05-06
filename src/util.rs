use crate::error::QryptoError;
use rand::rngs::OsRng;
use rand::TryRngCore;

pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, QryptoError> {
    let mut bytes = vec![0u8; len];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| QryptoError::RandomGenerationFailed)?;
    Ok(bytes)
}
