use crate::error::QryptoError;
use rand::RngCore;

pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, QryptoError> {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    Ok(bytes)
}
