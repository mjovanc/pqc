use crate::{
    error::QryptoError,
    traits::{KeyEncapsulation, KeyPair},
    util::generate_random_bytes,
};

const KYBER512_PK_SIZE: usize = 800;
const KYBER512_SK_SIZE: usize = 1632;
const KYBER512_CT_SIZE: usize = 768;
const _KYBER768_PK_SIZE: usize = 1184;
const _KYBER768_SK_SIZE: usize = 2400;
const _KYBER768_CT_SIZE: usize = 1088;
const _KYBER1024_PK_SIZE: usize = 1568;
const _KYBER1024_SK_SIZE: usize = 3168;
const _KYBER1024_CT_SIZE: usize = 1568;
const SHARED_SECRET_SIZE: usize = 32;

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

pub struct Kyber512;

impl KeyEncapsulation for Kyber512 {
    type KeyPair = KyberKeyPair;
    type PublicKey = Vec<u8>;
    type SecretKey = Vec<u8>;

    fn generate_keypair() -> Result<Self::KeyPair, QryptoError> {
        let pk = generate_random_bytes(KYBER512_PK_SIZE)?;
        let sk = generate_random_bytes(KYBER512_SK_SIZE)?;
        Ok(KyberKeyPair { public_key: pk, secret_key: sk })
    }

    fn encapsulate(pk: &Self::PublicKey) -> Result<(Vec<u8>, Vec<u8>), QryptoError> {
        if pk.len() != KYBER512_PK_SIZE {
            return Err(QryptoError::InvalidKeyLength);
        }
        let ciphertext = generate_random_bytes(KYBER512_CT_SIZE)?;
        let shared_secret = generate_random_bytes(SHARED_SECRET_SIZE)?;
        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(sk: &Self::SecretKey, ciphertext: &[u8]) -> Result<Vec<u8>, QryptoError> {
        if sk.len() != KYBER512_SK_SIZE || ciphertext.len() != KYBER512_CT_SIZE {
            return Err(QryptoError::InvalidKeyLength);
        }
        let shared_secret = generate_random_bytes(SHARED_SECRET_SIZE)?;
        Ok(shared_secret)
    }
}

#[cfg(test)]
mod tests {
    use crate::{decapsulate, encapsulate, generate_keypair};

    use super::*;

    #[test]
    fn kyber512_key_exchange() {
        let keypair = generate_keypair::<Kyber512>().expect("Keypair generation failed");

        let (ciphertext, shared_secret_bob) = encapsulate::<Kyber512>(keypair.public_key()).expect("Encapsulation failed");

        let shared_secret_alice = decapsulate::<Kyber512>(&keypair.secret_key(), &ciphertext).expect("Decapsulation failed");

        assert_eq!(shared_secret_alice, shared_secret_bob, "Shared secrets do not match!");
        assert!(!shared_secret_alice.is_empty(), "Shared secret is empty!");
    }
}
