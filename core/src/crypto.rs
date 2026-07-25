use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use zeroize::ZeroizeOnDrop;

use crate::errors::CoreError;

#[derive(Clone, Copy, Debug)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_kib: 65536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

#[derive(ZeroizeOnDrop)]
pub struct Key(Box<[u8; 32]>);

impl Key {
    fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

pub fn generate_salt() -> Result<[u8; 16], CoreError> {
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random salt".into()))?;
    Ok(salt)
}

pub fn derive_key(password: &str, salt: &[u8; 16], params: KdfParams) -> Result<Key, CoreError> {
    let argon2_params = Params::new(
        params.memory_kib,
        params.iterations,
        params.parallelism,
        Some(32),
    )
    .map_err(|e| CoreError::InvalidFormat(format!("invalid KDF params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, argon2_params);

    let mut out = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut out)
        .map_err(|_| CoreError::InvalidFormat("key derivation failed".into()))?;

    Ok(Key(Box::new(out)))
}

pub fn encrypt(key: &Key, plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    let cipher = XChaCha20Poly1305::new(key.as_array().into());

    let mut nonce_bytes = [0u8; 24];
    getrandom::getrandom(&mut nonce_bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate nonce".into()))?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::InvalidFormat("encryption failed".into()))?;

    let mut out = Vec::with_capacity(24 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

pub fn decrypt(key: &Key, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    if ciphertext.len() < 24 {
        return Err(CoreError::DecryptionFailed);
    }
    let (nonce_bytes, ct) = ciphertext.split_at(24);
    let cipher = XChaCha20Poly1305::new(key.as_array().into());
    let nonce = XNonce::from_slice(nonce_bytes);

    cipher
        .decrypt(nonce, Payload { msg: ct, aad })
        .map_err(|_| CoreError::DecryptionFailed)
}

pub fn encrypt_raw(key_bytes: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    let key = Key(Box::new(*key_bytes));
    encrypt(&key, plaintext, aad)
}

pub fn decrypt_raw(key_bytes: &[u8; 32], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, CoreError> {
    let key = Key(Box::new(*key_bytes));
    decrypt(&key, ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn derive_key_is_deterministic_for_same_input() {
        let salt = [7u8; 16];
        let k1 = derive_key("correct horse battery staple", &salt, test_params()).unwrap();
        let k2 = derive_key("correct horse battery staple", &salt, test_params()).unwrap();
        assert_eq!(k1.as_array(), k2.as_array());
    }

    #[test]
    fn derive_key_differs_for_different_salt() {
        let k1 = derive_key("same password", &[1u8; 16], test_params()).unwrap();
        let k2 = derive_key("same password", &[2u8; 16], test_params()).unwrap();
        assert_ne!(k1.as_array(), k2.as_array());
    }

    #[test]
    fn derive_key_differs_for_different_password() {
        let salt = [9u8; 16];
        let k1 = derive_key("password one", &salt, test_params()).unwrap();
        let k2 = derive_key("password two", &salt, test_params()).unwrap();
        assert_ne!(k1.as_array(), k2.as_array());
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = derive_key("master password", &[1u8; 16], test_params()).unwrap();
        let plaintext = b"my secret entry data";
        let aad = b"entry-id-123";

        let ciphertext = encrypt(&key, plaintext, aad).unwrap();
        assert_ne!(ciphertext[24..], plaintext[..]);
        let decrypted = decrypt(&key, &ciphertext, aad).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn decrypt_fails_with_wrong_key() {
        let key1 = derive_key("password one", &[1u8; 16], test_params()).unwrap();
        let key2 = derive_key("password two", &[1u8; 16], test_params()).unwrap();
        let ciphertext = encrypt(&key1, b"secret", b"aad").unwrap();
        assert_eq!(decrypt(&key2, &ciphertext, b"aad"), Err(CoreError::DecryptionFailed));
    }

    #[test]
    fn decrypt_fails_with_wrong_aad() {
        let key = derive_key("password", &[3u8; 16], test_params()).unwrap();
        let ciphertext = encrypt(&key, b"secret", b"correct-aad").unwrap();
        assert_eq!(decrypt(&key, &ciphertext, b"wrong-aad"), Err(CoreError::DecryptionFailed));
    }

    #[test]
    fn decrypt_fails_on_tampered_ciphertext() {
        let key = derive_key("password", &[4u8; 16], test_params()).unwrap();
        let mut ciphertext = encrypt(&key, b"secret data", b"aad").unwrap();
        let last = ciphertext.len() - 1;
        ciphertext[last] ^= 0xFF;
        assert_eq!(decrypt(&key, &ciphertext, b"aad"), Err(CoreError::DecryptionFailed));
    }

    #[test]
    fn decrypt_fails_on_truncated_input() {
        let key = derive_key("password", &[5u8; 16], test_params()).unwrap();
        assert_eq!(decrypt(&key, b"short", b"aad"), Err(CoreError::DecryptionFailed));
    }

    #[test]
    fn generate_salt_produces_distinct_values() {
        let s1 = generate_salt().unwrap();
        let s2 = generate_salt().unwrap();
        assert_ne!(s1, s2);
    }

    proptest::proptest! {
        #[test]
        fn roundtrip_holds_for_arbitrary_bytes(data: Vec<u8>, aad: Vec<u8>) {
            let key = derive_key("proptest password", &[6u8; 16], test_params()).unwrap();
            let ciphertext = encrypt(&key, &data, &aad).unwrap();
            let decrypted = decrypt(&key, &ciphertext, &aad).unwrap();
            proptest::prop_assert_eq!(decrypted, data);
        }
    }
}
