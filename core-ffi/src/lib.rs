use base64::Engine;
use quies_core::{
    check_strength as core_check_strength,
    generate_password as core_generate_password,
    generate_totp as core_generate_totp,
    generate_pkce as core_generate_pkce,
    generate_salt,
    derive_key,
    merge,
    search::SearchCache,
    CoreError,
    Index,
    KdfParams,
    Vault,
    VaultManifest,
};

uniffi::include_scaffolding!("quies");

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Debug, thiserror::Error)]
pub enum QuiesError {
    #[error("wrong password or corrupted vault")]
    DecryptionFailed,
    #[error("vault is locked")]
    VaultLocked,
    #[error("entry not found: {id}")]
    NotFound { id: String },
    #[error("vault version {version} is newer than this app supports")]
    UnsupportedVersion { version: u32 },
    #[error("malformed data: {message}")]
    InvalidFormat { message: String },
}

impl From<CoreError> for QuiesError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::DecryptionFailed => QuiesError::DecryptionFailed,
            CoreError::VaultLocked => QuiesError::VaultLocked,
            CoreError::NotFound(id) => QuiesError::NotFound { id },
            CoreError::UnsupportedVersion(v) => QuiesError::UnsupportedVersion { version: v },
            CoreError::InvalidFormat(msg) => QuiesError::InvalidFormat { message: msg },
        }
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, QuiesError> {
    BASE64.decode(s).map_err(|e| QuiesError::InvalidFormat {
        message: format!("base64 decode error: {e}"),
    })
}

fn key_from_b64(key_b64: &str) -> Result<[u8; 32], QuiesError> {
    let bytes = base64_decode(key_b64)?;
    bytes.try_into().map_err(|_| QuiesError::InvalidFormat {
        message: "key must be exactly 32 bytes".into(),
    })
}

pub fn generate_salt_b64() -> Result<String, QuiesError> {
    let salt = generate_salt().map_err(QuiesError::from)?;
    Ok(BASE64.encode(salt))
}

pub fn derive_key_b64(
    password: String,
    salt_b64: String,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
) -> Result<String, QuiesError> {
    let salt_bytes = base64_decode(&salt_b64)?;
    let salt: [u8; 16] = salt_bytes.try_into().map_err(|_| QuiesError::InvalidFormat {
        message: "salt must be exactly 16 bytes".into(),
    })?;
    let params = KdfParams { memory_kib, iterations, parallelism };
    let key = derive_key(&password, &salt, params).map_err(QuiesError::from)?;
    Ok(BASE64.encode(key.as_bytes()))
}

pub fn encrypt_b64(key_b64: String, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<String, QuiesError> {
    let key_bytes = key_from_b64(&key_b64)?;
    let ciphertext = quies_core::crypto::encrypt_raw(&key_bytes, &plaintext, &aad)
        .map_err(QuiesError::from)?;
    Ok(BASE64.encode(ciphertext))
}

pub fn decrypt_b64(key_b64: String, ciphertext_b64: String, aad: Vec<u8>) -> Result<Vec<u8>, QuiesError> {
    let key_bytes = key_from_b64(&key_b64)?;
    let ciphertext = base64_decode(&ciphertext_b64)?;
    quies_core::crypto::decrypt_raw(&key_bytes, &ciphertext, &aad).map_err(QuiesError::from)
}

pub struct CreateVaultResult {
    pub manifest_json: String,
    pub index_enc_b64: String,
    pub key_b64: String,
}

pub fn create_vault(password: String) -> Result<CreateVaultResult, QuiesError> {
    let params = KdfParams::default();
    let (_vault, manifest, index_enc) = Vault::create(&password, params).map_err(QuiesError::from)?;
    let key = derive_key(&password, &manifest.salt, params).map_err(QuiesError::from)?;
    Ok(CreateVaultResult {
        manifest_json: serde_json::to_string(&manifest)
            .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?,
        index_enc_b64: BASE64.encode(&index_enc),
        key_b64: BASE64.encode(key.as_bytes()),
    })
}

pub struct UnlockVaultResult {
    pub index_json: String,
    pub key_b64: String,
}

pub fn unlock_vault(
    manifest_json: String,
    index_enc_b64: String,
    password: String,
) -> Result<UnlockVaultResult, QuiesError> {
    let manifest: VaultManifest = serde_json::from_str(&manifest_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad manifest: {e}") })?;
    let index_enc = base64_decode(&index_enc_b64)?;
    let (_vault, index) = Vault::unlock(&manifest, &index_enc, &password).map_err(QuiesError::from)?;
    let key = derive_key(&password, &manifest.salt, manifest.kdf_params()).map_err(QuiesError::from)?;
    Ok(UnlockVaultResult {
        index_json: serde_json::to_string(&index)
            .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?,
        key_b64: BASE64.encode(key.as_bytes()),
    })
}

pub fn generate_password(
    length: u32,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, QuiesError> {
    core_generate_password(length as usize, uppercase, lowercase, numbers, symbols)
        .map_err(QuiesError::from)
}

pub fn check_strength(password: String) -> u8 {
    core_check_strength(&password)
}

pub fn generate_totp(
    secret_base32: String,
    time_step_seconds: u64,
    current_unix_time: u64,
    digits: u32,
) -> Result<String, QuiesError> {
    core_generate_totp(&secret_base32, time_step_seconds, current_unix_time, digits)
        .map_err(QuiesError::from)
}

pub struct BreachHashParts {
    pub prefix: String,
    pub suffix: String,
}

pub fn get_breach_hash_parts(password: String) -> Result<BreachHashParts, QuiesError> {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());
    if hash.len() < 5 {
        return Err(QuiesError::InvalidFormat { message: "sha1 hash too short".into() });
    }
    let (prefix, suffix) = hash.split_at(5);
    Ok(BreachHashParts { prefix: prefix.to_string(), suffix: suffix.to_string() })
}

pub fn search_index(index_json: String, term: String) -> Result<String, QuiesError> {
    let index: Index = serde_json::from_str(&index_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad index: {e}") })?;
    let cache = SearchCache::rebuild_from_index(&index);
    let items = cache.query(&term);
    serde_json::to_string(&items)
        .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })
}

pub fn merge_indexes(local_json: String, remote_json: String) -> Result<String, QuiesError> {
    let local: Index = serde_json::from_str(&local_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad local index: {e}") })?;
    let remote: Index = serde_json::from_str(&remote_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad remote index: {e}") })?;
    let result = merge(&local, &remote);
    serde_json::to_string(&result)
        .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })
}

pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

pub fn generate_pkce() -> Result<PkcePair, QuiesError> {
    let pair = core_generate_pkce().map_err(QuiesError::from)?;
    Ok(PkcePair {
        code_verifier: pair.code_verifier,
        code_challenge: pair.code_challenge,
    })
}
