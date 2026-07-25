use base64::Engine;
use quies_core::{
    check_strength, derive_key, generate_password, generate_pkce, generate_totp, merge,
    search::SearchCache, Index, KdfParams, Vault, VaultManifest,
};
use serde::Serialize;
use wasm_bindgen::prelude::*;

const BASE64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;

#[derive(Serialize)]
struct WasmResult<T: Serialize> {
    success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

fn ok_json<T: Serialize>(data: T) -> String {
    serde_json::to_string(&WasmResult {
        success: true,
        data: Some(data),
        error: None,
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"serialization failure"}"#.into())
}

fn err_json(msg: impl std::fmt::Display) -> String {
    serde_json::to_string(&WasmResult::<()> {
        success: false,
        data: None,
        error: Some(msg.to_string()),
    })
    .unwrap_or_else(|_| r#"{"success":false,"error":"error JSON formatting failed"}"#.into())
}

#[derive(Serialize)]
struct CreateVaultOutput {
    manifest: VaultManifest,
    index_enc_b64: String,
    key_b64: String,
}

#[wasm_bindgen]
pub fn wasm_create_vault(password: &str) -> String {
    let params = KdfParams::default();
    match Vault::create(password, params) {
        Ok((_vault, manifest, index_enc)) => {
            let key = match derive_key(password, &manifest.salt, params) {
                Ok(k) => k,
                Err(e) => return err_json(e),
            };
            let key_b64 = BASE64.encode(key.as_bytes());
            let index_enc_b64 = BASE64.encode(&index_enc);
            ok_json(CreateVaultOutput {
                manifest,
                index_enc_b64,
                key_b64,
            })
        }
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct UnlockVaultOutput {
    index: Index,
    key_b64: String,
}

#[wasm_bindgen]
pub fn wasm_unlock_vault(manifest_json: &str, index_enc_b64: &str, password: &str) -> String {
    let manifest: VaultManifest = match serde_json::from_str(manifest_json) {
        Ok(m) => m,
        Err(e) => return err_json(format!("invalid manifest: {e}")),
    };
    let index_enc = match BASE64.decode(index_enc_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 index: {e}")),
    };

    match Vault::unlock(&manifest, &index_enc, password) {
        Ok((_vault, index)) => {
            let key = match derive_key(password, &manifest.salt, manifest.kdf_params()) {
                Ok(k) => k,
                Err(e) => return err_json(e),
            };
            let key_b64 = BASE64.encode(key.as_bytes());
            ok_json(UnlockVaultOutput { index, key_b64 })
        }
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> String {
    match generate_password(length, uppercase, lowercase, numbers, symbols) {
        Ok(p) => ok_json(p),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_check_strength(password: &str) -> u8 {
    check_strength(password)
}

#[wasm_bindgen]
pub fn wasm_generate_totp(
    secret: &str,
    time_step: u64,
    current_time: u64,
    digits: u32,
) -> String {
    match generate_totp(secret, time_step, current_time, digits) {
        Ok(code) => ok_json(code),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_search_query(index_json: &str, term: &str) -> String {
    let index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let cache = SearchCache::rebuild_from_index(&index);
    let items = cache.query(term);
    ok_json(items)
}

#[wasm_bindgen]
pub fn wasm_merge_indexes(local_json: &str, remote_json: &str) -> String {
    let local: Index = match serde_json::from_str(local_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid local index: {e}")),
    };
    let remote: Index = match serde_json::from_str(remote_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid remote index: {e}")),
    };
    let res = merge(&local, &remote);
    ok_json(res)
}

#[derive(Serialize)]
struct BreachHashOutput {
    prefix: String,
    suffix: String,
}

#[wasm_bindgen]
pub fn wasm_get_breach_hash_parts(password: &str) -> String {
    use sha1::{Digest, Sha1};
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());

    if hash.len() < 5 {
        return err_json("hash error");
    }
    let (prefix, suffix) = hash.split_at(5);
    ok_json(BreachHashOutput {
        prefix: prefix.to_string(),
        suffix: suffix.to_string(),
    })
}

#[wasm_bindgen]
pub fn wasm_generate_pkce() -> String {
    match generate_pkce() {
        Ok(p) => ok_json(p),
        Err(e) => err_json(e),
    }
}
