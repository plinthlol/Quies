use base64::Engine;
use quies_core::{
    assign_tag, check_strength, create_collection, create_tag, delete_collection, delete_tag,
    build_auth_url, build_token_exchange_request, generate_oauth_state,
    generate_password, generate_pkce, generate_totp, list_children,
    list_favorites, list_root, list_tags, merge, move_entry, provider_for, remove_tag_from_entry,
    rename_collection, rename_tag,
    record_password_change, restore_password,
    import_bitwarden_json, export_bitwarden_json, import_csv, export_csv, import_1password_csv, export_1password_csv, import_protonpass_csv, export_protonpass_csv,
    get_breach_hash_parts,
    search::SearchCache, search_by_collection, search_by_tag,
    search_favorites, set_favorite, AliasProviderKind, CoreError, CreateAliasOptions,
    Entry, FavoriteSort, Index, KdfParams, OAuthProvider, OAuthTokens, PkcePair,
    PendingChanges, ConflictStrategy, Vault, VaultManifest,
};
use serde::Serialize;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};
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

fn parse_index(index_json: &str) -> Result<Index, String> {
    serde_json::from_str(index_json).map_err(|e| format!("invalid index json: {e}"))
}

fn parse_entry(entry_json: &str) -> Result<Entry, String> {
    serde_json::from_str(entry_json).map_err(|e| format!("invalid entry json: {e}"))
}

/// Accepts a few spellings per provider so callers don't need to match an
/// exact casing convention across JS/Rust.
fn parse_alias_provider(provider: &str) -> Result<AliasProviderKind, String> {
    match provider.to_lowercase().replace(['_', '-'], "").as_str() {
        "addyio" | "addy" => Ok(AliasProviderKind::AddyIo),
        "simplelogin" => Ok(AliasProviderKind::SimpleLogin),
        other => Err(format!("unknown alias provider: {other}")),
    }
}

// --- Opaque vault handle registry -----------------------------------------
//
// The Vault (and the zeroize-on-drop Key inside it) never leaves Rust/WASM
// linear memory as a JS-visible value: JS only ever sees an opaque u64
// handle. This replaces the previous design where wasm_create_vault/
// wasm_unlock_vault derived the key a second time and returned it as a
// base64 String — see AUDIT.md §1 / QUIES_AUDIT_FINDINGS.md [HIGH].
// Call wasm_lock_vault to drop a handle's entry and zeroize its key.

fn vaults() -> &'static Mutex<HashMap<u64, Vault>> {
    static VAULTS: OnceLock<Mutex<HashMap<u64, Vault>>> = OnceLock::new();
    VAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn with_vault<T>(handle: u64, f: impl FnOnce(&Vault) -> Result<T, CoreError>) -> Result<T, String> {
    let guard = vaults()
        .lock()
        .map_err(|_| "vault registry lock poisoned".to_string())?;
    let vault = guard.get(&handle).ok_or_else(|| "vault is locked".to_string())?;
    f(vault).map_err(|e| e.to_string())
}

fn with_vault_mut<T>(handle: u64, f: impl FnOnce(&mut Vault) -> Result<T, CoreError>) -> Result<T, String> {
    let mut guard = vaults()
        .lock()
        .map_err(|_| "vault registry lock poisoned".to_string())?;
    let vault = guard.get_mut(&handle).ok_or_else(|| "vault is locked".to_string())?;
    f(vault).map_err(|e| e.to_string())
}

#[derive(Serialize)]
struct CreateVaultOutput {
    manifest: VaultManifest,
    index_enc_b64: String,
    handle: u64,
}

#[wasm_bindgen]
pub fn wasm_create_vault(password: &str) -> String {
    let params = KdfParams::default();
    match Vault::create(password, params) {
        Ok((vault, manifest, index_enc)) => {
            let handle = next_handle();
            match vaults().lock() {
                Ok(mut g) => {
                    g.insert(handle, vault);
                }
                Err(_) => return err_json("vault registry lock poisoned"),
            }
            let index_enc_b64 = BASE64.encode(&index_enc);
            ok_json(CreateVaultOutput { manifest, index_enc_b64, handle })
        }
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct UnlockVaultOutput {
    index: Index,
    handle: u64,
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
        Ok((vault, index)) => {
            let handle = next_handle();
            match vaults().lock() {
                Ok(mut g) => {
                    g.insert(handle, vault);
                }
                Err(_) => return err_json("vault registry lock poisoned"),
            }
            ok_json(UnlockVaultOutput { index, handle })
        }
        Err(e) => err_json(e),
    }
}

/// Drops the vault (zeroizing its key) and invalidates the handle.
/// Safe to call on an already-locked/unknown handle (no-op).
#[wasm_bindgen]
pub fn wasm_lock_vault(handle: u64) {
    if let Ok(mut guard) = vaults().lock() {
        guard.remove(&handle);
    }
}

#[wasm_bindgen]
pub fn wasm_vault_encrypt(handle: u64, plaintext_b64: &str, aad_b64: &str) -> String {
    let plaintext = match BASE64.decode(plaintext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 plaintext: {e}")),
    };
    let aad = match BASE64.decode(aad_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 aad: {e}")),
    };
    match with_vault(handle, |v| v.encrypt(&plaintext, &aad)) {
        Ok(ciphertext) => ok_json(BASE64.encode(ciphertext)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt(handle: u64, ciphertext_b64: &str, aad_b64: &str) -> String {
    let ciphertext = match BASE64.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")),
    };
    let aad = match BASE64.decode(aad_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 aad: {e}")),
    };
    match with_vault(handle, |v| v.decrypt(&ciphertext, &aad)) {
        Ok(plaintext) => ok_json(BASE64.encode(plaintext)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_entry(handle: u64, entry_enc_b64: &str, entry_id: &str) -> String {
    let entry_enc = match BASE64.decode(entry_enc_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 entry: {e}")),
    };
    match with_vault(handle, |v| v.decrypt_entry(&entry_enc, entry_id)) {
        Ok(entry) => ok_json(entry),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct PutEntryOutput {
    entry_enc_b64: String,
    index_enc_b64: String,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_vault_put_entry(handle: u64, index_json: &str, entry_json: &str) -> String {
    let mut index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let entry: Entry = match serde_json::from_str(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entry json: {e}")),
    };

    match with_vault(handle, |v| v.put_entry(&mut index, entry)) {
        Ok((entry_enc, index_enc)) => ok_json(PutEntryOutput {
            entry_enc_b64: BASE64.encode(entry_enc),
            index_enc_b64: BASE64.encode(index_enc),
            index,
        }),
        Err(e) => err_json(e),
    }
}

#[derive(serde::Deserialize)]
struct RekeyEntryInputWasm {
    id: String,
    entry_enc_b64: String,
}

#[derive(Serialize)]
struct RekeyEntryOutputWasm {
    id: String,
    new_entry_enc_b64: String,
}

#[derive(Serialize)]
struct RekeyOutputWasm {
    manifest: VaultManifest,
    index_enc_b64: String,
    reencrypted_entries: Vec<RekeyEntryOutputWasm>,
}

#[wasm_bindgen]
pub fn wasm_vault_rekey(
    handle: u64,
    index_json: &str,
    entries_json: &str,
    new_password: &str,
) -> String {
    let index: Index = match serde_json::from_str(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(format!("invalid index json: {e}")),
    };
    let entries: Vec<RekeyEntryInputWasm> = match serde_json::from_str(entries_json) {
        Ok(es) => es,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };

    let mut decoded_entries = Vec::with_capacity(entries.len());
    for item in &entries {
        let bytes = match BASE64.decode(&item.entry_enc_b64) {
            Ok(b) => b,
            Err(e) => return err_json(format!("invalid base64 for entry {}: {e}", item.id)),
        };
        decoded_entries.push((item.id.clone(), bytes));
    }
    let refs: Vec<(&str, &[u8])> = decoded_entries
        .iter()
        .map(|(id, bytes)| (id.as_str(), bytes.as_slice()))
        .collect();

    let params = KdfParams::default();
    match with_vault_mut(handle, |v| v.rekey(&index, &refs, new_password, params)) {
        Ok(res) => {
            let index_enc_b64 = BASE64.encode(&res.index_enc);
            let reencrypted_entries = res
                .entries_enc
                .into_iter()
                .map(|(id, bytes)| RekeyEntryOutputWasm {
                    id,
                    new_entry_enc_b64: BASE64.encode(bytes),
                })
                .collect();

            ok_json(RekeyOutputWasm {
                manifest: res.manifest,
                index_enc_b64,
                reencrypted_entries,
            })
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
    match merge(&local, &remote) {
        Ok(res) => ok_json(res),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_get_breach_hash_parts(password: &str) -> String {
    match get_breach_hash_parts(password) {
        Ok(parts) => ok_json(parts),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_pkce() -> String {
    match generate_pkce() {
        Ok(p) => ok_json(p),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_generate_oauth_state() -> String {
    match generate_oauth_state() {
        Ok(s) => ok_json(s),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_build_auth_url(provider: &str, client_id: &str, redirect_uri: &str, pkce_json: &str, state: &str) -> String {
    let provider = match parse_oauth_provider(provider) { Ok(p) => p, Err(e) => return err_json(e) };
    let pkce: PkcePair = match serde_json::from_str(pkce_json) { Ok(p) => p, Err(e) => return err_json(format!("invalid PKCE json: {e}")) };
    ok_json(build_auth_url(provider, client_id, redirect_uri, &pkce, state))
}

#[wasm_bindgen]
pub fn wasm_build_token_exchange_request(token_url: &str, client_id: &str, code: &str, redirect_uri: &str, verifier: &str) -> String {
    ok_json(build_token_exchange_request(token_url, client_id, code, redirect_uri, verifier))
}

#[wasm_bindgen]
pub fn wasm_parse_token_response(response_b64: &str, current_unix_time: i64) -> String {
    let bytes = match BASE64.decode(response_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 response: {e}")) };
    match quies_core::parse_token_response(&bytes, current_unix_time) { Ok(t) => ok_json(t), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_encrypt_tokens(handle: u64, tokens_json: &str) -> String {
    let tokens: OAuthTokens = match serde_json::from_str(tokens_json) { Ok(t) => t, Err(e) => return err_json(format!("invalid token json: {e}")) };
    match with_vault(handle, |v| v.encrypt_tokens(&tokens)) { Ok(b) => ok_json(BASE64.encode(b)), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_tokens(handle: u64, ciphertext_b64: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")) };
    match with_vault(handle, |v| v.decrypt_tokens(&bytes)) { Ok(t) => ok_json(t), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_save_search_cache(handle: u64, index_json: &str) -> String {
    let index = match parse_index(index_json) { Ok(i) => i, Err(e) => return err_json(e) };
    let cache = SearchCache::rebuild_from_index(&index);
    match with_vault(handle, |v| v.save_search_cache(&cache)) { Ok(b) => ok_json(BASE64.encode(b)), Err(e) => err_json(e) }
}

#[wasm_bindgen]
pub fn wasm_vault_load_search_cache_query(handle: u64, ciphertext_b64: &str, term: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) { Ok(b) => b, Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")) };
    match with_vault(handle, |v| v.load_search_cache(&bytes).map(|c| c.query(term).into_iter().cloned().collect::<Vec<_>>())) { Ok(items) => ok_json(items), Err(e) => err_json(e) }
}

fn parse_oauth_provider(provider: &str) -> Result<OAuthProvider, String> {
    match provider.to_lowercase().as_str() { "googledrive" | "google" => Ok(OAuthProvider::GoogleDrive), "dropbox" => Ok(OAuthProvider::Dropbox), "onedrive" | "microsoft" => Ok(OAuthProvider::OneDrive), other => Err(format!("unknown OAuth provider: {other}")) }
}

#[wasm_bindgen]
pub fn wasm_sync_pending_apply(pending_json: &str, operation: &str, id: &str) -> String {
    let mut pending: PendingChanges = match serde_json::from_str(pending_json) { Ok(p) => p, Err(e) => return err_json(format!("invalid pending changes json: {e}")) };
    match operation { "enqueue" => pending.enqueue(id), "dequeue" => pending.dequeue(id), "reset_retry" => pending.reset_retry(id), "record_failure" => { pending.record_failure(id); }, other => return err_json(format!("unknown pending operation: {other}")) }
    ok_json(pending)
}

#[wasm_bindgen]
pub fn wasm_sync_retry_backoff(attempt: u32) -> u64 { quies_core::retry_backoff_seconds(attempt) }

#[wasm_bindgen]
pub fn wasm_sync_resolve_conflict(local_json: &str, remote_json: &str, strategy: &str) -> String {
    let local = match serde_json::from_str(local_json) { Ok(v) => v, Err(e) => return err_json(format!("invalid local entry: {e}")) };
    let remote = match serde_json::from_str(remote_json) { Ok(v) => v, Err(e) => return err_json(format!("invalid remote entry: {e}")) };
    let strategy = match strategy { "local" => ConflictStrategy::KeepLocal, "remote" => ConflictStrategy::KeepRemote, "newest" => ConflictStrategy::KeepNewest, other => return err_json(format!("unknown conflict strategy: {other}")) };
    ok_json(quies_core::resolve_conflict(&local, &remote, strategy))
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct TagOutput {
    tag: quies_core::Tag,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_tags_create(index_json: &str, id: &str, name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match create_tag(&mut index, id.to_string(), name, now) {
        Ok(tag) => ok_json(TagOutput { tag, index }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_tags_rename(index_json: &str, tag_id: &str, new_name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match rename_tag(&mut index, tag_id, new_name, now) {
        Ok(()) => ok_json(index),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct TagDeleteOutput {
    index: Index,
    affected_entry_ids: Vec<String>,
}

#[wasm_bindgen]
pub fn wasm_tags_delete(index_json: &str, tag_id: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match delete_tag(&mut index, tag_id, now) {
        Ok(affected_entry_ids) => ok_json(TagDeleteOutput { index, affected_entry_ids }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_tags_list(index_json: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_tags(&index))
}

#[wasm_bindgen]
pub fn wasm_tags_search(index_json: &str, tag_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_by_tag(&index, tag_id))
}

#[derive(Serialize)]
struct EntryTagOutput {
    entry: Entry,
    changed: bool,
}

#[wasm_bindgen]
pub fn wasm_entry_assign_tag(index_json: &str, entry_json: &str, tag_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    match assign_tag(&index, &mut entry, tag_id) {
        Ok(changed) => ok_json(EntryTagOutput { entry, changed }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_entry_remove_tag(entry_json: &str, tag_id: &str) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    let changed = remove_tag_from_entry(&mut entry, tag_id);
    ok_json(EntryTagOutput { entry, changed })
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

#[derive(Serialize)]
struct CollectionOutput {
    collection: quies_core::Collection,
    index: Index,
}

#[wasm_bindgen]
pub fn wasm_collections_create(
    index_json: &str,
    id: &str,
    name: &str,
    parent_id: Option<String>,
    now: i64,
) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match create_collection(&mut index, id.to_string(), name, parent_id, now) {
        Ok(collection) => ok_json(CollectionOutput { collection, index }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_collections_rename(index_json: &str, collection_id: &str, new_name: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match rename_collection(&mut index, collection_id, new_name, now) {
        Ok(()) => ok_json(index),
        Err(e) => err_json(e),
    }
}

#[derive(Serialize)]
struct CollectionDeleteOutput {
    index: Index,
    affected_entry_ids: Vec<String>,
}

#[wasm_bindgen]
pub fn wasm_collections_delete(index_json: &str, collection_id: &str, now: i64) -> String {
    let mut index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    match delete_collection(&mut index, collection_id, now) {
        Ok(affected_entry_ids) => ok_json(CollectionDeleteOutput { index, affected_entry_ids }),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_collections_list_root(index_json: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_root(&index))
}

#[wasm_bindgen]
pub fn wasm_collections_list_children(index_json: &str, parent_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(list_children(&index, parent_id))
}

#[wasm_bindgen]
pub fn wasm_collections_search(index_json: &str, collection_id: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_by_collection(&index, collection_id))
}

#[wasm_bindgen]
pub fn wasm_entry_move_to_collection(entry_json: &str, collection_id: Option<String>) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    move_entry(&mut entry, collection_id);
    ok_json(entry)
}

// ---------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_entry_set_favorite(entry_json: &str, favorite: bool) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    set_favorite(&mut entry, favorite);
    ok_json(entry)
}

/// `sort` accepts `"title"` (alphabetical) or `"recent"` (most-recently-
/// updated first); anything else is an error.
#[wasm_bindgen]
pub fn wasm_favorites_list(index_json: &str, sort: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    let sort = match sort {
        "title" => FavoriteSort::TitleAscending,
        "recent" => FavoriteSort::RecentlyUpdatedFirst,
        other => return err_json(format!("unknown favorite sort: {other}")),
    };
    ok_json(list_favorites(&index, sort))
}

#[wasm_bindgen]
pub fn wasm_favorites_search(index_json: &str, term: &str) -> String {
    let index = match parse_index(index_json) {
        Ok(i) => i,
        Err(e) => return err_json(e),
    };
    ok_json(search_favorites(&index, term))
}

// ---------------------------------------------------------------------------
// Email alias manager
// ---------------------------------------------------------------------------
//
// These only build/parse HTTP request specs -- no fetch() call happens in
// this crate. JS performs the actual request with whatever HTTP client it
// prefers, then hands the raw response body back to the parse_* functions.

#[wasm_bindgen]
pub fn wasm_alias_create_request(
    provider: &str,
    api_key: &str,
    local_part: Option<String>,
    domain: Option<String>,
    description: Option<String>,
) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let opts = CreateAliasOptions { local_part, domain, description };
    ok_json(provider_for(provider).create_alias_request(api_key, &opts))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_alias_response(&body) {
        Ok(record) => ok_json(record),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_alias_delete_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).delete_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_enable_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).enable_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_disable_request(provider: &str, api_key: &str, provider_id: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).disable_alias_request(api_key, provider_id))
}

#[wasm_bindgen]
pub fn wasm_alias_list_request(provider: &str, api_key: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).list_aliases_request(api_key))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_list_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_alias_list_response(&body) {
        Ok(records) => ok_json(records),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_alias_account_info_request(provider: &str, api_key: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    ok_json(provider_for(provider).account_info_request(api_key))
}

#[wasm_bindgen]
pub fn wasm_alias_parse_account_info_response(provider: &str, response_body_b64: &str) -> String {
    let provider = match parse_alias_provider(provider) {
        Ok(p) => p,
        Err(e) => return err_json(e),
    };
    let body = match BASE64.decode(response_body_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 response body: {e}")),
    };
    match provider_for(provider).parse_account_info_response(&body) {
        Ok(info) => ok_json(info),
        Err(e) => err_json(e),
    }
}

// ---------------------------------------------------------------------------
// Password History
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_entry_record_password_change(entry_json: &str, new_password: &str, now: i64) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    record_password_change(&mut entry, new_password.to_string(), now);
    ok_json(entry)
}

#[wasm_bindgen]
pub fn wasm_entry_restore_password(entry_json: &str, history_index: u32, now: i64) -> String {
    let mut entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    match restore_password(&mut entry, history_index as usize, now) {
        Ok(()) => ok_json(entry),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_entry_get_password_history(entry_json: &str) -> String {
    let entry = match parse_entry(entry_json) {
        Ok(e) => e,
        Err(e) => return err_json(e),
    };
    let history = quies_core::get_password_history(&entry);
    ok_json(history)
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_vault_encrypt_attachment(handle: u64, attachment_json: &str, entry_id: &str) -> String {
    let attachment: quies_core::Attachment = match serde_json::from_str(attachment_json) {
        Ok(a) => a,
        Err(e) => return err_json(format!("invalid attachment json: {e}")),
    };
    match with_vault(handle, |v| v.encrypt_attachment(&attachment, entry_id)) {
        Ok(enc) => ok_json(BASE64.encode(enc)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_vault_decrypt_attachment(handle: u64, ciphertext_b64: &str, entry_id: &str, attachment_id: &str) -> String {
    let bytes = match BASE64.decode(ciphertext_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64 ciphertext: {e}")),
    };
    match with_vault(handle, |v| v.decrypt_attachment(&bytes, entry_id, attachment_id)) {
        Ok(attachment) => ok_json(attachment),
        Err(e) => err_json(e),
    }
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

#[wasm_bindgen]
pub fn wasm_import_bitwarden_json(json_b64: &str) -> String {
    let bytes = match BASE64.decode(json_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_bitwarden_json(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_bitwarden_json(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    match export_bitwarden_json(&entries) {
        Ok(bytes) => ok_json(BASE64.encode(bytes)),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_import_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_csv(&entries)))
}

#[wasm_bindgen]
pub fn wasm_import_1password_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_1password_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_import_protonpass_csv(csv_b64: &str) -> String {
    let bytes = match BASE64.decode(csv_b64) {
        Ok(b) => b,
        Err(e) => return err_json(format!("invalid base64: {e}")),
    };
    match import_protonpass_csv(&bytes) {
        Ok(entries) => ok_json(entries),
        Err(e) => err_json(e),
    }
}

#[wasm_bindgen]
pub fn wasm_export_1password_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_1password_csv(&entries)))
}

#[wasm_bindgen]
pub fn wasm_export_protonpass_csv(entries_json: &str) -> String {
    let entries: Vec<Entry> = match serde_json::from_str(entries_json) {
        Ok(e) => e,
        Err(e) => return err_json(format!("invalid entries json: {e}")),
    };
    ok_json(BASE64.encode(export_protonpass_csv(&entries)))
}
