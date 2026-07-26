use base64::Engine;
use quies_core::{
    assign_tag,
    check_strength as core_check_strength,
    create_collection,
    create_tag,
    delete_collection,
    delete_tag,
    generate_password as core_generate_password,
    generate_totp as core_generate_totp,
    generate_pkce as core_generate_pkce,
    generate_oauth_state as core_generate_oauth_state,
    build_auth_url as core_build_auth_url,
    build_token_exchange_request as core_build_token_exchange_request,
    parse_token_response as core_parse_token_response,
    list_children,
    list_favorites,
    list_root,
    list_tags,
    merge,
    move_entry,
    provider_for,
    remove_tag_from_entry,
    rename_collection,
    rename_tag,
    record_password_change as core_record_password_change,
    restore_password as core_restore_password,
    import_bitwarden_json as core_import_bitwarden_json,
    export_bitwarden_json as core_export_bitwarden_json,
    import_csv as core_import_csv,
    export_csv as core_export_csv,
    import_1password_csv as core_import_1password_csv,
    export_1password_csv as core_export_1password_csv,
    import_protonpass_csv as core_import_protonpass_csv,
    export_protonpass_csv as core_export_protonpass_csv,
    get_breach_hash_parts as core_get_breach_hash_parts,
    BreachHashParts,
    search::SearchCache,
    search_by_collection,
    search_by_tag,
    search_favorites,
    set_favorite,
    Attachment,
    CoreError,
    Entry,
    FavoriteSort,
    Index,
    KdfParams,
    Vault,
    VaultManifest,
    ConflictStrategy,
    PendingChanges,
};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
    #[error("already exists: {message}")]
    AlreadyExists { message: String },
    #[error("invalid operation: {message}")]
    InvalidOperation { message: String },
}

impl From<CoreError> for QuiesError {
    fn from(e: CoreError) -> Self {
        match e {
            CoreError::DecryptionFailed => QuiesError::DecryptionFailed,
            CoreError::VaultLocked => QuiesError::VaultLocked,
            CoreError::NotFound(id) => QuiesError::NotFound { id },
            CoreError::UnsupportedVersion(v) => QuiesError::UnsupportedVersion { version: v },
            CoreError::InvalidFormat(msg) => QuiesError::InvalidFormat { message: msg },
            CoreError::AlreadyExists(msg) => QuiesError::AlreadyExists { message: msg },
            CoreError::InvalidOperation(msg) => QuiesError::InvalidOperation { message: msg },
        }
    }
}

fn base64_decode(s: &str) -> Result<Vec<u8>, QuiesError> {
    BASE64.decode(s).map_err(|e| QuiesError::InvalidFormat {
        message: format!("base64 decode error: {e}"),
    })
}

fn to_json<T: serde::Serialize>(value: &T) -> Result<String, QuiesError> {
    serde_json::to_string(value).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })
}

fn parse_index(json: &str) -> Result<Index, QuiesError> {
    serde_json::from_str(json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad index: {e}") })
}

fn parse_entry(json: &str) -> Result<Entry, QuiesError> {
    serde_json::from_str(json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad entry: {e}") })
}

// --- Opaque vault handle registry -----------------------------------------
//
// The Vault (and the zeroize-on-drop Key inside it) never leaves this
// process, let alone this crate: Swift/Kotlin only ever see an opaque u64
// handle. This replaces the previous design where create_vault/unlock_vault
// derived the key a second time and returned it as a base64 String — see
// AUDIT.md §1 / QUIES_AUDIT_FINDINGS.md [HIGH] for why that was unsafe.
// Dropping a handle's entry (lock_vault, or process exit) runs Key's
// ZeroizeOnDrop as normal.

fn vaults() -> &'static Mutex<HashMap<u64, Vault>> {
    static VAULTS: OnceLock<Mutex<HashMap<u64, Vault>>> = OnceLock::new();
    VAULTS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::SeqCst)
}

fn with_vault<T>(
    handle: u64,
    f: impl FnOnce(&Vault) -> Result<T, CoreError>,
) -> Result<T, QuiesError> {
    let guard = vaults().lock().map_err(|_| QuiesError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?;
    let vault = guard.get(&handle).ok_or(QuiesError::VaultLocked)?;
    f(vault).map_err(QuiesError::from)
}

fn with_vault_mut<T>(
    handle: u64,
    f: impl FnOnce(&mut Vault) -> Result<T, CoreError>,
) -> Result<T, QuiesError> {
    let mut guard = vaults().lock().map_err(|_| QuiesError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?;
    let vault = guard.get_mut(&handle).ok_or(QuiesError::VaultLocked)?;
    f(vault).map_err(QuiesError::from)
}

pub struct CreateVaultResult {
    pub manifest_json: String,
    pub index_enc_b64: String,
    pub handle: u64,
}

pub fn create_vault(password: String) -> Result<CreateVaultResult, QuiesError> {
    let params = KdfParams::default();
    let (vault, manifest, index_enc) = Vault::create(&password, params).map_err(QuiesError::from)?;
    let handle = next_handle();
    vaults().lock().map_err(|_| QuiesError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?.insert(handle, vault);
    Ok(CreateVaultResult {
        manifest_json: serde_json::to_string(&manifest)
            .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?,
        index_enc_b64: BASE64.encode(&index_enc),
        handle,
    })
}

pub struct UnlockVaultResult {
    pub index_json: String,
    pub handle: u64,
}

pub fn unlock_vault(
    manifest_json: String,
    index_enc_b64: String,
    password: String,
) -> Result<UnlockVaultResult, QuiesError> {
    let manifest: VaultManifest = serde_json::from_str(&manifest_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad manifest: {e}") })?;
    let index_enc = base64_decode(&index_enc_b64)?;
    let (vault, index) = Vault::unlock(&manifest, &index_enc, &password).map_err(QuiesError::from)?;
    let handle = next_handle();
    vaults().lock().map_err(|_| QuiesError::InvalidFormat {
        message: "vault registry lock poisoned".into(),
    })?.insert(handle, vault);
    Ok(UnlockVaultResult {
        index_json: serde_json::to_string(&index)
            .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?,
        handle,
    })
}

/// Drops the vault (and zeroizes its key) and invalidates the handle.
/// Safe to call on an already-locked/unknown handle (no-op).
pub fn lock_vault(handle: u64) {
    if let Ok(mut guard) = vaults().lock() {
        guard.remove(&handle);
    }
}

pub fn vault_encrypt(handle: u64, plaintext: Vec<u8>, aad: Vec<u8>) -> Result<String, QuiesError> {
    let ciphertext = with_vault(handle, |v| v.encrypt(&plaintext, &aad))?;
    Ok(BASE64.encode(ciphertext))
}

pub fn vault_decrypt(handle: u64, ciphertext_b64: String, aad: Vec<u8>) -> Result<Vec<u8>, QuiesError> {
    let ciphertext = base64_decode(&ciphertext_b64)?;
    with_vault(handle, |v| v.decrypt(&ciphertext, &aad))
}

pub fn vault_decrypt_entry(
    handle: u64,
    entry_enc_b64: String,
    entry_id: String,
) -> Result<String, QuiesError> {
    let entry_enc = base64_decode(&entry_enc_b64)?;
    let entry = with_vault(handle, |v| v.decrypt_entry(&entry_enc, &entry_id))?;
    serde_json::to_string(&entry).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })
}

pub struct PutEntryResult {
    pub entry_enc_b64: String,
    pub index_enc_b64: String,
    pub index_json: String,
}

pub fn vault_put_entry(
    handle: u64,
    index_json: String,
    entry_json: String,
) -> Result<PutEntryResult, QuiesError> {
    let mut index: Index = serde_json::from_str(&index_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad index: {e}") })?;
    let entry: Entry = serde_json::from_str(&entry_json)
        .map_err(|e| QuiesError::InvalidFormat { message: format!("bad entry: {e}") })?;

    let (entry_enc, index_enc) = with_vault(handle, |v| v.put_entry(&mut index, entry))?;

    Ok(PutEntryResult {
        entry_enc_b64: BASE64.encode(entry_enc),
        index_enc_b64: BASE64.encode(index_enc),
        index_json: serde_json::to_string(&index)
            .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?,
    })
}

pub struct RekeyEntryInputFfi {
    pub id: String,
    pub entry_enc_b64: String,
}

pub struct RekeyEntryOutputFfi {
    pub id: String,
    pub new_entry_enc_b64: String,
}

pub struct RekeyResultFfi {
    pub manifest_json: String,
    pub index_enc_b64: String,
    pub reencrypted_entries: Vec<RekeyEntryOutputFfi>,
}

pub fn vault_rekey(
    handle: u64,
    index_json: String,
    entries: Vec<RekeyEntryInputFfi>,
    new_password: String,
) -> Result<RekeyResultFfi, QuiesError> {
    let index = parse_index(&index_json)?;
    let mut decoded_entries = Vec::with_capacity(entries.len());
    for item in &entries {
        let bytes = base64_decode(&item.entry_enc_b64)?;
        decoded_entries.push((item.id.clone(), bytes));
    }
    let refs: Vec<(&str, &[u8])> = decoded_entries
        .iter()
        .map(|(id, bytes)| (id.as_str(), bytes.as_slice()))
        .collect();

    let params = KdfParams::default();
    let res = with_vault_mut(handle, |v| v.rekey(&index, &refs, &new_password, params))?;

    let manifest_json = serde_json::to_string(&res.manifest)
        .map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    let index_enc_b64 = BASE64.encode(&res.index_enc);
    let reencrypted_entries = res
        .entries_enc
        .into_iter()
        .map(|(id, bytes)| RekeyEntryOutputFfi {
            id,
            new_entry_enc_b64: BASE64.encode(bytes),
        })
        .collect();

    Ok(RekeyResultFfi {
        manifest_json,
        index_enc_b64,
        reencrypted_entries,
    })
}

// --- Everything below is unchanged: none of it ever touched key material ---

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

pub fn get_breach_hash_parts(password: String) -> Result<BreachHashParts, QuiesError> {
    core_get_breach_hash_parts(&password).map_err(QuiesError::from)
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
    let result = merge(&local, &remote).map_err(QuiesError::from)?;
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

pub fn generate_oauth_state() -> Result<String, QuiesError> {
    core_generate_oauth_state().map_err(QuiesError::from)
}

pub struct OAuthTokensFfi { pub access_token: String, pub refresh_token: Option<String>, pub expires_at: Option<i64> }
impl From<quies_core::OAuthTokens> for OAuthTokensFfi { fn from(t: quies_core::OAuthTokens) -> Self { Self { access_token: t.access_token, refresh_token: t.refresh_token, expires_at: t.expires_at } } }

pub fn build_auth_url(provider: String, client_id: String, redirect_uri: String, pkce_json: String, state: String) -> Result<String, QuiesError> {
    let provider = parse_oauth_provider(&provider)?;
    let pkce: quies_core::PkcePair = serde_json::from_str(&pkce_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    Ok(core_build_auth_url(provider, &client_id, &redirect_uri, &pkce, &state))
}
pub fn build_token_exchange_request(token_url: String, client_id: String, code: String, redirect_uri: String, verifier: String) -> HttpRequestSpecFfi {
    core_build_token_exchange_request(&token_url, &client_id, &code, &redirect_uri, &verifier).into()
}
pub fn parse_token_response(response_body: Vec<u8>, current_unix_time: i64) -> Result<OAuthTokensFfi, QuiesError> { core_parse_token_response(&response_body, current_unix_time).map(Into::into).map_err(Into::into) }
pub fn vault_encrypt_tokens(handle: u64, tokens_json: String) -> Result<String, QuiesError> { let tokens: quies_core::OAuthTokens = serde_json::from_str(&tokens_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?; Ok(BASE64.encode(with_vault(handle, |v| v.encrypt_tokens(&tokens))?)) }
pub fn vault_decrypt_tokens(handle: u64, ciphertext_b64: String) -> Result<OAuthTokensFfi, QuiesError> { let bytes = base64_decode(&ciphertext_b64)?; with_vault(handle, |v| v.decrypt_tokens(&bytes)).map(Into::into) }
pub fn vault_save_search_cache(handle: u64, index_json: String) -> Result<String, QuiesError> { let index = parse_index(&index_json)?; let cache = SearchCache::rebuild_from_index(&index); Ok(BASE64.encode(with_vault(handle, |v| v.save_search_cache(&cache))?)) }
pub fn vault_load_search_cache_query(handle: u64, ciphertext_b64: String, term: String) -> Result<String, QuiesError> { let bytes = base64_decode(&ciphertext_b64)?; let items = with_vault(handle, |v| v.load_search_cache(&bytes).map(|c| c.query(&term).into_iter().cloned().collect::<Vec<_>>()))?; to_json(&items) }

fn parse_oauth_provider(provider: &str) -> Result<quies_core::OAuthProvider, QuiesError> { match provider.to_lowercase().as_str() { "googledrive" | "google" => Ok(quies_core::OAuthProvider::GoogleDrive), "dropbox" => Ok(quies_core::OAuthProvider::Dropbox), "onedrive" | "microsoft" => Ok(quies_core::OAuthProvider::OneDrive), other => Err(QuiesError::InvalidFormat { message: format!("unknown OAuth provider: {other}") }) } }
pub fn sync_pending_apply(pending_json: String, operation: String, id: String) -> Result<String, QuiesError> { let mut p: PendingChanges = serde_json::from_str(&pending_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?; match operation.as_str() { "enqueue" => p.enqueue(&id), "dequeue" => p.dequeue(&id), "reset_retry" => p.reset_retry(&id), "record_failure" => { p.record_failure(&id); }, other => return Err(QuiesError::InvalidOperation { message: format!("unknown pending operation: {other}") }) }; to_json(&p) }
pub fn sync_retry_backoff(attempt: u32) -> u64 { quies_core::retry_backoff_seconds(attempt) }
pub fn sync_resolve_conflict(local_json: String, remote_json: String, strategy: String) -> Result<String, QuiesError> { let local: quies_core::IndexEntry = serde_json::from_str(&local_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?; let remote: quies_core::IndexEntry = serde_json::from_str(&remote_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?; let strategy = match strategy.as_str() { "local" => ConflictStrategy::KeepLocal, "remote" => ConflictStrategy::KeepRemote, "newest" => ConflictStrategy::KeepNewest, other => return Err(QuiesError::InvalidOperation { message: format!("unknown conflict strategy: {other}") }) }; to_json(&quies_core::resolve_conflict(&local, &remote, strategy)) }

// ---------------------------------------------------------------------------
// Password History
// ---------------------------------------------------------------------------

pub fn entry_record_password_change(entry_json: String, new_password: String, now: i64) -> Result<String, QuiesError> {
    let mut entry: Entry = serde_json::from_str(&entry_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    core_record_password_change(&mut entry, new_password, now);
    to_json(&entry)
}

pub fn entry_restore_password(entry_json: String, history_index: u32, now: i64) -> Result<String, QuiesError> {
    let mut entry: Entry = serde_json::from_str(&entry_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    core_restore_password(&mut entry, history_index as usize, now)?;
    to_json(&entry)
}

pub fn entry_get_password_history(entry_json: String) -> Result<String, QuiesError> {
    let entry: Entry = serde_json::from_str(&entry_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    let history = quies_core::get_password_history(&entry);
    to_json(&history)
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

pub fn vault_encrypt_attachment(handle: u64, attachment_json: String, entry_id: String) -> Result<String, QuiesError> {
    let attachment: Attachment = serde_json::from_str(&attachment_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    let enc = with_vault(handle, |v| v.encrypt_attachment(&attachment, &entry_id))?;
    Ok(BASE64.encode(enc))
}

pub fn vault_decrypt_attachment(handle: u64, ciphertext_b64: String, entry_id: String, attachment_id: String) -> Result<String, QuiesError> {
    let bytes = base64_decode(&ciphertext_b64)?;
    let attachment = with_vault(handle, |v| v.decrypt_attachment(&bytes, &entry_id, &attachment_id))?;
    to_json(&attachment)
}

// ---------------------------------------------------------------------------
// Import / Export
// ---------------------------------------------------------------------------

pub fn import_bitwarden_json(json_b64: String) -> Result<String, QuiesError> {
    let bytes = base64_decode(&json_b64)?;
    let entries = core_import_bitwarden_json(&bytes)?;
    to_json(&entries)
}

pub fn export_bitwarden_json(entries_json: String) -> Result<String, QuiesError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    let bytes = core_export_bitwarden_json(&entries)?;
    Ok(BASE64.encode(bytes))
}

pub fn import_csv(csv_b64: String) -> Result<String, QuiesError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_csv(&bytes)?;
    to_json(&entries)
}

pub fn export_csv(entries_json: String) -> Result<String, QuiesError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_csv(&entries)))
}

pub fn import_1password_csv(csv_b64: String) -> Result<String, QuiesError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_1password_csv(&bytes)?;
    to_json(&entries)
}

pub fn import_protonpass_csv(csv_b64: String) -> Result<String, QuiesError> {
    let bytes = base64_decode(&csv_b64)?;
    let entries = core_import_protonpass_csv(&bytes)?;
    to_json(&entries)
}

pub fn export_1password_csv(entries_json: String) -> Result<String, QuiesError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_1password_csv(&entries)))
}

pub fn export_protonpass_csv(entries_json: String) -> Result<String, QuiesError> {
    let entries: Vec<Entry> = serde_json::from_str(&entries_json).map_err(|e| QuiesError::InvalidFormat { message: e.to_string() })?;
    Ok(BASE64.encode(core_export_protonpass_csv(&entries)))
}

// ---------------------------------------------------------------------------
// Tags
// ---------------------------------------------------------------------------

pub struct TagResult {
    pub tag_json: String,
    pub index_json: String,
}

pub fn tags_create(index_json: String, id: String, name: String, now: i64) -> Result<TagResult, QuiesError> {
    let mut index = parse_index(&index_json)?;
    let tag = create_tag(&mut index, id, &name, now).map_err(QuiesError::from)?;
    Ok(TagResult { tag_json: to_json(&tag)?, index_json: to_json(&index)? })
}

pub fn tags_rename(index_json: String, tag_id: String, new_name: String, now: i64) -> Result<String, QuiesError> {
    let mut index = parse_index(&index_json)?;
    rename_tag(&mut index, &tag_id, &new_name, now).map_err(QuiesError::from)?;
    to_json(&index)
}

pub struct TagDeleteResult {
    pub index_json: String,
    pub affected_entry_ids: Vec<String>,
}

pub fn tags_delete(index_json: String, tag_id: String, now: i64) -> Result<TagDeleteResult, QuiesError> {
    let mut index = parse_index(&index_json)?;
    let affected_entry_ids = delete_tag(&mut index, &tag_id, now).map_err(QuiesError::from)?;
    Ok(TagDeleteResult { index_json: to_json(&index)?, affected_entry_ids })
}

pub fn tags_list(index_json: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&list_tags(&index))
}

pub fn tags_search(index_json: String, tag_id: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&search_by_tag(&index, &tag_id))
}

pub struct EntryTagResult {
    pub entry_json: String,
    pub changed: bool,
}

/// Assigns `tag_id` to the decrypted entry in `entry_json`. Validates the tag
/// exists against `index_json` (see [`assign_tag`]) — callers should pass the
/// same index the tag was created in. `changed` is `false` if the entry
/// already had the tag.
pub fn entry_assign_tag(index_json: String, entry_json: String, tag_id: String) -> Result<EntryTagResult, QuiesError> {
    let index = parse_index(&index_json)?;
    let mut entry = parse_entry(&entry_json)?;
    let changed = assign_tag(&index, &mut entry, &tag_id).map_err(QuiesError::from)?;
    Ok(EntryTagResult { entry_json: to_json(&entry)?, changed })
}

pub fn entry_remove_tag(entry_json: String, tag_id: String) -> Result<EntryTagResult, QuiesError> {
    let mut entry = parse_entry(&entry_json)?;
    let changed = remove_tag_from_entry(&mut entry, &tag_id);
    Ok(EntryTagResult { entry_json: to_json(&entry)?, changed })
}

// ---------------------------------------------------------------------------
// Collections
// ---------------------------------------------------------------------------

pub struct CollectionResult {
    pub collection_json: String,
    pub index_json: String,
}

pub fn collections_create(
    index_json: String,
    id: String,
    name: String,
    parent_id: Option<String>,
    now: i64,
) -> Result<CollectionResult, QuiesError> {
    let mut index = parse_index(&index_json)?;
    let collection = create_collection(&mut index, id, &name, parent_id, now).map_err(QuiesError::from)?;
    Ok(CollectionResult { collection_json: to_json(&collection)?, index_json: to_json(&index)? })
}

pub fn collections_rename(
    index_json: String,
    collection_id: String,
    new_name: String,
    now: i64,
) -> Result<String, QuiesError> {
    let mut index = parse_index(&index_json)?;
    rename_collection(&mut index, &collection_id, &new_name, now).map_err(QuiesError::from)?;
    to_json(&index)
}

pub struct CollectionDeleteResult {
    pub index_json: String,
    pub affected_entry_ids: Vec<String>,
}

pub fn collections_delete(index_json: String, collection_id: String, now: i64) -> Result<CollectionDeleteResult, QuiesError> {
    let mut index = parse_index(&index_json)?;
    let affected_entry_ids = delete_collection(&mut index, &collection_id, now).map_err(QuiesError::from)?;
    Ok(CollectionDeleteResult { index_json: to_json(&index)?, affected_entry_ids })
}

pub fn collections_list_root(index_json: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&list_root(&index))
}

pub fn collections_list_children(index_json: String, parent_id: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&list_children(&index, &parent_id))
}

pub fn collections_search(index_json: String, collection_id: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&search_by_collection(&index, &collection_id))
}

pub fn entry_move_to_collection(entry_json: String, collection_id: Option<String>) -> Result<String, QuiesError> {
    let mut entry = parse_entry(&entry_json)?;
    move_entry(&mut entry, collection_id);
    to_json(&entry)
}

// ---------------------------------------------------------------------------
// Favorites
// ---------------------------------------------------------------------------

pub fn entry_set_favorite(entry_json: String, favorite: bool) -> Result<String, QuiesError> {
    let mut entry = parse_entry(&entry_json)?;
    set_favorite(&mut entry, favorite);
    to_json(&entry)
}

pub enum FavoriteSortFfi {
    TitleAscending,
    RecentlyUpdatedFirst,
}

impl From<FavoriteSortFfi> for FavoriteSort {
    fn from(s: FavoriteSortFfi) -> Self {
        match s {
            FavoriteSortFfi::TitleAscending => FavoriteSort::TitleAscending,
            FavoriteSortFfi::RecentlyUpdatedFirst => FavoriteSort::RecentlyUpdatedFirst,
        }
    }
}

pub fn favorites_list(index_json: String, sort: FavoriteSortFfi) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&list_favorites(&index, sort.into()))
}

pub fn favorites_search(index_json: String, term: String) -> Result<String, QuiesError> {
    let index = parse_index(&index_json)?;
    to_json(&search_favorites(&index, &term))
}

// ---------------------------------------------------------------------------
// Email alias manager
// ---------------------------------------------------------------------------
//
// These wrappers only build/parse HTTP request specs — same "no sockets in
// core (or its bindings)" rule as everywhere else in this file. Swift/Kotlin
// performs the actual HTTP call with whatever networking stack it prefers,
// then hands the raw response bytes back to the parse_* functions.

pub enum AliasProviderKindFfi {
    AddyIo,
    SimpleLogin,
}

impl From<AliasProviderKindFfi> for quies_core::AliasProviderKind {
    fn from(k: AliasProviderKindFfi) -> Self {
        match k {
            AliasProviderKindFfi::AddyIo => quies_core::AliasProviderKind::AddyIo,
            AliasProviderKindFfi::SimpleLogin => quies_core::AliasProviderKind::SimpleLogin,
        }
    }
}

pub struct CreateAliasOptionsFfi {
    pub local_part: Option<String>,
    pub domain: Option<String>,
    pub description: Option<String>,
}

impl From<CreateAliasOptionsFfi> for quies_core::CreateAliasOptions {
    fn from(o: CreateAliasOptionsFfi) -> Self {
        quies_core::CreateAliasOptions {
            local_part: o.local_part,
            domain: o.domain,
            description: o.description,
        }
    }
}

pub struct AliasRecordFfi {
    pub provider_id: String,
    pub email: String,
    pub enabled: bool,
    pub description: Option<String>,
}

impl From<quies_core::AliasRecord> for AliasRecordFfi {
    fn from(r: quies_core::AliasRecord) -> Self {
        AliasRecordFfi {
            provider_id: r.provider_id,
            email: r.email,
            enabled: r.enabled,
            description: r.description,
        }
    }
}

pub struct AliasAccountInfoFfi {
    pub display_name: Option<String>,
    pub quota_remaining: Option<i64>,
}

impl From<quies_core::AliasAccountInfo> for AliasAccountInfoFfi {
    fn from(i: quies_core::AliasAccountInfo) -> Self {
        AliasAccountInfoFfi { display_name: i.display_name, quota_remaining: i.quota_remaining }
    }
}

pub struct HttpHeaderFfi {
    pub name: String,
    pub value: String,
}

pub struct HttpRequestSpecFfi {
    pub url: String,
    pub method: String,
    pub headers: Vec<HttpHeaderFfi>,
    pub body: Vec<u8>,
}

impl From<quies_core::HttpRequestSpec> for HttpRequestSpecFfi {
    fn from(spec: quies_core::HttpRequestSpec) -> Self {
        HttpRequestSpecFfi {
            url: spec.url,
            method: spec.method,
            headers: spec
                .headers
                .into_iter()
                .map(|(name, value)| HttpHeaderFfi { name, value })
                .collect(),
            body: spec.body,
        }
    }
}

pub fn alias_create_request(
    provider: AliasProviderKindFfi,
    api_key: String,
    options: CreateAliasOptionsFfi,
) -> HttpRequestSpecFfi {
    provider_for(provider.into()).create_alias_request(&api_key, &options.into()).into()
}

pub fn alias_parse_response(provider: AliasProviderKindFfi, response_body: Vec<u8>) -> Result<AliasRecordFfi, QuiesError> {
    provider_for(provider.into())
        .parse_alias_response(&response_body)
        .map(Into::into)
        .map_err(QuiesError::from)
}

pub fn alias_delete_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).delete_alias_request(&api_key, &provider_id).into()
}

pub fn alias_enable_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).enable_alias_request(&api_key, &provider_id).into()
}

pub fn alias_disable_request(provider: AliasProviderKindFfi, api_key: String, provider_id: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).disable_alias_request(&api_key, &provider_id).into()
}

pub fn alias_list_request(provider: AliasProviderKindFfi, api_key: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).list_aliases_request(&api_key).into()
}

pub fn alias_parse_list_response(
    provider: AliasProviderKindFfi,
    response_body: Vec<u8>,
) -> Result<Vec<AliasRecordFfi>, QuiesError> {
    let records = provider_for(provider.into())
        .parse_alias_list_response(&response_body)
        .map_err(QuiesError::from)?;
    Ok(records.into_iter().map(Into::into).collect())
}

pub fn alias_account_info_request(provider: AliasProviderKindFfi, api_key: String) -> HttpRequestSpecFfi {
    provider_for(provider.into()).account_info_request(&api_key).into()
}

pub fn alias_parse_account_info_response(
    provider: AliasProviderKindFfi,
    response_body: Vec<u8>,
) -> Result<AliasAccountInfoFfi, QuiesError> {
    provider_for(provider.into())
        .parse_account_info_response(&response_body)
        .map(Into::into)
        .map_err(QuiesError::from)
}
