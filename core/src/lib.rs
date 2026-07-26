pub mod aliases;
pub mod collections;
pub mod crypto;
pub mod errors;
pub mod favorites;
pub mod history;
pub mod import_export;
pub mod oauth;
pub mod password;
pub mod search;
pub mod sync;
pub mod tags;
pub mod vault;

/// Returns the current Unix timestamp in seconds.
/// Used internally by history and import/export modules.
pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

pub use aliases::{
    provider_for, AddyIoProvider, AliasAccountInfo, AliasProvider, AliasProviderKind, AliasRecord,
    CreateAliasOptions, SimpleLoginProvider,
};
pub use collections::{
    create_collection, delete_collection, list_children, list_root, move_entry, rename_collection,
    search_by_collection,
};
pub use crypto::{decrypt, derive_key, encrypt, generate_salt, Key, KdfParams};
pub use errors::CoreError;
pub use favorites::{list_favorites, search_favorites, set_favorite, FavoriteSort};
pub use oauth::{build_auth_url, build_token_exchange_request, decrypt_tokens, encrypt_tokens, generate_oauth_state, generate_pkce, parse_token_response, HttpRequestSpec, OAuthProvider, OAuthTokens, PkcePair};
pub use password::{
    check_strength, generate_password, generate_totp, get_breach_hash_parts, BreachHashParts,
};
pub use search::{SearchCache, SearchItem};
pub use sync::{
    build_status_report, merge, resolve_conflict, retry_backoff_seconds, ConflictStrategy,
    MergeResult, PendingChanges, SyncState, SyncStatusReport,
};
pub use tags::{assign_tag, create_tag, delete_tag, list_tags, remove_tag_from_entry, rename_tag, search_by_tag};
pub use history::{get_password_history, record_password_change, restore_password};
pub use import_export::{
    export_bitwarden_json, export_csv, export_1password_csv, export_protonpass_csv,
    import_1password_csv, import_bitwarden_json, import_csv, import_protonpass_csv,
};
pub use vault::{
    Attachment, AttachmentMeta, Collection, Entry, Index, IndexEntry, ItemCategory,
    PasswordHistoryItem, RekeyResult, Tag, Vault, VaultManifest, CURRENT_VAULT_VERSION,
    MAX_ATTACHMENT_SIZE_BYTES,
};
