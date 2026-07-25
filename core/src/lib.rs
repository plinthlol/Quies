pub mod crypto;
pub mod errors;
pub mod oauth;
pub mod password;
pub mod search;
pub mod sync;
pub mod vault;

pub use crypto::{decrypt, decrypt_raw, derive_key, encrypt, encrypt_raw, generate_salt, Key, KdfParams};
pub use errors::CoreError;
pub use oauth::{build_auth_url, build_token_exchange_request, decrypt_tokens, encrypt_tokens, generate_pkce, parse_token_response, HttpRequestSpec, OAuthProvider, OAuthTokens, PkcePair};
pub use password::{check_strength, generate_password, generate_totp};
pub use search::{SearchCache, SearchItem};
pub use sync::{merge, MergeResult, PendingChanges};
pub use vault::{Entry, Index, IndexEntry, Vault, VaultManifest, CURRENT_VAULT_VERSION};
