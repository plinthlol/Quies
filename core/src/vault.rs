use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::crypto::{decrypt, derive_key, encrypt, generate_salt, Key, KdfParams};
use crate::errors::CoreError;

pub const CURRENT_VAULT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct VaultManifest {
    pub version: u32,
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl VaultManifest {
    pub fn kdf_params(&self) -> KdfParams {
        KdfParams {
            memory_kib: self.memory_kib,
            iterations: self.iterations,
            parallelism: self.parallelism,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct IndexEntry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
    pub deleted: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct Index {
    pub version: u64,
    pub entries: Vec<IndexEntry>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub id: String,
    pub title: String,
    pub username: String,
    pub password: String,
    pub url: String,
    pub notes: String,
    pub totp_secret: Option<String>,
    pub custom_fields: HashMap<String, String>,
    pub updated_at: i64,
    pub deleted: bool,
}

pub struct Vault {
    key: Key,
}

impl Vault {
    pub fn create(password: &str, params: KdfParams) -> Result<(Self, VaultManifest, Vec<u8>), CoreError> {
        let salt = generate_salt()?;
        let key = derive_key(password, &salt, params)?;

        let manifest = VaultManifest {
            version: CURRENT_VAULT_VERSION,
            salt,
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        };

        let empty_index = Index::default();
        let index_json = serde_json::to_vec(&empty_index)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize index: {e}")))?;
        let index_enc = encrypt(&key, &index_json, b"index")?;

        Ok((Vault { key }, manifest, index_enc))
    }

    pub fn unlock(
        manifest: &VaultManifest,
        index_enc: &[u8],
        password: &str,
    ) -> Result<(Self, Index), CoreError> {
        if manifest.version > CURRENT_VAULT_VERSION {
            return Err(CoreError::UnsupportedVersion(manifest.version));
        }

        let key = derive_key(password, &manifest.salt, manifest.kdf_params())?;
        let index_bytes = decrypt(&key, index_enc, b"index")?;
        let index: Index = serde_json::from_slice(&index_bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("corrupt index json: {e}")))?;

        Ok((Vault { key }, index))
    }

    pub fn lock(self) {}

    pub fn decrypt_entry(&self, entry_enc: &[u8], entry_id: &str) -> Result<Entry, CoreError> {
        let bytes = decrypt(&self.key, entry_enc, entry_id.as_bytes())?;
        serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("corrupt entry json: {e}")))
    }

    pub fn put_entry(
        &self,
        index: &mut Index,
        entry: Entry,
    ) -> Result<(Vec<u8>, Vec<u8>), CoreError> {
        let entry_id = entry.id.clone();
        let index_item = IndexEntry {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            updated_at: entry.updated_at,
            deleted: entry.deleted,
        };

        if let Some(pos) = index.entries.iter().position(|e| e.id == entry_id) {
            index.entries[pos] = index_item;
        } else {
            index.entries.push(index_item);
        }
        index.version += 1;

        let entry_json = serde_json::to_vec(&entry)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize entry: {e}")))?;
        let entry_enc = encrypt(&self.key, &entry_json, entry_id.as_bytes())?;

        let index_json = serde_json::to_vec(index)
            .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize index: {e}")))?;
        let index_enc = encrypt(&self.key, &index_json, b"index")?;

        Ok((entry_enc, index_enc))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_params() -> KdfParams {
        KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 }
    }

    #[test]
    fn vault_create_and_unlock_roundtrip() {
        let (vault, manifest, index_enc) = Vault::create("pass123", test_params()).unwrap();
        let (_unlocked_vault, index) = Vault::unlock(&manifest, &index_enc, "pass123").unwrap();
        assert_eq!(index.entries.len(), 0);
        vault.lock();
    }

    #[test]
    fn put_and_decrypt_entry() {
        let (vault, _manifest, _index_enc) = Vault::create("pass123", test_params()).unwrap();
        let mut index = Index::default();

        let entry = Entry {
            id: "uuid-1".into(),
            title: "Github".into(),
            username: "user".into(),
            password: "secretpassword".into(),
            url: "https://github.com".into(),
            notes: "note".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 100,
            deleted: false,
        };

        let (entry_enc, _updated_index_enc) = vault.put_entry(&mut index, entry.clone()).unwrap();
        let decrypted = vault.decrypt_entry(&entry_enc, "uuid-1").unwrap();
        assert_eq!(decrypted, entry);
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].title, "Github");
    }
}
