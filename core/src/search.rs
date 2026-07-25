use serde::{Deserialize, Serialize};
use crate::crypto::{decrypt, encrypt, Key};
use crate::errors::CoreError;
use crate::vault::Index;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SearchItem {
    pub id: String,
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,
}

#[derive(Default)]
pub struct SearchCache {
    index_version: u64,
    items: Vec<SearchItem>,
}

impl SearchCache {
    pub fn rebuild_from_index(index: &Index) -> Self {
        let items = index
            .entries
            .iter()
            .filter(|e| !e.deleted)
            .map(|e| SearchItem {
                id: e.id.clone(),
                title: e.title.clone(),
                username: e.username.clone(),
                url: e.url.clone(),
                updated_at: e.updated_at,
            })
            .collect();

        Self {
            index_version: index.version,
            items,
        }
    }

    pub fn save_encrypted(&self, key: &Key) -> Result<Vec<u8>, CoreError> {
        let payload = serde_json::to_vec(&self.items)
            .map_err(|e| CoreError::InvalidFormat(format!("search cache serialize error: {e}")))?;
        encrypt(key, &payload, b"search_cache")
    }

    pub fn load_encrypted(key: &Key, ciphertext: &[u8], index_version: u64) -> Result<Self, CoreError> {
        let bytes = decrypt(key, ciphertext, b"search_cache")?;
        let items: Vec<SearchItem> = serde_json::from_slice(&bytes)
            .map_err(|e| CoreError::InvalidFormat(format!("search cache corrupt: {e}")))?;
        Ok(Self {
            index_version,
            items,
        })
    }

    pub fn index_version(&self) -> u64 {
        self.index_version
    }

    pub fn query(&self, term: &str) -> Vec<&SearchItem> {
        if term.trim().is_empty() {
            return self.items.iter().collect();
        }
        let lower = term.to_lowercase();
        self.items
            .iter()
            .filter(|item| {
                item.title.to_lowercase().contains(&lower)
                    || item.username.to_lowercase().contains(&lower)
                    || item.url.to_lowercase().contains(&lower)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, KdfParams};
    use crate::vault::IndexEntry;

    #[test]
    fn test_search_cache_query_and_crypto() {
        let mut index = Index::default();
        index.entries.push(IndexEntry {
            id: "1".into(),
            title: "GitHub".into(),
            username: "octocat".into(),
            url: "github.com".into(),
            updated_at: 1,
            deleted: false,
        });

        let cache = SearchCache::rebuild_from_index(&index);
        let results = cache.query("cat");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].title, "GitHub");

        let params = KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 };
        let key = derive_key("pass", &[0u8; 16], params).unwrap();
        let enc = cache.save_encrypted(&key).unwrap();

        let loaded = SearchCache::load_encrypted(&key, &enc, index.version).unwrap();
        assert_eq!(loaded.items.len(), 1);
    }
}
