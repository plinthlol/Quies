use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use crate::vault::Index;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, Default)]
pub struct PendingChanges {
    pub pending_entry_ids: HashSet<String>,
    pub last_synced_index_version: u64,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct MergeResult {
    pub to_upload_entries: Vec<String>,
    pub to_download_entries: Vec<String>,
    pub merged_index: Index,
}

pub fn merge(local: &Index, remote: &Index) -> MergeResult {
    let mut merged = Index {
        version: local.version.max(remote.version) + 1,
        entries: Vec::new(),
    };

    let mut to_upload = Vec::new();
    let mut to_download = Vec::new();

    let mut local_map = std::collections::HashMap::new();
    for entry in &local.entries {
        local_map.insert(entry.id.as_str(), entry);
    }

    let mut remote_map = std::collections::HashMap::new();
    for entry in &remote.entries {
        remote_map.insert(entry.id.as_str(), entry);
    }

    let mut all_ids: HashSet<&str> = HashSet::new();
    all_ids.extend(local_map.keys());
    all_ids.extend(remote_map.keys());

    for id in all_ids {
        match (local_map.get(id), remote_map.get(id)) {
            (Some(l), Some(r)) => {
                if l.updated_at >= r.updated_at {
                    merged.entries.push((*l).clone());
                    if l.updated_at > r.updated_at {
                        to_upload.push(id.to_string());
                    }
                } else {
                    merged.entries.push((*r).clone());
                    to_download.push(id.to_string());
                }
            }
            (Some(l), None) => {
                merged.entries.push((*l).clone());
                to_upload.push(id.to_string());
            }
            (None, Some(r)) => {
                merged.entries.push((*r).clone());
                to_download.push(id.to_string());
            }
            (None, None) => {}
        }
    }

    MergeResult {
        to_upload_entries: to_upload,
        to_download_entries: to_download,
        merged_index: merged,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::IndexEntry;

    #[test]
    fn test_merge_indexes() {
        let local_entry = IndexEntry {
            id: "1".into(),
            title: "Local Newer".into(),
            username: "u".into(),
            url: "url".into(),
            updated_at: 200,
            deleted: false,
        };
        let remote_entry = IndexEntry {
            id: "1".into(),
            title: "Remote Older".into(),
            username: "u".into(),
            url: "url".into(),
            updated_at: 100,
            deleted: false,
        };

        let mut local = Index::default();
        local.entries.push(local_entry);

        let mut remote = Index::default();
        remote.entries.push(remote_entry);

        let res = merge(&local, &remote);
        assert_eq!(res.to_upload_entries, vec!["1"]);
        assert_eq!(res.merged_index.entries[0].title, "Local Newer");
    }
}
