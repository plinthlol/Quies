use crate::errors::CoreError;
use crate::vault::{Entry, Index, IndexEntry, Tag};

/// Creates a new tag with the given (caller-supplied, e.g. UUID) id.
/// Rejects empty names, duplicate IDs, and case-insensitive duplicate names
/// among non-deleted tags.
pub fn create_tag(index: &mut Index, id: String, name: &str, now: i64) -> Result<Tag, CoreError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(CoreError::InvalidFormat("tag name cannot be empty".into()));
    }
    if index.tags.iter().any(|tag| tag.id == id) {
        return Err(CoreError::AlreadyExists(format!("tag id '{id}' already exists")));
    }
    if index
        .tags
        .iter()
        .any(|t| !t.deleted && t.name.eq_ignore_ascii_case(name))
    {
        return Err(CoreError::AlreadyExists(format!("tag '{name}' already exists")));
    }
    let tag = Tag {
        id,
        name: name.to_string(),
        updated_at: now,
        deleted: false,
    };
    index.tags.push(tag.clone());
    Ok(tag)
}

/// Renames an existing tag in place. The tag id (and therefore every entry's
/// reference to it) is unchanged.
pub fn rename_tag(index: &mut Index, tag_id: &str, new_name: &str, now: i64) -> Result<(), CoreError> {
    let new_name = new_name.trim();
    if new_name.is_empty() {
        return Err(CoreError::InvalidFormat("tag name cannot be empty".into()));
    }
    if index
        .tags
        .iter()
        .any(|t| !t.deleted && t.id != tag_id && t.name.eq_ignore_ascii_case(new_name))
    {
        return Err(CoreError::AlreadyExists(format!("tag '{new_name}' already exists")));
    }
    let tag = index
        .tags
        .iter_mut()
        .find(|t| t.id == tag_id && !t.deleted)
        .ok_or_else(|| CoreError::NotFound(format!("tag {tag_id}")))?;
    tag.name = new_name.to_string();
    tag.updated_at = now;
    Ok(())
}

/// Soft-deletes a tag and strips it from every `IndexEntry.tags` list so
/// search/filtering is consistent immediately. Returns the ids of entries
/// that referenced the tag — the caller still needs to decrypt each of those
/// full `Entry` blobs, drop the tag id from `Entry.tags` (see
/// [`remove_tag_from_entry`]), and re-save via `Vault::put_entry`, since core
/// only has the lightweight index in memory here, not every full entry.
pub fn delete_tag(index: &mut Index, tag_id: &str, now: i64) -> Result<Vec<String>, CoreError> {
    let tag = index
        .tags
        .iter_mut()
        .find(|t| t.id == tag_id && !t.deleted)
        .ok_or_else(|| CoreError::NotFound(format!("tag {tag_id}")))?;
    tag.deleted = true;
    tag.updated_at = now;

    let mut affected = Vec::new();
    for e in index.entries.iter_mut() {
        if e.tags.iter().any(|t| t == tag_id) {
            e.tags.retain(|t| t != tag_id);
            affected.push(e.id.clone());
        }
    }
    Ok(affected)
}

/// Assigns a tag to a decrypted `Entry`. Validates the tag exists (and isn't
/// deleted) against the index. Returns `Ok(true)` if newly assigned,
/// `Ok(false)` if the entry already had it. The caller must still persist the
/// change via `Vault::put_entry`, which will also sync `IndexEntry.tags`.
pub fn assign_tag(index: &Index, entry: &mut Entry, tag_id: &str) -> Result<bool, CoreError> {
    if !index.tags.iter().any(|t| t.id == tag_id && !t.deleted) {
        return Err(CoreError::NotFound(format!("tag {tag_id}")));
    }
    if entry.tags.iter().any(|t| t == tag_id) {
        return Ok(false);
    }
    entry.tags.push(tag_id.to_string());
    Ok(true)
}

/// Removes a tag from a decrypted `Entry`. Returns `true` if it was present.
pub fn remove_tag_from_entry(entry: &mut Entry, tag_id: &str) -> bool {
    let before = entry.tags.len();
    entry.tags.retain(|t| t != tag_id);
    entry.tags.len() != before
}

/// Non-deleted entries carrying the given tag id (index-level, no decryption
/// needed).
pub fn search_by_tag<'a>(index: &'a Index, tag_id: &str) -> Vec<&'a IndexEntry> {
    index
        .entries
        .iter()
        .filter(|e| !e.deleted && e.tags.iter().any(|t| t == tag_id))
        .collect()
}

/// All non-deleted tags.
pub fn list_tags(index: &Index) -> Vec<&Tag> {
    index.tags.iter().filter(|t| !t.deleted).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_entry(id: &str) -> Entry {
        Entry {
            id: id.into(),
            title: "t".into(),
            username: "u".into(),
            password: "p".into(),
            url: "url".into(),
            notes: "".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 1,
            deleted: false,
            tags: Vec::new(),
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: Default::default(),
            password_history: Vec::new(),
            attachments: Vec::new(),
        }
    }

    #[test]
    fn create_rejects_empty_and_duplicate_names() {
        let mut index = Index::default();
        create_tag(&mut index, "t1".into(), "Work", 1).unwrap();

        assert!(create_tag(&mut index, "t2".into(), "  ", 1).is_err());
        // case-insensitive duplicate
        assert!(matches!(
            create_tag(&mut index, "t3".into(), "work", 1),
            Err(CoreError::AlreadyExists(_))
        ));
        assert!(matches!(
            create_tag(&mut index, "t1".into(), "Personal", 1),
            Err(CoreError::AlreadyExists(_))
        ));
    }

    #[test]
    fn rename_updates_name_and_rejects_duplicates() {
        let mut index = Index::default();
        create_tag(&mut index, "t1".into(), "Work", 1).unwrap();
        create_tag(&mut index, "t2".into(), "Personal", 1).unwrap();

        rename_tag(&mut index, "t1", "Job", 2).unwrap();
        assert_eq!(index.tags[0].name, "Job");

        assert!(matches!(
            rename_tag(&mut index, "t1", "personal", 3),
            Err(CoreError::AlreadyExists(_))
        ));
        assert!(matches!(rename_tag(&mut index, "missing", "X", 3), Err(CoreError::NotFound(_))));
    }

    #[test]
    fn delete_strips_tag_from_index_entries_and_reports_affected_ids() {
        let mut index = Index::default();
        let tag = create_tag(&mut index, "t1".into(), "Work", 1).unwrap();

        let mut entry = test_entry("e1");
        assign_tag(&index, &mut entry, &tag.id).unwrap();

        // Simulate what Vault::put_entry would do to the index.
        index.entries.push(crate::vault::IndexEntry {
            id: entry.id.clone(),
            title: entry.title.clone(),
            username: entry.username.clone(),
            url: entry.url.clone(),
            updated_at: entry.updated_at,
            deleted: entry.deleted,
            tags: entry.tags.clone(),
            collection_id: entry.collection_id.clone(),
            favorite: entry.favorite,
            category: entry.category,
            attachments: entry.attachments.clone(),
        });

        assert_eq!(search_by_tag(&index, &tag.id).len(), 1);

        let affected = delete_tag(&mut index, &tag.id, 2).unwrap();
        assert_eq!(affected, vec!["e1".to_string()]);
        assert_eq!(search_by_tag(&index, &tag.id).len(), 0);
        assert!(list_tags(&index).is_empty());
    }

    #[test]
    fn assign_tag_rejects_unknown_or_deleted_tag() {
        let mut index = Index::default();
        let tag = create_tag(&mut index, "t1".into(), "Work", 1).unwrap();
        delete_tag(&mut index, &tag.id, 2).unwrap();

        let mut entry = test_entry("e1");
        assert!(matches!(assign_tag(&index, &mut entry, &tag.id), Err(CoreError::NotFound(_))));
        assert!(matches!(assign_tag(&index, &mut entry, "nonexistent"), Err(CoreError::NotFound(_))));
    }

    #[test]
    fn assign_tag_is_idempotent() {
        let mut index = Index::default();
        let tag = create_tag(&mut index, "t1".into(), "Work", 1).unwrap();
        let mut entry = test_entry("e1");

        assert!(assign_tag(&index, &mut entry, &tag.id).unwrap());
        assert!(!assign_tag(&index, &mut entry, &tag.id).unwrap());
        assert_eq!(entry.tags.len(), 1);

        assert!(remove_tag_from_entry(&mut entry, &tag.id));
        assert!(entry.tags.is_empty());
        assert!(!remove_tag_from_entry(&mut entry, &tag.id));
    }
}
