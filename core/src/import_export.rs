/// Vault import / export support.
///
/// This module converts between the `quies-core` [`Entry`] model and
/// well-known password-manager interchange formats.  **No networking** is
/// performed here — callers supply raw bytes and receive structured data (or
/// vice-versa).
///
/// Supported formats
/// -----------------
/// | Format              | Import | Export |
/// |---------------------|--------|--------|
/// | Bitwarden JSON      | ✅     | ✅     |
/// | Generic CSV         | ✅     | ✅     |
/// | 1Password CSV       | ✅     | ❌     |
/// | Proton Pass CSV     | ✅     | ❌     |
use crate::errors::CoreError;
use crate::vault::{Entry, ItemCategory};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ──────────────────────────────────────────────────────────────────────────────
// Bitwarden JSON
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Debug)]
struct BwLoginUri {
    #[serde(rename = "uri")]
    uri: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    totp: Option<String>,
    uris: Option<Vec<BwLoginUri>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwField {
    name: Option<String>,
    value: Option<String>,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct BwItem {
    #[serde(rename = "type")]
    item_type: u32,
    name: String,
    notes: Option<String>,
    login: Option<BwLogin>,
    fields: Option<Vec<BwField>>,
}

#[derive(Serialize, Deserialize, Debug)]
struct BwExport {
    items: Vec<BwItem>,
}

/// Marker custom field used to round-trip a category Bitwarden's format has
/// no native `type` for (currently just [`ItemCategory::BankAccount`]).
/// Written by `export_bitwarden_json`, consumed (and stripped back out of
/// `custom_fields`) by `import_bitwarden_json`. Any Bitwarden-side client
/// just sees an ordinary custom field and ignores it.
const CATEGORY_OVERRIDE_FIELD: &str = "_quies_original_category";

/// Parse a Bitwarden JSON export (unencrypted vault export from
/// bitwarden.com → Tools → Export).
pub fn import_bitwarden_json(json_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let export: BwExport = serde_json::from_slice(json_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("invalid Bitwarden JSON: {e}")))?;

    let mut entries = Vec::new();
    let now = crate::now_unix();

    for item in export.items {
        let login = item.login.as_ref();
        let url = login
            .and_then(|l| l.uris.as_ref())
            .and_then(|uris| uris.first())
            .and_then(|u| u.uri.clone())
            .unwrap_or_default();

        let mut category = match item.item_type {
            1 => ItemCategory::Login,
            2 => ItemCategory::SecureNote,
            3 => ItemCategory::CreditCard,
            4 => ItemCategory::Identity,
            _ => ItemCategory::Login,
        };

        let mut custom_fields = item
            .fields
            .unwrap_or_default()
            .into_iter()
            .filter_map(|f| Some((f.name?, f.value.unwrap_or_default())))
            .collect::<HashMap<_, _>>();

        // Restore a category Bitwarden's `type` can't represent natively, if
        // this export was produced by export_bitwarden_json — see
        // CATEGORY_OVERRIDE_FIELD. Strip the marker either way so it doesn't
        // show up as a visible junk custom field.
        if let Some(marker) = custom_fields.remove(CATEGORY_OVERRIDE_FIELD) {
            if marker == "BankAccount" {
                category = ItemCategory::BankAccount;
            }
        }

        entries.push(Entry {
            id: new_id()?,
            title: item.name,
            username: login
                .and_then(|l| l.username.clone())
                .unwrap_or_default(),
            password: login
                .and_then(|l| l.password.clone())
                .unwrap_or_default(),
            url,
            notes: item.notes.unwrap_or_default(),
            totp_secret: login.and_then(|l| l.totp.clone()),
            custom_fields,
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize the given entries as a Bitwarden-compatible JSON export.
pub fn export_bitwarden_json(entries: &[Entry]) -> Result<Vec<u8>, CoreError> {
    let items: Vec<BwItem> = entries
        .iter()
        .filter(|e| !e.deleted)
        .map(|e| BwItem {
            item_type: match e.category {
                ItemCategory::Login => 1,
                ItemCategory::SecureNote => 2,
                ItemCategory::CreditCard => 3,
                ItemCategory::Identity => 4,
                ItemCategory::BankAccount => 1,
            },
            name: e.title.clone(),
            notes: if e.notes.is_empty() {
                None
            } else {
                Some(e.notes.clone())
            },
            login: Some(BwLogin {
                username: Some(e.username.clone()),
                password: Some(e.password.clone()),
                totp: e.totp_secret.clone(),
                uris: if e.url.is_empty() {
                    None
                } else {
                    Some(vec![BwLoginUri {
                        uri: Some(e.url.clone()),
                    }])
                },
            }),
            fields: {
                let mut fields: Vec<BwField> = e
                    .custom_fields
                    .iter()
                    .map(|(k, v)| BwField {
                        name: Some(k.clone()),
                        value: Some(v.clone()),
                    })
                    .collect();
                if e.category == ItemCategory::BankAccount {
                    fields.push(BwField {
                        name: Some(CATEGORY_OVERRIDE_FIELD.to_string()),
                        value: Some("BankAccount".to_string()),
                    });
                }
                if fields.is_empty() { None } else { Some(fields) }
            },
        })
        .collect();

    serde_json::to_vec_pretty(&BwExport { items })
        .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize Bitwarden JSON: {e}")))
}

// ──────────────────────────────────────────────────────────────────────────────
// Generic CSV
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a generic password CSV with headers:
/// `title,username,password,url,notes`
pub fn import_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("CSV is not valid UTF-8: {e}")))?;

    let mut entries = Vec::new();
    let now = crate::now_unix();

    let mut lines = text.lines();
    let header = lines
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("CSV has no header row".into()))?;

    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let title_idx = col_idx("title").or_else(|| col_idx("name"));
    let user_idx = col_idx("username").or_else(|| col_idx("login"));
    let pass_idx = col_idx("password");
    let url_idx = col_idx("url").or_else(|| col_idx("website"));
    let notes_idx = col_idx("notes").or_else(|| col_idx("note"));

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(line);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i)).cloned().unwrap_or_default()
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(title_idx),
            username: get(user_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(notes_idx),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a generic CSV with headers:
/// `title,username,password,url,notes`
pub fn export_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("title,username,password,url,notes\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// 1Password CSV (Title,Username,Password,URL,OTPAuth,Notes)
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a 1Password CSV export file.
pub fn import_1password_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    // 1Password exports use the same column names as generic CSV plus `OTPAuth`
    // for TOTP. We run the generic importer first then patch TOTP.
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("1Password CSV is not valid UTF-8: {e}")))?;

    let now = crate::now_unix();
    let mut entries = Vec::new();
    let mut lines = text.lines();

    let header = lines
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("1Password CSV has no header row".into()))?;
    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let title_idx = col_idx("title");
    let user_idx = col_idx("username");
    let pass_idx = col_idx("password");
    let url_idx = col_idx("url");
    let notes_idx = col_idx("notes");
    let totp_idx = col_idx("otpauth").or_else(|| col_idx("one-time password"));

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(line);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i)).cloned().unwrap_or_default()
        };

        let totp_raw = get(totp_idx);
        let totp_secret = if totp_raw.starts_with("otpauth://") {
            extract_totp_secret_from_uri(&totp_raw)
        } else if !totp_raw.is_empty() {
            Some(totp_raw)
        } else {
            None
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(title_idx),
            username: get(user_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(notes_idx),
            totp_secret,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a 1Password-compatible CSV with headers:
/// `Title,Username,Password,URL,OTPAuth,Notes`
pub fn export_1password_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("Title,Username,Password,URL,OTPAuth,Notes\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        if let Some(secret) = &e.totp_secret {
            // title/username can contain arbitrary characters (':', '?',
            // '&', ...) — percent-encode them so the URI's query string
            // boundary is unambiguous. Otherwise a title like "Is this a
            // bank?" would shift where extract_totp_secret_from_uri thinks
            // the query starts, and the secret would silently fail to
            // round-trip back in on import.
            let title_enc = crate::oauth::percent_encode(&e.title);
            let user_enc = crate::oauth::percent_encode(&e.username);
            out.push_str(&csv_field(&format!(
                "otpauth://totp/{title_enc}:{user_enc}?secret={secret}&issuer={title_enc}"
            )));
        }
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Proton Pass CSV
// ──────────────────────────────────────────────────────────────────────────────

/// Parse a Proton Pass CSV export file.
///
/// Proton Pass exports use these headers:
/// `name, url, email, password, note, totp`
pub fn import_protonpass_csv(csv_bytes: &[u8]) -> Result<Vec<Entry>, CoreError> {
    let text = std::str::from_utf8(csv_bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("Proton Pass CSV is not valid UTF-8: {e}")))?;

    let now = crate::now_unix();
    let mut entries = Vec::new();
    let mut lines = text.lines();

    let header = lines
        .next()
        .ok_or_else(|| CoreError::InvalidFormat("Proton Pass CSV has no header row".into()))?;
    let cols: Vec<String> = split_csv_row(header);
    let col_idx = |name: &str| cols.iter().position(|c| c.eq_ignore_ascii_case(name));

    let name_idx = col_idx("name");
    let url_idx = col_idx("url");
    let email_idx = col_idx("email").or_else(|| col_idx("username"));
    let pass_idx = col_idx("password");
    let note_idx = col_idx("note").or_else(|| col_idx("notes"));
    let totp_idx = col_idx("totp");

    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let fields = split_csv_row(line);
        // split_csv_row already stripped quotes and un-escaped `""`, so the
        // field is the real value already — no further trimming needed (and
        // trimming here was the bug: see split_csv_row's doc comment).
        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| fields.get(i)).cloned().unwrap_or_default()
        };

        let totp_raw = get(totp_idx);
        let totp_secret = if totp_raw.starts_with("otpauth://") {
            extract_totp_secret_from_uri(&totp_raw)
        } else if !totp_raw.is_empty() {
            Some(totp_raw)
        } else {
            None
        };

        entries.push(Entry {
            id: new_id()?,
            title: get(name_idx),
            username: get(email_idx),
            password: get(pass_idx),
            url: get(url_idx),
            notes: get(note_idx),
            totp_secret,
            custom_fields: HashMap::new(),
            updated_at: now,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        });
    }

    Ok(entries)
}

/// Serialize entries to a Proton Pass-compatible CSV with headers:
/// `name,url,email,password,note,totp`
pub fn export_protonpass_csv(entries: &[Entry]) -> Vec<u8> {
    let mut out = String::from("name,url,email,password,note,totp\n");
    for e in entries.iter().filter(|e| !e.deleted) {
        out.push_str(&csv_field(&e.title));
        out.push(',');
        out.push_str(&csv_field(&e.url));
        out.push(',');
        out.push_str(&csv_field(&e.username));
        out.push(',');
        out.push_str(&csv_field(&e.password));
        out.push(',');
        out.push_str(&csv_field(&e.notes));
        out.push(',');
        if let Some(secret) = &e.totp_secret {
            out.push_str(&csv_field(secret));
        }
        out.push('\n');
    }
    out.into_bytes()
}

// ──────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ──────────────────────────────────────────────────────────────────────────────

/// Generates a random RFC 4122 version-4 UUID, used as the id for every
/// entry produced by import. Must be a real CSPRNG draw, not a hash of
/// coarse, low-entropy inputs: this id is used to key entries in the vault
/// index and to name their `entries/{id}.enc` file on disk, so two entries
/// getting the same id during a bulk import silently overwrite one another.
/// (getrandom is already used everywhere else in this crate for exactly this
/// kind of unique/secret value, and already has wasm32 support configured in
/// Cargo.toml, so this works identically on native and in the browser build.)
fn new_id() -> Result<String, CoreError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random id".to_string()))?;
    // RFC 4122 §4.4: set version (4) and variant (RFC 4122) bits.
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Ok(format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3],
        bytes[4], bytes[5],
        bytes[6], bytes[7],
        bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ))
}

fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// RFC 4180 field splitter. Unlike a naive quote-toggling splitter, this
/// actually consumes the surrounding quotes and un-escapes a doubled `""`
/// into a literal `"` as it goes, so callers get the real field value
/// directly — no separate `trim_matches('"')` pass is needed (and doing that
/// afterwards was the bug: it strips quote characters from both ends of the
/// raw token irrespective of how many of them were content vs. delimiters,
/// corrupting any field with an embedded escaped quote, e.g. `"Say ""Hi"""`
/// coming back as `Say ""Hi` instead of `Say "Hi"`).
fn split_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let chars: Vec<char> = line.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if in_quotes {
            if c == '"' {
                if chars.get(i + 1) == Some(&'"') {
                    field.push('"');
                    i += 1; // consume the escaped pair together
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => fields.push(std::mem::take(&mut field)),
                _ => field.push(c),
            }
        }
        i += 1;
    }
    fields.push(field);
    fields
}

fn extract_totp_secret_from_uri(uri: &str) -> Option<String> {
    uri.split('?')
        .nth(1)?
        .split('&')
        .find_map(|param| {
            let (k, v) = param.split_once('=')?;
            if k.eq_ignore_ascii_case("secret") {
                Some(v.to_string())
            } else {
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bulk_import_produces_unique_ids() {
        // Regression test for the old new_id() implementation, which hashed
        // only a coarse clock reading + the (unchanging, within one loop)
        // thread id — entries imported back-to-back could collide and
        // silently overwrite each other. Import a decent-sized batch in a
        // tight loop (the worst case for a weak clock-based id) and check
        // every id came out distinct.
        let mut csv = String::from("title,username,password,url,notes\n");
        for i in 0..500 {
            csv.push_str(&format!("Item {i},user{i},pass{i},,\n"));
        }
        let entries = import_csv(csv.as_bytes()).unwrap();
        assert_eq!(entries.len(), 500);
        let unique: std::collections::HashSet<_> = entries.iter().map(|e| e.id.clone()).collect();
        assert_eq!(unique.len(), 500, "import produced duplicate entry ids");
    }

    #[test]
    fn onepassword_totp_roundtrip_survives_question_mark_in_title() {
        // Regression test: title/username used to be spliced unescaped into
        // the otpauth:// URI, so a literal '?' in the title shifted where
        // extract_totp_secret_from_uri thought the query string started,
        // silently dropping the secret on export -> reimport.
        let entries = vec![Entry {
            id: "test".into(),
            title: "Is this a bank?".into(),
            username: "alice".into(),
            password: "s3cr3t".into(),
            url: "".into(),
            notes: "".into(),
            totp_secret: Some("JBSWY3DPEHPK3PXP".into()),
            custom_fields: HashMap::new(),
            updated_at: 0,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];

        let exported = export_1password_csv(&entries);
        let reimported = import_1password_csv(&exported).unwrap();
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn bitwarden_json_roundtrip() {
        let json = br#"{
            "items": [{
                "type": 1,
                "name": "GitHub",
                "notes": "work account",
                "login": {
                    "username": "dev@example.com",
                    "password": "s3cr3t!",
                    "totp": "JBSWY3DPEHPK3PXP",
                    "uris": [{"uri": "https://github.com"}]
                },
                "fields": [{"name": "recovery", "value": "abc123"}]
            }]
        }"#;

        let entries = import_bitwarden_json(json).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "dev@example.com");
        assert_eq!(entries[0].password, "s3cr3t!");
        assert_eq!(entries[0].url, "https://github.com");
        assert_eq!(entries[0].notes, "work account");
        assert_eq!(
            entries[0].totp_secret.as_deref(),
            Some("JBSWY3DPEHPK3PXP")
        );
        assert_eq!(
            entries[0].custom_fields.get("recovery").map(|s| s.as_str()),
            Some("abc123")
        );

        let exported = export_bitwarden_json(&entries).unwrap();
        let reimported = import_bitwarden_json(&exported).unwrap();
        assert_eq!(reimported[0].username, "dev@example.com");
    }

    #[test]
    fn bitwarden_json_roundtrip_preserves_bank_account_category() {
        // Bitwarden's `type` field has no bank-account value, so this used to
        // silently and permanently downgrade to Login on export. It should
        // now round-trip back to BankAccount via the marker custom field.
        let entries = vec![Entry {
            id: "test".into(),
            title: "My Bank".into(),
            username: "".into(),
            password: "".into(),
            url: "".into(),
            notes: "".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 0,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::BankAccount,
            password_history: vec![],
            attachments: vec![],
        }];

        let exported = export_bitwarden_json(&entries).unwrap();
        // Still a valid, plain Bitwarden Login item — type 1 — for any
        // Bitwarden-side client that opens this export.
        let text = String::from_utf8(exported.clone()).unwrap();
        assert!(text.contains("\"type\": 1"));

        let reimported = import_bitwarden_json(&exported).unwrap();
        assert_eq!(reimported[0].category, ItemCategory::BankAccount);
        // Marker field shouldn't leak through as a visible custom field.
        assert!(!reimported[0].custom_fields.contains_key(CATEGORY_OVERRIDE_FIELD));
    }

    #[test]
    fn csv_roundtrip() {
        let csv = b"title,username,password,url,notes\nGitHub,user,pass123,https://github.com,work\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].password, "pass123");

        let exported = export_csv(&entries);
        let reimported = import_csv(&exported).unwrap();
        assert_eq!(reimported[0].title, "GitHub");
        assert_eq!(reimported[0].password, "pass123");
    }

    #[test]
    fn onepassword_csv_extracts_totp_from_uri() {
        let csv = b"Title,Username,Password,URL,OTPAuth,Notes\nSlack,alice,s3cr3t,https://slack.com,otpauth://totp/Slack:alice?secret=JBSWY3DPEHPK3PXP&issuer=Slack,\n";
        let entries = import_1password_csv(csv).unwrap();
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn csv_handles_escaped_quotes_in_quoted_fields() {
        // RFC 4180: a literal `"` inside a quoted field is written as `""`.
        // Regression test for the split_csv_row bug where a trailing
        // trim_matches('"') pass mangled fields like this instead of the
        // parser itself consuming/un-escaping the quotes.
        let csv = b"title,username,password,url,notes\n\"Say \"\"Hi\"\"\",user,pass,,\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Say \"Hi\"");
    }

    #[test]
    fn csv_handles_commas_in_quoted_fields() {
        let csv = b"title,username,password,url,notes\n\"Smith, John\",user,pass,,\"note with, comma\"\n";
        let entries = import_csv(csv).unwrap();
        assert_eq!(entries[0].title, "Smith, John");
        assert_eq!(entries[0].username, "user");
        assert_eq!(entries[0].notes, "note with, comma");
    }

    #[test]
    fn protonpass_csv_import() {
        let csv = b"name,url,email,password,note,totp\nGitHub,https://github.com,alice@example.com,s3cr3t!,work account,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\nProton Mail,https://mail.proton.me,bob@proton.me,p@ss123,,\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "alice@example.com");
        assert_eq!(entries[0].password, "s3cr3t!");
        assert_eq!(entries[0].url, "https://github.com");
        assert_eq!(entries[0].notes, "work account");
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(entries[1].title, "Proton Mail");
        assert_eq!(entries[1].totp_secret, None);
    }

    #[test]
    fn protonpass_csv_handles_raw_totp_secret() {
        let csv = b"name,url,email,password,note,totp\nSlack,https://slack.com,user@x.com,pass123,,JBSWY3DPEHPK3PXP\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn onepassword_csv_export_roundtrip() {
        let csv = b"Title,Username,Password,URL,OTPAuth,Notes\nSlack,alice,s3cr3t,https://slack.com,otpauth://totp/Slack:alice?secret=JBSWY3DPEHPK3PXP&issuer=Slack,work\nGitHub,bob,p@ss,https://github.com,,personal\n";
        let entries = import_1password_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);

        let exported = export_1password_csv(&entries);
        let reimported = import_1password_csv(&exported).unwrap();
        assert_eq!(reimported.len(), 2);
        assert_eq!(reimported[0].title, "Slack");
        assert_eq!(reimported[0].username, "alice");
        assert_eq!(reimported[0].password, "s3cr3t");
        assert_eq!(reimported[0].url, "https://slack.com");
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(reimported[0].notes, "work");
        assert_eq!(reimported[1].title, "GitHub");
        assert_eq!(reimported[1].totp_secret, None);
    }

    #[test]
    fn onepassword_csv_export_without_totp() {
        let entries = vec![Entry {
            id: "test".into(),
            title: "No TOTP".into(),
            username: "alice".into(),
            password: "pass".into(),
            url: "https://example.com".into(),
            notes: "notes".into(),
            totp_secret: None,
            custom_fields: HashMap::new(),
            updated_at: 0,
            deleted: false,
            tags: vec![],
            collection_id: None,
            favorite: false,
            alias_provider: None,
            alias_id: None,
            alias_email: None,
            category: ItemCategory::Login,
            password_history: vec![],
            attachments: vec![],
        }];
        let exported = export_1password_csv(&entries);
        let text = String::from_utf8(exported).unwrap();
        // OTPAuth column should be empty
        assert!(text.contains("No TOTP,alice,pass,https://example.com,,notes"));
    }

    #[test]
    fn protonpass_csv_export_roundtrip() {
        let csv = b"name,url,email,password,note,totp\nGitHub,https://github.com,alice@example.com,s3cr3t!,work account,otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub\nProton Mail,https://mail.proton.me,bob@proton.me,p@ss123,,\n";
        let entries = import_protonpass_csv(csv).unwrap();
        assert_eq!(entries.len(), 2);

        let exported = export_protonpass_csv(&entries);
        let reimported = import_protonpass_csv(&exported).unwrap();
        assert_eq!(reimported.len(), 2);
        assert_eq!(reimported[0].title, "GitHub");
        assert_eq!(reimported[0].username, "alice@example.com");
        assert_eq!(reimported[0].password, "s3cr3t!");
        assert_eq!(reimported[0].url, "https://github.com");
        assert_eq!(reimported[0].notes, "work account");
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
        assert_eq!(reimported[1].title, "Proton Mail");
        assert_eq!(reimported[1].totp_secret, None);
    }

    #[test]
    fn protonpass_csv_export_raw_totp_passthrough() {
        let csv = b"name,url,email,password,note,totp\nSlack,https://slack.com,user@x.com,pass123,,JBSWY3DPEHPK3PXP\n";
        let entries = import_protonpass_csv(csv).unwrap();

        let exported = export_protonpass_csv(&entries);
        let reimported = import_protonpass_csv(&exported).unwrap();
        assert_eq!(reimported[0].totp_secret.as_deref(), Some("JBSWY3DPEHPK3PXP"));
    }

    #[test]
    fn export_skips_deleted_entries() {
        let entries = vec![
            Entry {
                id: "1".into(),
                title: "Keep".into(),
                username: "u".into(),
                password: "p".into(),
                url: "".into(),
                notes: "".into(),
                totp_secret: None,
                custom_fields: HashMap::new(),
                updated_at: 0,
                deleted: false,
                tags: vec![],
                collection_id: None,
                favorite: false,
                alias_provider: None,
                alias_id: None,
                alias_email: None,
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            },
            Entry {
                id: "2".into(),
                title: "Deleted".into(),
                username: "u".into(),
                password: "p".into(),
                url: "".into(),
                notes: "".into(),
                totp_secret: None,
                custom_fields: HashMap::new(),
                updated_at: 0,
                deleted: true,
                tags: vec![],
                collection_id: None,
                favorite: false,
                alias_provider: None,
                alias_id: None,
                alias_email: None,
                category: ItemCategory::Login,
                password_history: vec![],
                attachments: vec![],
            },
        ];

        let exported_1p = export_1password_csv(&entries);
        let text_1p = String::from_utf8(exported_1p).unwrap();
        assert!(text_1p.contains("Keep"));
        assert!(!text_1p.contains("Deleted"));

        let exported_pp = export_protonpass_csv(&entries);
        let text_pp = String::from_utf8(exported_pp).unwrap();
        assert!(text_pp.contains("Keep"));
        assert!(!text_pp.contains("Deleted"));
    }
}
