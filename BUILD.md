# Quies — Agent Build Spec

This document is written for an AI agent. Follow it exactly. Do not add features not listed.
Do not use libraries not listed. When in doubt, just ask.

---

## Core Rule

**Core does crypto. Shell does everything else.**

The shell (desktop/mobile/extension) MUST:
- Never store the vault key on disk in plaintext
- Never log passwords, keys, or plaintext entry data
- Never handle crypto directly — always call core
- Wipe the key from memory on lock/timeout

**Update (post-audit fix):** `core-wasm` and `core-ffi` used to return the raw 32-byte vault key to
the caller as a base64 string (`wasm_create_vault`, `wasm_unlock_vault`, `create_vault`,
`unlock_vault`), with every subsequent `encrypt`/`decrypt` call taking the key back in as a string
argument. That contradicted the Core Rule above for any shell built on WASM or UniFFI, since a
JS/Swift/Kotlin string cannot be reliably zeroized. See `QUIES_AUDIT_FINDINGS.md` [HIGH] for the full
analysis. This has been fixed: `create_vault`/`unlock_vault`/`wasm_create_vault`/`wasm_unlock_vault`
now return an opaque `u64` handle instead of a key. The `Vault` (and its private, zeroize-on-drop
`Key`) lives entirely inside a Rust-owned registry in `core-wasm`/`core-ffi` and is never serialized
out. Use `vault_encrypt`/`vault_decrypt`/`vault_decrypt_entry`/`vault_put_entry`
(`wasm_vault_encrypt`/etc. on the WASM side) with the handle, and call `lock_vault`/`wasm_lock_vault`
on lock/timeout to drop the entry and zeroize the key. This is a breaking API change from the
pre-audit version — any existing shell code calling the old `key_b64`-based functions needs updating
to pass a handle instead.

- **Tauri desktop** is unaffected either way — `src-tauri` links `quies-core` directly as a native
  Rust dependency and already kept the opaque `Vault` inside Rust app state for the whole session.
- **Extension / iOS / Android** now get the same guarantee via the handle registry: the key never
  exists as a JS/Swift/Kotlin value at all, so there's nothing for those runtimes to fail to zeroize.

---

## Existing Codebase

This repository currently contains only the core and its two binding crates — no shell has been built
yet, despite `README.md` describing one. Treat any shell-related claims in `README.md`/`PLAN.md` as
aspirational until you've verified the corresponding directory actually exists.

```
<repo-root>/
├── Cargo.toml          # workspace: members = ["core", "core-wasm", "core-ffi"]
├── core/                # quies-core — DO NOT MODIFY unless fixing a bug
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs
│       ├── crypto.rs    # Argon2id + XChaCha20-Poly1305
│       ├── vault.rs     # Vault, Entry, Index, VaultManifest
│       ├── search.rs    # SearchCache
│       ├── password.rs  # generate_password, check_strength, generate_totp
│       ├── sync.rs       # merge()
│       ├── oauth.rs      # PKCE, auth URL, token exchange/encryption
│       └── errors.rs     # CoreError
├── core-wasm/            # wasm-bindgen wrapper — for browser extension only
│   ├── Cargo.toml
│   └── src/lib.rs
└── core-ffi/             # UniFFI wrapper — for iOS and Android only
    ├── Cargo.toml
    ├── build.rs
    └── src/
        ├── lib.rs
        └── quies.udl
```

Not yet present, and not part of this snapshot: `extension/`, `ui/`, `src-tauri/`, `ios/`, `android/`.
Building any of these is what this document covers. All paths below are relative to the workspace
root — substitute your actual checkout path, don't hardcode one.

Verify the core builds and its 19 existing unit tests pass before building any shell against it:
```bash
cd core && cargo test --lib
cd ../core-wasm && cargo check
cd ../core-ffi && cargo check
```

---

## Auth Strategy (ALL platforms)

Password + auto-lock timeout. No biometrics. No OS keychain.

```
Unlock:   user types master password
          → shell calls core to derive key + decrypt vault
          → key held in app memory only
          → start idle timer (default 5 minutes)

Locked:   idle timer fires OR app backgrounds OR user presses lock
          → key wiped from memory
          → UI shows lock screen

Re-unlock: user types password again
```

The key NEVER touches disk. The key NEVER leaves the process memory. (For WASM/FFI-based shells,
re-read the note in **Core Rule** above — this guarantee currently only fully holds for Tauri.)

---

## Core API — Exact Function Signatures

These are the core functions the shell needs. All error types are `CoreError`.

```rust
// --- Vault lifecycle ---

// Create a brand new vault. Returns manifest (save to disk as JSON),
// encrypted index blob (save to disk), and the unlocked Vault struct.
Vault::create(password: &str, params: KdfParams)
  -> Result<(Vault, VaultManifest, Vec<u8>), CoreError>

// Unlock an existing vault from disk. Returns unlocked Vault + decrypted Index.
Vault::unlock(manifest: &VaultManifest, index_enc: &[u8], password: &str)
  -> Result<(Vault, Index), CoreError>

// Lock the vault (consumes it, drops and zeroizes the key).
vault.lock()

// --- Entry operations ---

// Encrypt and add/update an entry. Returns new entry blob + new index blob.
// Both blobs must be saved to disk.
vault.put_entry(index: &mut Index, entry: Entry)
  -> Result<(Vec<u8>, Vec<u8>), CoreError>

// Decrypt a single entry blob. entry_id must be the entry's own UUID — it's
// the AAD, so passing the wrong id (e.g. from a renamed/swapped file) fails closed.
vault.decrypt_entry(entry_enc: &[u8], entry_id: &str)
  -> Result<Entry, CoreError>

// --- Search ---

// Rebuild search cache from index (fast, in-memory only).
SearchCache::rebuild_from_index(index: &Index) -> SearchCache

// Query returns matching items (title/username/url substring match, case-insensitive).
cache.query(term: &str) -> Vec<&SearchItem>

// Persist/restore the cache encrypted at rest (optional — rebuilding from
// the index is cheap enough that most shells won't need this).
cache.save_encrypted(key: &Key) -> Result<Vec<u8>, CoreError>
SearchCache::load_encrypted(key: &Key, ciphertext: &[u8], index_version: u64)
  -> Result<SearchCache, CoreError>

// --- Password tools ---
generate_password(length: usize, uppercase: bool, lowercase: bool, numbers: bool, symbols: bool)
  -> Result<String, CoreError>

check_strength(password: &str) -> u8  // 0=very weak 1=weak 2=ok 3=strong 4=very strong

generate_totp(secret_base32: &str, time_step: u64, current_unix_time: u64, digits: u32)
  -> Result<String, CoreError>
// FIXED: core now rejects time_step == 0 and digits outside 6-8 with CoreError::InvalidFormat.
// No shell-side clamping needed anymore.

// --- Sync ---
merge(local: &Index, remote: &Index) -> MergeResult
// MergeResult { to_upload_entries: Vec<String>, to_download_entries: Vec<String>, merged_index: Index }
// merge() does NOT save its result — the shell must encrypt merged_index and write it to disk.
// merge() still does not authenticate the remote index (accepted limitation of the no-server
// trust model — see QUIES_AUDIT_FINDINGS.md [MEDIUM]). A malicious remote can still force a
// stale/rollback entry to "win" via an inflated updated_at.

// --- OAuth PKCE + token handling (for cloud sync auth) ---
generate_pkce() -> Result<PkcePair, CoreError>
// PkcePair { code_verifier: String, code_challenge: String }
// FIXED: code_challenge is now SHA-256, matching the S256 build_auth_url() advertises.

generate_oauth_state() -> Result<String, CoreError>
// NEW: random CSRF state token. Generate one alongside the PKCE pair, persist it with the
// pending auth request, and verify it against the provider's redirect before exchanging the code.

build_auth_url(provider: OAuthProvider, client_id: &str, redirect_uri: &str, pkce: &PkcePair, state: &str) -> String
// OAuthProvider is GoogleDrive | Dropbox | OneDrive. `state` is now a required parameter —
// pass the value from generate_oauth_state().

build_token_exchange_request(token_url: &str, client_id: &str, code: &str, redirect_uri: &str, verifier: &str)
  -> HttpRequestSpec
// HttpRequestSpec { url, method, headers, body } — core builds the request, shell performs the
// actual HTTP call (core never does network I/O).

parse_token_response(bytes: &[u8], current_unix_time: i64) -> Result<OAuthTokens, CoreError>
// OAuthTokens { access_token, refresh_token: Option<String>, expires_at: Option<i64> }

encrypt_tokens(key: &Key, tokens: &OAuthTokens) -> Result<Vec<u8>, CoreError>
decrypt_tokens(key: &Key, ciphertext: &[u8]) -> Result<OAuthTokens, CoreError>

// --- Breach checking (k-anonymity, for HIBP) ---
// Core only hashes the password and splits the SHA-1 hash into k-anonymity prefix/suffix —
// it never sends anything over the network. The shell does the actual HIBP HTTP GET on the
// prefix and checks whether the suffix appears in the response.
get_breach_hash_parts(password: &str) -> Result<BreachHashParts, CoreError>
// BreachHashParts { prefix: String (5 hex chars), suffix: String (35 hex chars) }
```

### Core Data Structures

```rust
pub struct VaultManifest {
    pub version: u32,
    pub salt: [u8; 16],
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

pub struct IndexEntry {
    pub id: String,       // UUID v4
    pub title: String,
    pub username: String,
    pub url: String,
    pub updated_at: i64,  // unix timestamp seconds
    pub deleted: bool,
}

pub struct Index {
    pub version: u64,
    pub entries: Vec<IndexEntry>,
}

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
```

---

## Vault File Layout on Disk

The shell decides where to store files. Recommended layout:

```
~/.local/share/quies/                  (Linux)
~/Library/Application Support/Quies/   (Mac)
%APPDATA%\Quies\                       (Windows)

vault/
├── manifest.json              # VaultManifest serialized as JSON (not secret)
├── index.enc                  # encrypted Index blob
└── entries/
    ├── {uuid}.enc             # one encrypted Entry blob per entry
    └── {uuid}.enc
```

`manifest.json` example:
```json
{
  "version": 1,
  "salt": [163, 248, 12, ...],
  "memory_kib": 65536,
  "iterations": 3,
  "parallelism": 4
}
```

---

## Screens / Views (all platforms)

Implement exactly these screens. No more, no less for v1.

```
1. SETUP SCREEN        — shown if no vault exists
   - "Create new vault" button
   - Password input (+ confirm)
   - Vault storage location picker (local path)
   - Submit → Vault::create() → go to UNLOCK SUCCESS

2. UNLOCK SCREEN       — shown when vault exists but locked
   - Password input
   - Submit → Vault::unlock() → go to VAULT LIST
   - Error if wrong password: show "Wrong password" (never surface the raw CoreError message)

3. VAULT LIST SCREEN   — main screen when unlocked
   - Search bar at top → SearchCache::query()
   - List of entries (title + username)
   - "+ Add" button → go to EDIT ENTRY SCREEN
   - Tap entry → go to ENTRY DETAIL SCREEN
   - Lock button → wipe key, go to UNLOCK SCREEN

4. ENTRY DETAIL SCREEN — view a single entry
   - Show: title, username, password (hidden by default, tap to reveal), url, notes, TOTP if set
   - "Copy password" button → copy to clipboard, clear clipboard after 30 seconds
   - "Copy username" button
   - "Edit" button → go to EDIT ENTRY SCREEN
   - "Delete" button → mark entry.deleted = true, put_entry(), go back

5. EDIT ENTRY SCREEN   — create or edit
   - Fields: title, username, password, url, notes, totp_secret (optional)
   - Password generator button → generate_password(20, true, true, true, true)
   - Strength meter → check_strength()
   - Save → vault.put_entry() → save blobs to disk → go back

6. SETTINGS SCREEN     — minimal
   - Auto-lock timeout: 1min / 5min / 15min / 1hr / never
   - Change master password (re-encrypt: unlock with old → lock → create new key → re-encrypt all entries)
   - Export vault (copy vault folder path)
```

---

## Desktop App (Tauri) — build this shell first

### Prerequisites
```bash
# Install Rust (already done if core builds)
# Install Node.js 18+
cargo install tauri-cli
```

### Create project
```bash
cd <repo-root>
cargo tauri init --app-name quies --window-title "Quies" --dist-dir ../ui/dist --dev-url http://localhost:5173
# Creates src-tauri/
```

### Add core dependency to `src-tauri/Cargo.toml`
```toml
[dependencies]
quies-core = { path = "../../core" }
tauri = { version = "2", features = [] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
uuid = { version = "1", features = ["v4"] }
```

### App state pattern (`src-tauri/src/main.rs`)

```rust
use std::sync::Mutex;
use quies_core::{Vault, Index, SearchCache};

// This struct lives in memory only. Never serialized. Never saved to disk.
// The Vault's Key stays inside quies-core the whole time — this is the safe
// pattern the WASM/FFI bindings should eventually match (see Core Rule above).
pub struct AppState {
    vault: Option<Vault>,
    index: Option<Index>,
    vault_dir: Option<PathBuf>,
}

// Register as Tauri managed state:
tauri::Builder::default()
    .manage(Mutex::new(AppState { vault: None, index: None, vault_dir: None }))
    .invoke_handler(tauri::generate_handler![
        cmd_create_vault,
        cmd_unlock_vault,
        cmd_lock_vault,
        cmd_list_entries,
        cmd_get_entry,
        cmd_put_entry,
        cmd_delete_entry,
        cmd_search,
        cmd_generate_password,
        cmd_check_strength,
        cmd_generate_totp,
    ])
```

### Tauri commands pattern

```rust
#[tauri::command]
fn cmd_unlock_vault(
    state: tauri::State<Mutex<AppState>>,
    vault_dir: String,
    password: String,
) -> Result<serde_json::Value, String> {
    let vault_dir = PathBuf::from(vault_dir);

    // Read manifest
    let manifest_bytes = fs::read(vault_dir.join("manifest.json"))
        .map_err(|e| format!("cannot read manifest: {e}"))?;
    let manifest: VaultManifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("bad manifest: {e}"))?;

    // Read index blob
    let index_enc = fs::read(vault_dir.join("index.enc"))
        .map_err(|e| format!("cannot read index: {e}"))?;

    // Unlock
    let (vault, index) = Vault::unlock(&manifest, &index_enc, &password)
        .map_err(|_| "Wrong password".to_string())?;

    // Store in state — key lives here in RAM only, inside Vault, never serialized out
    let mut s = state.lock().unwrap();
    s.vault = Some(vault);
    s.index = Some(index.clone());
    s.vault_dir = Some(vault_dir);

    Ok(serde_json::to_value(&index).unwrap())
}

#[tauri::command]
fn cmd_lock_vault(state: tauri::State<Mutex<AppState>>) {
    let mut s = state.lock().unwrap();
    if let Some(vault) = s.vault.take() {
        vault.lock(); // drops key, zeroizes memory
    }
    s.index = None;
    s.vault_dir = None;
}
```

### Frontend (UI)
Use any web framework (React, Vue, Svelte — pick one). Call Tauri commands via:
```javascript
import { invoke } from '@tauri-apps/api/core'

const result = await invoke('cmd_unlock_vault', { vaultDir: path, password })
```

### Auto-lock timer (frontend)
```javascript
let lockTimer;

function resetTimer() {
  clearTimeout(lockTimer);
  lockTimer = setTimeout(() => invoke('cmd_lock_vault'), TIMEOUT_MS);
}

// Reset on any user interaction
document.addEventListener('mousemove', resetTimer);
document.addEventListener('keydown', resetTimer);
```

### Build for distribution
```bash
cargo tauri build
# Output:
# Mac:     src-tauri/target/release/bundle/dmg/quies.dmg
# Linux:   src-tauri/target/release/bundle/deb/quies.deb
# Windows: src-tauri/target/release/bundle/msi/quies.msi
```

---

## Browser Extension (Chromium first, then Firefox)

Not present in this repository snapshot — build from scratch against `core-wasm`. Unlock now returns
an opaque `u64` handle (`wasm_create_vault`/`wasm_unlock_vault`), not a key — hold the handle in the
service worker's memory for the session and call `wasm_lock_vault(handle)` on lock/timeout. There is
no key material to leak into `chrome.storage.local`/`.sync` anymore; just don't persist the handle
across a lock (a stale handle is simply invalid, not sensitive, but treat it as session-only regardless).

### Prerequisites
```bash
# Install wasm-pack to build core-wasm for the browser
cargo install wasm-pack
```

### Build the WASM package
```bash
cd core-wasm
wasm-pack build --target web --out-dir ../extension/wasm
```
This produces `quies_core_wasm.js` (JS glue) and `quies_core_wasm_bg.wasm`, both imported by the
extension's background service worker.

### Target directory structure
```
extension/
├── manifest.json          # Manifest V3
├── background.js          # Service worker: holds unlocked vault state, auto-lock timer
├── popup.html / .css / .js
├── wasm/                  # output of `wasm-pack build`, imported by background.js
│   ├── quies_core_wasm.js
│   └── quies_core_wasm_bg.wasm
└── adapters/
    ├── webdav.js
    ├── s3.js
    └── oauth.js
```

### manifest.json (MV3, minimal)
```json
{
  "manifest_version": 3,
  "name": "Quies",
  "version": "0.1.0",
  "background": { "service_worker": "background.js", "type": "module" },
  "action": { "default_popup": "popup.html" },
  "permissions": ["storage", "clipboardWrite"],
  "host_permissions": []
}
```
Add `host_permissions` entries only for the storage backends the user actually configures (WebDAV
host, S3 endpoint, or the relevant OAuth provider's token endpoint) — don't request broad host access.

### background.js — state pattern
```javascript
import init, {
  wasm_create_vault, wasm_unlock_vault,
  wasm_generate_password, wasm_check_strength, wasm_generate_totp,
  wasm_search_query, wasm_merge_indexes, wasm_get_breach_hash_parts, wasm_generate_pkce,
} from './wasm/quies_core_wasm.js';

await init();

// In-memory only. Cleared on lock, on service-worker suspend, and never written
// to chrome.storage. Service workers can be killed by the browser at any time —
// treat that the same as a lock event and require re-entering the password.
let state = { keyB64: null, indexJson: null, lockTimer: null };

const LOCK_TIMEOUT_MS = 15 * 60 * 1000; // 15 min, matches README's stated default

function resetLockTimer() {
  clearTimeout(state.lockTimer);
  state.lockTimer = setTimeout(lock, LOCK_TIMEOUT_MS);
}

function lock() {
  if (state.handle != null) wasm_lock_vault(state.handle);
  state.handle = null;
  state.indexJson = null;
  clearTimeout(state.lockTimer);
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === 'unlock') {
    const result = JSON.parse(wasm_unlock_vault(msg.manifestJson, msg.indexEncB64, msg.password));
    if (result.success) {
      state.handle = result.data.handle;
      state.indexJson = JSON.stringify(result.data.index);
      resetLockTimer();
    }
    sendResponse(result);
    return true;
  }
  if (msg.type === 'lock') { lock(); sendResponse({ success: true }); return true; }
  // ... additional handlers for search, put_entry (via encrypt_b64-equivalent calls),
  // generate_password, generate_totp, breach check, sync — same pattern: check
  // state.keyB64 is set, call the relevant wasm_* export, resetLockTimer() on activity.
});
```

### popup.js
Popup UI sends messages to the background service worker (`chrome.runtime.sendMessage`) rather than
calling WASM directly — the service worker is the single source of truth for unlocked state, since the
popup itself is torn down every time it closes.

### Auto-lock triggers (extension-specific, in addition to the idle timer above)
- Service worker suspension/restart → treat as locked, require re-unlock.
- Browser restart → treat as locked.
- No `chrome.idle` reliance as the *only* lock trigger — MV3 service workers already get suspended
  aggressively enough that the explicit timer above is the primary mechanism.

### Firefox port
Once the Chromium version works, add `webextension-polyfill` and swap `chrome.*` calls for the
polyfill's `browser.*` API; MV3 support and service-worker lifecycle differ slightly on Firefox, so
retest the lock/suspend behavior there rather than assuming parity.

### Storage adapters (`adapters/*.js`)
Each adapter implements the same three-function interface described in **Sync Implementation** below
and is called from `background.js`, never from `popup.js`, so that storage credentials and the sync
loop stay alongside the vault key rather than in the popup's short-lived context.

### HIBP breach checking (`background.js`, using `wasm_get_breach_hash_parts`)
```javascript
async function checkBreach(password) {
  const { prefix, suffix } = JSON.parse(wasm_get_breach_hash_parts(password)).data;
  const resp = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  const text = await resp.text();
  return text.split('\r\n').some(line => line.startsWith(suffix));
}
```
This is the only network call in the whole breach-check feature, and it only ever sends a 5-character
hash prefix — the full password and full hash never leave the device. Confirm this stays true if the
adapter is ever changed to a different breach-check provider.

---

## iOS App

### Prerequisites
```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
cargo install uniffi-bindgen
```

### Build steps (run from repo root)

```bash
# 1. Build static libraries
cd core-ffi
cargo build --release --target aarch64-apple-ios
cargo build --release --target aarch64-apple-ios-sim

# 2. Generate Swift bindings
uniffi-bindgen generate src/quies.udl \
  --language swift \
  --out-dir ../../ios/QuiesCore/Generated/

# 3. Create XCFramework
xcodebuild -create-xcframework \
  -library target/aarch64-apple-ios/release/libquies_core_ffi.a \
  -headers ../../ios/QuiesCore/Generated/ \
  -library target/aarch64-apple-ios-sim/release/libquies_core_ffi.a \
  -headers ../../ios/QuiesCore/Generated/ \
  -output ../../ios/QuiesCore.xcframework
```

### Xcode project structure
```
ios/
├── Quies.xcodeproj
├── QuiesCore.xcframework    ← drag into Xcode, mark "Embed & Sign"
└── Quies/
    ├── App.swift
    ├── State/
    │   └── VaultState.swift     ← holds key in memory
    └── Views/
        ├── UnlockView.swift
        ├── VaultListView.swift
        ├── EntryDetailView.swift
        ├── EditEntryView.swift
        └── SettingsView.swift
```

### VaultState.swift pattern

```swift
import SwiftUI
import QuiesCore

@MainActor
class VaultState: ObservableObject {
    @Published var isUnlocked = false
    @Published var entries: [IndexEntry] = []

    // Key held in memory only — never written to disk. Note: as of the current
    // core-ffi bindings this is a plain Swift String (see Core Rule above), which
    // Swift cannot guarantee is scrubbed on dealloc. Minimize how long it's retained.
    private var unlockResult: UnlockVaultResult?
    private var lockTimer: Task<Void, Never>?
    private var timeoutSeconds: Int = 300  // 5 min default

    func unlock(vaultDir: URL, password: String) throws {
        let manifestData = try Data(contentsOf: vaultDir.appendingPathComponent("manifest.json"))
        let manifestJson = String(data: manifestData, encoding: .utf8)!

        let indexEncData = try Data(contentsOf: vaultDir.appendingPathComponent("index.enc"))
        let indexEncB64 = indexEncData.base64EncodedString()

        let result = try unlockVault(
            manifestJson: manifestJson,
            indexEncB64: indexEncB64,
            password: password
        )

        self.unlockResult = result
        let index = try JSONDecoder().decode(QuiesIndex.self, from: result.indexJson.data(using: .utf8)!)
        self.entries = index.entries.filter { !$0.deleted }
        self.isUnlocked = true

        resetLockTimer()
    }

    func lock() {
        unlockResult = nil
        entries = []
        isUnlocked = false
        lockTimer?.cancel()
    }

    func resetLockTimer() {
        lockTimer?.cancel()
        lockTimer = Task {
            try? await Task.sleep(nanoseconds: UInt64(timeoutSeconds) * 1_000_000_000)
            lock()
        }
    }
}
```

### Auto-lock on background (App.swift)
```swift
@Environment(\.scenePhase) private var scenePhase

.onChange(of: scenePhase) { phase in
    if phase == .background {
        vaultState.lock()
    }
}
```

---

## Android App

### Prerequisites
```bash
rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
cargo install uniffi-bindgen

# Install Android NDK via Android Studio SDK Manager
# NDK version: 25+
```

### Configure NDK linkers (`~/.cargo/config.toml`)
```toml
[target.aarch64-linux-android]
ar = "${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
linker = "${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android21-clang"

[target.armv7-linux-androideabi]
ar = "${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar"
linker = "${NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/armv7a-linux-androideabi21-clang"
```

Replace `${NDK}` with your actual NDK path (e.g. `~/Android/Sdk/ndk/25.2.9519653`).

### Build steps

```bash
# 1. Build .so files
cd core-ffi
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi

# 2. Copy to Android project
mkdir -p ../../android/app/src/main/jniLibs/arm64-v8a
mkdir -p ../../android/app/src/main/jniLibs/armeabi-v7a

cp target/aarch64-linux-android/release/libquies_core_ffi.so \
   ../../android/app/src/main/jniLibs/arm64-v8a/

cp target/armv7-linux-androideabi/release/libquies_core_ffi.so \
   ../../android/app/src/main/jniLibs/armeabi-v7a/

# 3. Generate Kotlin bindings
uniffi-bindgen generate src/quies.udl \
  --language kotlin \
  --out-dir ../../android/app/src/main/java/me/quies/core/
```

### Android project structure
```
android/
├── app/
│   └── src/main/
│       ├── java/me/quies/
│       │   ├── core/           ← generated Kotlin bindings (do not edit)
│       │   ├── state/
│       │   │   └── VaultViewModel.kt
│       │   └── ui/
│       │       ├── UnlockScreen.kt
│       │       ├── VaultListScreen.kt
│       │       ├── EntryDetailScreen.kt
│       │       ├── EditEntryScreen.kt
│       │       └── SettingsScreen.kt
│       └── jniLibs/            ← .so files go here
```

### VaultViewModel.kt pattern

```kotlin
import androidx.lifecycle.ViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import me.quies.core.*

class VaultViewModel : ViewModel() {
    val isUnlocked = MutableStateFlow(false)
    val entries = MutableStateFlow<List<IndexEntry>>(emptyList())

    // Key held in memory only — same caveat as iOS: as of the current core-ffi
    // bindings this is a plain Kotlin String (see Core Rule above).
    private var unlockResult: UnlockVaultResult? = null
    private var lockJob: Job? = null
    private val timeoutMs = 5 * 60 * 1000L

    fun unlock(vaultDir: File, password: String): Result<Unit> = runCatching {
        val manifestJson = File(vaultDir, "manifest.json").readText()
        val indexEncB64 = android.util.Base64.encodeToString(
            File(vaultDir, "index.enc").readBytes(),
            android.util.Base64.NO_WRAP
        )
        val result = unlockVault(manifestJson, indexEncB64, password)
        unlockResult = result
        // parse index from result.indexJson
        isUnlocked.value = true
        resetLockTimer()
    }

    fun lock() {
        unlockResult = null
        entries.value = emptyList()
        isUnlocked.value = false
        lockJob?.cancel()
    }

    private fun resetLockTimer() {
        lockJob?.cancel()
        lockJob = viewModelScope.launch {
            delay(timeoutMs)
            lock()
        }
    }
}
```

### Auto-lock on background (`MainActivity.kt`)
```kotlin
override fun onStop() {
    super.onStop()
    vaultViewModel.lock()
}
```

---

## Sync Implementation (all platforms)

Sync is optional. Ship without it first. Add storage backends one at a time.

### Interface to implement (one per backend)

```
upload(path: String, data: ByteArray)
download(path: String) -> ByteArray
list(prefix: String) -> List<String>
```

### Sync algorithm (same on all platforms)

```
1. download("manifest.json") → remote_manifest
2. download("index.enc") → remote_index_enc
3. decrypt remote_index_enc with local key → remote_index
4. merged = core::merge(local_index, remote_index)
5. for id in merged.to_upload:
       data = read local entries/{id}.enc
       upload("entries/{id}.enc", data)
6. for id in merged.to_download:
       data = download("entries/{id}.enc")
       save locally to entries/{id}.enc
7. encrypt merged.merged_index → new_index_enc
8. save new_index_enc locally and upload("index.enc", new_index_enc)
9. upload("manifest.json", local_manifest_json)
```

Remember `merge()` has no way to authenticate the remote index (AUDIT.md §8) — anyone who can write to
the configured storage backend can influence which entries win a conflict. That's an accepted trade-off
of the bring-your-own-storage model, but make sure the settings UI communicates it (e.g. "only sync to
storage you trust and control") rather than implying it's authenticated end-to-end.

### WebDAV (simplest backend)
- Use HTTP PROPFIND / PUT / GET
- Auth: Basic auth (username + password) or app password
- Works with Nextcloud, ownCloud, any WebDAV server

### S3-compatible
- PUT / GET / LIST operations
- Auth: access key + secret key
- Works with AWS S3, Cloudflare R2, Backblaze B2, MinIO

### OAuth (Google Drive / Dropbox / OneDrive)
- Use `generate_pkce()` from core for PKCE — see the caveat under **Core API** above (SHA-1 vs S256)
  before shipping this to production.
- Shell opens browser for OAuth consent, generating and verifying its own `state` param (core doesn't
  supply one yet).
- Exchange code for tokens using `build_token_exchange_request()` from core, then `parse_token_response()`
  on the HTTP response body.
- Store tokens encrypted with vault key using `encrypt_tokens()` from core.
- Refresh tokens using `OAuthTokens.refresh_token` through the same exchange/parse pattern.

---

## What NOT to Do

- Do NOT add any network calls inside `quies-core`
- Do NOT store the vault key in any file, database, or persistent storage
- Do NOT use `println!` or any logger to print passwords, keys, or decrypted entries
- Do NOT implement features not listed in the Screens section for v1
- Do NOT modify `core/`, `core-wasm/`, or `core-ffi/` unless fixing a compilation error or addressing
  a finding from `QUIES_AUDIT_FINDINGS.md`
- Do NOT add a separate "account" system — Quies has no server, no accounts
- Do NOT use Electron for desktop — use Tauri only
- Do NOT copy passwords to clipboard without clearing after 30 seconds
- Do NOT try to reintroduce a raw exported key (`key_b64`) to "simplify" a shell integration —
  the whole point of the handle-based API is that no host language ever holds key material

---

## Pitfalls to Watch

| Pitfall | Fix |
|---|---|
| `Vault::unlock` returns `DecryptionFailed` for wrong password | Show "Wrong password", do not leak which field is wrong |
| `put_entry` returns two blobs — both must be saved | Save `entry_enc` to `entries/{id}.enc` AND `index_enc` to `index.enc` |
| `merge()` returns a merged index but does NOT save it | Shell must encrypt and save the result |
| `Entry.deleted = true` is soft delete | Filter `deleted == false` in all list views |
| TOTP counter = `unix_time / time_step` | Use system clock in UTC seconds, not milliseconds. `time_step = 0` and `digits` outside 6-8 are now rejected by core, not a panic risk anymore |
| Clipboard clear on Android | Use `ClipboardManager` with a 30-second handler |
| Vault unlock is slow (~0.5s) | Run in background thread, show loading indicator. The WASM/FFI bindings now derive the key exactly once per unlock (fixed) |
| Vault handle (`u64`) from `core-wasm`/`core-ffi` | Session-scoped only — call `lock_vault`/`wasm_lock_vault(handle)` on lock/timeout; do not persist it across restarts |
