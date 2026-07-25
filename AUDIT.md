# Quies Security Audit Brief

You are auditing **quies-core** and its two binding crates, **core-wasm** and **core-ffi** — the
Rust cryptographic core of a local-first, zero-knowledge password manager. Your job is to find
real, exploitable security bugs, not style issues. Report every finding with severity, exact
location, and a proof-of-concept where possible.

---

## Codebase

| File | LOC | What it does |
|---|---|---|
| `core/src/crypto.rs` | 194 | Argon2id KDF, XChaCha20-Poly1305 encrypt/decrypt, salt/nonce generation |
| `core/src/vault.rs` | 181 | Vault format, `Entry`/`Index`/`VaultManifest` schema, entry encrypt/decrypt |
| `core/src/password.rs` | 152 | Password generator, strength checker, RFC 6238 TOTP (HMAC-SHA1) |
| `core/src/search.rs` | 108 | Local search cache, encrypted at rest |
| `core/src/sync.rs` | 107 | Index merge, last-write-wins conflict resolution |
| `core/src/oauth.rs` | 173 | PKCE pair generation, OAuth URL builder, token encryption |
| `core/src/errors.rs` | 19 | `CoreError` enum |
| `core-wasm/src/lib.rs` | 183 | WASM/JS boundary — JSON in/out over `wasm-bindgen` |
| `core-ffi/src/lib.rs` + `quies.udl` | 208 | UniFFI boundary — Swift (iOS) and Kotlin (Android) bindings |

Note the asymmetry: `core/` never leaks the `Key` type outside itself (it's private-field, zeroize-on-drop,
no `Clone`/`Copy`). `core-wasm` and `core-ffi` are a **separate trust boundary** — they re-derive and
**export the raw 32-byte key as a base64 string** to the host language. Audit them as if they were a
different, less-trusted codebase, because from a memory-safety standpoint they are.

---

## Threat Model

- Attacker has full read/write access to the encrypted vault files on disk (manifest, index, entry blobs).
- Attacker can send arbitrary input to every public function in `core`, `core-wasm`, and `core-ffi` —
  assume fuzzing-level hostility on every `&str`/`Vec<u8>`/numeric argument, not just "reasonable" input.
- Attacker can fully control the contents of any *remote* sync index (WebDAV/S3/OAuth storage is
  untrusted and unauthenticated from the core's point of view).
- Attacker cannot break ChaCha20-Poly1305 or Argon2id directly (assumed cryptographically sound).
- Master password is the only secret an attacker doesn't have. Vault file, manifest, and index are
  allowed to be fully public.
- No server, no network calls inside `core` itself. Keys are supposed to live only in memory while
  the vault is unlocked, per `BUILD.md`'s "Core Rule" — verify whether `core-wasm`/`core-ffi` actually
  honor that, since they hand the raw key to JS/Swift/Kotlin (see §1 below).

---

## 1. Key Material Crossing the FFI/WASM Boundary — Audit This First

`wasm_create_vault`, `wasm_unlock_vault` (`core-wasm/src/lib.rs`) and `create_vault`, `unlock_vault`
(`core-ffi/src/lib.rs`) each construct a `Vault`, immediately discard it as `_vault`, then call
`derive_key()` a second time and return `BASE64.encode(key.as_bytes())` to the caller. `encrypt_b64`/
`decrypt_b64` in `core-ffi` take a `key_b64: String` argument for every single call.

This means the 32-byte master key spends its life as a `String` in JavaScript/Swift/Kotlin, not as a
Rust `Key`. Check:

- Do JS strings, Swift `String`, and Kotlin `String` get reliably zeroized on scope exit? (They do not,
  in general — they're immutable, may be interned/copied by the runtime, and can be paged to disk by
  the OS.) Does this contradict the "key never touches disk / never leaves process memory" requirement
  stated for the shells?
- Why is the key derived *twice* per unlock (once inside `Vault::unlock`, discarded; once again via
  the explicit `derive_key()` call)? Confirm this doubles the Argon2id cost (the single most expensive
  operation in the whole unlock path) for no cryptographic benefit — is this purely a wasted ~0.5s, or
  does it also mean the password sits in memory for two derivation passes instead of one?
- Since the `Vault` struct (which holds the private, zeroize-on-drop `Key`) is never actually used
  for anything past construction in these bindings, is there any code path where `core-wasm`/`core-ffi`
  needs the raw key at all, versus keeping an opaque vault handle inside Rust and only exposing
  `encrypt`/`decrypt`/`decrypt_entry`-style calls that take ciphertext in and plaintext out?
- Trace every caller of `key_b64` on the JS/Swift/Kotlin side (if shell code exists) for logging,
  serialization into app state snapshots, or storage in `sessionStorage`/`localStorage`.

Treat this as an architecture-level finding, not a one-line fix — it affects every downstream shell
(extension, Tauri, iOS, Android) and should be weighed against the "Core does crypto, shell never
touches keys" principle the rest of the project is built on.

---

## 2. Nonce Handling (`crypto.rs`)

- `encrypt()` draws a fresh 24-byte nonce from `getrandom` per call. Confirm there is no code path
  (retry logic, caching, batch re-encryption) that could reuse a nonce for the same key.
- What happens if `getrandom::getrandom` fails? Confirm the `Err` path is actually propagated and
  the function cannot silently proceed with a zeroed or reused nonce buffer.
- XChaCha20's 192-bit nonce space makes accidental collision statistically negligible — confirm this
  is actually XChaCha (24-byte nonce, `XChaCha20Poly1305`) and not regular ChaCha20-Poly1305 (12-byte)
  anywhere in the codebase, since the two have very different reuse-safety margins.

## 3. AAD (Additional Authenticated Data) Usage

- `vault.rs`: index is encrypted with static AAD `b"index"`; entries use `entry.id` as AAD; OAuth
  tokens use `b"oauth_tokens"`; the search cache uses `b"search_cache"`. Since all of these are
  encrypted under the *same* vault key, can an attacker take a valid ciphertext blob from one context
  (e.g. an old entry's `.enc` file) and successfully decrypt it under a different AAD by re-tagging
  the file? Confirm AAD checking actually happens on the `decrypt()` call site, not just the encrypt side.
- Can an attacker swap `entries/{uuid-A}.enc` and `entries/{uuid-B}.enc` on disk (rename the files) and
  have the app decrypt A's ciphertext while believing it's B's entry? Trace exactly what value is
  passed as `entry_id` in `Vault::decrypt_entry` at each call site — is it read from the filename, or
  from trusted in-memory state?

## 4. Key Derivation (`crypto.rs::derive_key`)

- Argon2id params (`memory_kib=65536, iterations=3, parallelism=4`) — are these current OWASP/RFC 9106
  minimums for an interactive KDF? Compare against current guidance rather than assuming they're fine.
- Salt: 16 random bytes from `generate_salt()`, stored in the (public) manifest — confirm it's generated
  fresh per-vault and never derived from user input.
- Is the derived key or the password ever written to disk, logged, or included in a `Debug`/`Display`
  impl or error message anywhere in `core`, `core-wasm`, or `core-ffi`?

## 5. Key Type Hygiene (`crypto.rs::Key`)

- `Key` derives `ZeroizeOnDrop` but not `Clone`/`Copy` — confirm neither is implemented anywhere
  (including via a blanket impl pulled in by a dependency) and that no code path clones the wrapped
  `Box<[u8; 32]>` before it's zeroized.
- `encrypt_raw`/`decrypt_raw` (`crypto.rs`) construct a throwaway `Key(Box::new(*key_bytes))` from a
  caller-supplied `&[u8; 32]` on every call. That's the function `core-ffi::encrypt_b64`/`decrypt_b64`
  use per-operation, driven by the base64 key passed in from Swift/Kotlin (see §1) — confirm the
  original `[u8; 32]` the caller decoded from base64 is itself zeroized after use, not just the
  temporary `Key` wrapper.

## 6. Password Generator (`password.rs::generate_password`)

- `let idx = (byte as usize) % charset.len();` — charset sizes in this file are 26/52/62/94, none of
  which evenly divide 256. Quantify the actual bias this introduces per charset size (it's small but
  nonzero, and a password generator should be exactly uniform, not "close enough"). Is rejection
  sampling or a wider random draw + modulo-free reduction warranted here?

## 7. TOTP (`password.rs::generate_totp`, `decode_base32`)

- `let counter = current_unix_time / time_step_seconds;` — `time_step_seconds` is a caller-controlled
  `u64` with no validation. Confirm what happens when it's `0` (integer division by zero panics in Rust
  and is unrecoverable across the WASM/FFI boundary — is that a crash an attacker-controlled input can
  trigger from the shell layer?).
- `10u32.pow(digits)` — `digits` is caller-controlled with no upper bound checked before this call.
  Confirm the behavior for `digits >= 10` (`10^10` overflows `u32`): does this panic in a debug build,
  silently wrap in release, or is it actually unreachable because something upstream bounds `digits`?
- `decode_base32`: confirm invalid characters are rejected (they appear to be, via the `_ =>` match
  arm) and that no combination of input length/padding causes the `buffer`/`bits` bit-packing logic to
  read or write out of the intended range.
- Is `totp_secret` ever persisted anywhere other than inside the encrypted `Entry` blob (check the
  search cache and index — those intentionally exclude it, confirm that holds for every code path,
  not just the "happy path" struct definitions)?

## 8. Sync Merge (`sync.rs::merge`)

- Merge trusts `updated_at` (`i64`, attacker-suppliable if the remote storage backend is compromised
  or malicious per the threat model) with no authentication of the remote index's origin. Confirm an
  attacker who controls the remote copy can set `updated_at = i64::MAX` on any entry to force it to
  always "win" the merge and silently overwrite the user's local, legitimate data on next sync.
- Is there any per-entry integrity check (e.g. a MAC binding `updated_at` to the actual entry
  ciphertext) that would prevent an attacker from bumping the timestamp on an entry without also being
  able to produce a validly-encrypted payload for it? If not, is that an accepted limitation of the
  "no server" trust model, or a gap that should be documented explicitly in the threat model?

## 9. OAuth (`oauth.rs`)

- `generate_pkce()` builds `code_challenge` by SHA-**1**-hashing the verifier (`sha1::Sha1`), but
  `build_auth_url()` unconditionally sends `code_challenge_method=S256` to the provider. RFC 7636 S256
  is defined as SHA-**256**. Confirm this mismatch is real (it is, per the source), determine whether
  any of the three providers (Google, Dropbox, Microsoft) would actually accept a SHA-1 challenge under
  an `S256` label, and assess the impact if one does: PKCE is meant to bind the authorization code to
  the party that started the flow, and a weaker/mismatched hash undermines that guarantee.
- Is the `state` parameter implemented anywhere in `build_auth_url` or the token exchange? If not,
  what mitigates CSRF against the OAuth redirect callback?
- `code_verifier`: confirm the 32 random bytes feeding it come from `getrandom` (not a weaker source)
  and that the custom `base64_url_encode` helper (hand-rolled, not from the `base64` crate already used
  elsewhere in this same file) produces correct, unpadded base64url output for all input lengths —
  check the tail-bits handling in the `if bits > 0` branch specifically.
- Are OAuth tokens (`encrypt_tokens`/`decrypt_tokens`) encrypted with the same vault key as entries, and
  does the AAD (`b"oauth_tokens"`) meaningfully prevent a token blob from being replayed as a different
  ciphertext type (see §3)?

## 10. Error Handling

- `DecryptionFailed` is returned uniformly for wrong password, wrong AAD, tampered ciphertext, and
  truncated input — good, confirm no other branch anywhere leaks distinguishing information (timing,
  error variant, message content) about *why* a decrypt failed.
- `InvalidFormat(String)` wraps `format!("...{e}")` in many places, including raw `serde_json` and
  `argon2` error messages. Confirm none of these underlying error types ever include a fragment of the
  input plaintext, key material, or password in their `Display` output before it gets wrapped and
  potentially surfaced to a UI or log.

## 11. Integer Safety

- Beyond the TOTP issues in §7 (div-by-zero, `pow` overflow), check `sync.rs`'s `i64` `updated_at`
  comparisons and `local.version.max(remote.version) + 1` for overflow at the `i64`/`u64` boundary.
- Check every `usize` cast from a caller-controlled numeric argument (`length` in `generate_password`,
  `digits` in TOTP, array indexing in `decode_base32` and the TOTP truncation step) for panics on
  extreme inputs (`0`, `usize::MAX`, negative-then-cast values arriving from JS `number`/Kotlin `Int`).

## 12. Unsafe Code & Input Validation at the FFI Boundary

- Confirm there are no `unsafe` blocks anywhere in `core`, `core-wasm`, or `core-ffi` (there shouldn't
  be any).
- Every `core-ffi` function that takes a `String`/`Vec<u8>` from Swift/Kotlin and every `core-wasm`
  function that takes input from JS should validate structurally before handing it to `core` — confirm
  `key_from_b64` correctly rejects any base64 that doesn't decode to exactly 32 bytes (it appears to,
  via `try_into()`) and that this check can't be bypassed by any of the call sites.

---

## What NOT to Report

- Code style, formatting, naming conventions.
- Missing features (autofill, 2FA backup codes, hardware key support, etc.) — this is a v1 core audit.
- Performance issues that don't have a security implication (the double key-derivation in §1 is in
  scope *because* it affects how long secret material lives in memory, not because it's slow).
- Theoretical attacks that require breaking ChaCha20-Poly1305 or Argon2id as primitives.

---

## Output Format

For each finding:

```
## [SEVERITY] Title

**Location**: file.rs:line_number
**Description**: What the bug is.
**Impact**: What an attacker can do if they exploit it.
**Proof of Concept**: Code or steps to reproduce (if possible).
**Fix**: What should be changed.
```

Severity levels: `CRITICAL` / `HIGH` / `MEDIUM` / `LOW` / `INFO`

Order findings by severity, most severe first. If a finding spans multiple files (e.g. §1's key
export, which touches both `core-wasm` and `core-ffi`), file it once with both locations listed
rather than duplicating it per crate.
