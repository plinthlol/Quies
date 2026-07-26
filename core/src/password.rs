use hmac::{Hmac, Mac};
use sha1::{Digest, Sha1};
use serde::{Deserialize, Serialize};
use crate::errors::CoreError;

/// Inclusive bounds on generated password length. 256 is already far beyond any
/// practical use and caps worst-case allocation/entropy-draw work per call.
pub const MIN_PASSWORD_LENGTH: usize = 4;
pub const MAX_PASSWORD_LENGTH: usize = 256;

pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, CoreError> {
    if !(MIN_PASSWORD_LENGTH..=MAX_PASSWORD_LENGTH).contains(&length) {
        return Err(CoreError::InvalidFormat(format!(
            "length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}"
        )));
    }

    let mut charset = Vec::new();
    if uppercase {
        charset.extend_from_slice(b"ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if lowercase {
        charset.extend_from_slice(b"abcdefghijklmnopqrstuvwxyz");
    }
    if numbers {
        charset.extend_from_slice(b"0123456789");
    }
    if symbols {
        charset.extend_from_slice(b"!@#$%^&*()_+-=[]{}|;:,.<>?");
    }

    if charset.is_empty() {
        return Err(CoreError::InvalidFormat("at least one character set must be enabled".into()));
    }

    // Rejection sampling: discard any byte in the "extra" partial range so every
    // remaining byte maps to charset indices with exactly uniform probability,
    // instead of `byte % charset.len()`, which is slightly biased whenever
    // charset.len() doesn't evenly divide 256.
    let limit = 256 - (256 % charset.len());
    let mut result = Vec::with_capacity(length);
    let mut chunk = [0u8; 64];

    while result.len() < length {
        getrandom::getrandom(&mut chunk)
            .map_err(|_| CoreError::InvalidFormat("failed to generate random bytes".into()))?;
        for &byte in chunk.iter() {
            if result.len() == length {
                break;
            }
            let byte = byte as usize;
            if byte < limit {
                result.push(charset[byte % charset.len()]);
            }
        }
    }

    String::from_utf8(result)
        .map_err(|e| CoreError::InvalidFormat(format!("utf8 conversion error: {e}")))
}

pub fn check_strength(password: &str) -> u8 {
    if password.is_empty() {
        return 0;
    }
    let mut pool_size: f64 = 0.0;
    if password.chars().any(|c| c.is_ascii_lowercase()) {
        pool_size += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_uppercase()) {
        pool_size += 26.0;
    }
    if password.chars().any(|c| c.is_ascii_digit()) {
        pool_size += 10.0;
    }
    if password.chars().any(|c| c.is_ascii_punctuation()) {
        pool_size += 32.0;
    }
    if pool_size == 0.0 {
        pool_size = 128.0;
    }

    let entropy = (password.len() as f64) * pool_size.log2();

    if entropy < 28.0 {
        0
    } else if entropy < 36.0 {
        1
    } else if entropy < 60.0 {
        2
    } else if entropy < 80.0 {
        3
    } else {
        4
    }
}

fn decode_base32(input: &str) -> Result<Vec<u8>, CoreError> {
    let clean: String = input.chars().filter(|c| !c.is_whitespace() && *c != '=').collect();
    let mut buffer = 0u64;
    let mut bits = 0;
    let mut out = Vec::new();

    for c in clean.to_uppercase().chars() {
        let val = match c {
            'A'..='Z' => (c as u8 - b'A') as u64,
            '2'..='7' => (c as u8 - b'2' + 26) as u64,
            _ => return Err(CoreError::InvalidFormat(format!("invalid base32 char: {c}"))),
        };
        buffer = (buffer << 5) | val;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Ok(out)
}

/// RFC 6238 doesn't mandate a range, but every real-world authenticator app
/// uses 6-8 digits; anything outside that is either a caller bug or an attempt
/// to force a huge `10u32.pow(digits)` / output-string allocation.
pub const MIN_TOTP_DIGITS: u32 = 6;
pub const MAX_TOTP_DIGITS: u32 = 8;

pub fn generate_totp(
    secret_base32: &str,
    time_step_seconds: u64,
    current_unix_time: u64,
    digits: u32,
) -> Result<String, CoreError> {
    if time_step_seconds == 0 {
        return Err(CoreError::InvalidFormat("time_step_seconds must be nonzero".into()));
    }
    if !(MIN_TOTP_DIGITS..=MAX_TOTP_DIGITS).contains(&digits) {
        return Err(CoreError::InvalidFormat(format!(
            "digits must be between {MIN_TOTP_DIGITS} and {MAX_TOTP_DIGITS}"
        )));
    }

    let secret = decode_base32(secret_base32)?;
    let counter = current_unix_time / time_step_seconds;

    type HmacSha1 = Hmac<Sha1>;
    let mut mac = HmacSha1::new_from_slice(&secret)
        .map_err(|_| CoreError::InvalidFormat("invalid HMAC key size".into()))?;

    mac.update(&counter.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let code = (((result[offset] & 0x7f) as u32) << 24)
        | ((result[offset + 1] as u32) << 16)
        | ((result[offset + 2] as u32) << 8)
        | (result[offset + 3] as u32);

    let modulo = 10u32.pow(digits);
    let otp = code % modulo;

    Ok(format!("{:0width$}", otp, width = digits as usize))
}

/// The two halves of a k-anonymity breach-check lookup (e.g. against the
/// Have I Been Pwned range API): `prefix` is the first 5 hex chars of the
/// password's SHA-1 hash, `suffix` is the rest. Core only hashes locally —
/// it never performs network I/O. The shell does the actual HTTP request
/// against `prefix` and checks whether `suffix` appears in the response.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BreachHashParts {
    pub prefix: String,
    pub suffix: String,
}

pub fn get_breach_hash_parts(password: &str) -> Result<BreachHashParts, CoreError> {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let hash = format!("{:X}", hasher.finalize());
    // A SHA-1 digest formatted via {:X} is always exactly 40 hex chars, so
    // this can't actually happen — kept as a defensive guard in case the
    // digest formatting ever changes upstream.
    if hash.len() < 5 {
        return Err(CoreError::InvalidFormat("sha1 hash too short".into()));
    }
    let (prefix, suffix) = hash.split_at(5);
    Ok(BreachHashParts { prefix: prefix.to_string(), suffix: suffix.to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_password() {
        let pass = generate_password(16, true, true, true, true).unwrap();
        assert_eq!(pass.len(), 16);
    }

    #[test]
    fn test_check_strength() {
        assert_eq!(check_strength("12345"), 0);
        assert!(check_strength("StrongPass#2026!") >= 3);
    }

    #[test]
    fn test_rfc6238_totp() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        let code = generate_totp(secret, 30, 59, 6).unwrap();
        assert_eq!(code, "287082");
    }

    #[test]
    fn generate_password_rejects_out_of_range_length() {
        assert!(generate_password(0, true, true, true, true).is_err());
        assert!(generate_password(3, true, true, true, true).is_err());
        assert!(generate_password(257, true, true, true, true).is_err());
        assert!(generate_password(usize::MAX, true, true, true, true).is_err());
    }

    #[test]
    fn generate_totp_rejects_zero_time_step() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(generate_totp(secret, 0, 1_000_000, 6).is_err());
    }

    #[test]
    fn generate_totp_rejects_out_of_range_digits() {
        let secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert!(generate_totp(secret, 30, 59, 0).is_err());
        assert!(generate_totp(secret, 30, 59, 5).is_err());
        assert!(generate_totp(secret, 30, 59, 9).is_err());
        assert!(generate_totp(secret, 30, 59, u32::MAX).is_err());
    }

    #[test]
    fn breach_hash_parts_known_vector() {
        // SHA1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        // (verified directly: python3 -c "import hashlib;
        // print(hashlib.sha1(b'password').hexdigest().upper())")
        let parts = get_breach_hash_parts("password").unwrap();
        assert_eq!(parts.prefix, "5BAA6");
        assert_eq!(parts.suffix, "1E4C9B93F3F0682250B6CF8331B7EE68FD8");
        assert_eq!(format!("{}{}", parts.prefix, parts.suffix).len(), 40);
    }
}
