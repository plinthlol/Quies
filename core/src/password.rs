use hmac::{Hmac, Mac};
use sha1::Sha1;
use crate::errors::CoreError;

pub fn generate_password(
    length: usize,
    uppercase: bool,
    lowercase: bool,
    numbers: bool,
    symbols: bool,
) -> Result<String, CoreError> {
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

    let mut result = Vec::with_capacity(length);
    let mut rand_bytes = vec![0u8; length];
    getrandom::getrandom(&mut rand_bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random bytes".into()))?;

    for byte in rand_bytes {
        let idx = (byte as usize) % charset.len();
        result.push(charset[idx]);
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

pub fn generate_totp(
    secret_base32: &str,
    time_step_seconds: u64,
    current_unix_time: u64,
    digits: u32,
) -> Result<String, CoreError> {
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
}
