use serde::{Deserialize, Serialize};
use crate::crypto::{decrypt, encrypt, Key};
use crate::errors::CoreError;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum OAuthProvider {
    GoogleDrive,
    Dropbox,
    OneDrive,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct OAuthTokens {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_at: Option<i64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct PkcePair {
    pub code_verifier: String,
    pub code_challenge: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpRequestSpec {
    pub url: String,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

pub fn generate_pkce() -> Result<PkcePair, CoreError> {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes)
        .map_err(|_| CoreError::InvalidFormat("failed to generate random PKCE bytes".into()))?;

    let verifier = base64_url_encode(&bytes);
    use sha1::Digest;
    let mut hasher = sha1::Sha1::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64_url_encode(&hash);

    Ok(PkcePair {
        code_verifier: verifier,
        code_challenge: challenge,
    })
}

fn base64_url_encode(input: &[u8]) -> String {
    let mut out = String::new();
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut buffer = 0u32;
    let mut bits = 0;

    for &b in input {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 6 {
            bits -= 6;
            let idx = ((buffer >> bits) & 0x3F) as usize;
            out.push(CHARS[idx] as char);
        }
    }
    if bits > 0 {
        let idx = ((buffer << (6 - bits)) & 0x3F) as usize;
        out.push(CHARS[idx] as char);
    }
    out
}

pub fn build_auth_url(
    provider: OAuthProvider,
    client_id: &str,
    redirect_uri: &str,
    pkce: &PkcePair,
) -> String {
    match provider {
        OAuthProvider::GoogleDrive => format!(
            "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id={}&redirect_uri={}&scope=https://www.googleapis.com/auth/drive.file&code_challenge={}&code_challenge_method=S256",
            client_id, redirect_uri, pkce.code_challenge
        ),
        OAuthProvider::Dropbox => format!(
            "https://www.dropbox.com/oauth2/authorize?response_type=code&client_id={}&redirect_uri={}&code_challenge={}&code_challenge_method=S256",
            client_id, redirect_uri, pkce.code_challenge
        ),
        OAuthProvider::OneDrive => format!(
            "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?response_type=code&client_id={}&redirect_uri={}&scope=files.readwrite%20offline_access&code_challenge={}&code_challenge_method=S256",
            client_id, redirect_uri, pkce.code_challenge
        ),
    }
}

pub fn build_token_exchange_request(
    token_url: &str,
    client_id: &str,
    code: &str,
    redirect_uri: &str,
    verifier: &str,
) -> HttpRequestSpec {
    let body_str = format!(
        "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}",
        client_id, code, redirect_uri, verifier
    );
    HttpRequestSpec {
        url: token_url.to_string(),
        method: "POST".to_string(),
        headers: vec![("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string())],
        body: body_str.into_bytes(),
    }
}

pub fn parse_token_response(bytes: &[u8], current_unix_time: i64) -> Result<OAuthTokens, CoreError> {
    #[derive(Deserialize)]
    struct TokenResponse {
        access_token: String,
        refresh_token: Option<String>,
        expires_in: Option<i64>,
    }

    let parsed: TokenResponse = serde_json::from_slice(bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("oauth response error: {e}")))?;

    let expires_at = parsed.expires_in.map(|secs| current_unix_time + secs);

    Ok(OAuthTokens {
        access_token: parsed.access_token,
        refresh_token: parsed.refresh_token,
        expires_at,
    })
}

pub fn encrypt_tokens(key: &Key, tokens: &OAuthTokens) -> Result<Vec<u8>, CoreError> {
    let json = serde_json::to_vec(tokens)
        .map_err(|e| CoreError::InvalidFormat(format!("failed to serialize tokens: {e}")))?;
    encrypt(key, &json, b"oauth_tokens")
}

pub fn decrypt_tokens(key: &Key, ciphertext: &[u8]) -> Result<OAuthTokens, CoreError> {
    let bytes = decrypt(key, ciphertext, b"oauth_tokens")?;
    serde_json::from_slice(&bytes)
        .map_err(|e| CoreError::InvalidFormat(format!("failed to deserialize tokens: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{derive_key, KdfParams};

    #[test]
    fn test_pkce_and_auth_url() {
        let pkce = generate_pkce().unwrap();
        let url = build_auth_url(OAuthProvider::GoogleDrive, "client123", "http://localhost", &pkce);
        assert!(url.contains("client123"));
        assert!(url.contains(&pkce.code_challenge));
    }

    #[test]
    fn test_token_encryption_roundtrip() {
        let tokens = OAuthTokens {
            access_token: "access123".into(),
            refresh_token: Some("refresh123".into()),
            expires_at: Some(1000),
        };
        let params = KdfParams { memory_kib: 8192, iterations: 1, parallelism: 1 };
        let key = derive_key("pass", &[0u8; 16], params).unwrap();

        let enc = encrypt_tokens(&key, &tokens).unwrap();
        let dec = decrypt_tokens(&key, &enc).unwrap();
        assert_eq!(dec, tokens);
    }
}
