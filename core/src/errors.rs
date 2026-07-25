use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum CoreError {
    #[error("wrong password or corrupted vault")]
    DecryptionFailed,

    #[error("vault is locked")]
    VaultLocked,

    #[error("entry not found: {0}")]
    NotFound(String),

    #[error("vault version {0} is newer than this app supports")]
    UnsupportedVersion(u32),

    #[error("malformed data: {0}")]
    InvalidFormat(String),
}
