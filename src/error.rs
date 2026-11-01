//! Strongly-typed error definitions and path-safety guards for `RustPass`.

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Canonical result alias for `RustPass` library operations.
pub type Result<T> = std::result::Result<T, RustPassError>;

/// Domain and cryptographic errors produced by `RustPass`.
#[derive(Debug, Error)]
pub enum RustPassError {
    /// Underlying file-system I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File does not start with the KDBX magic bytes (`0x9AA2D903`, `0xB54BFB67`).
    #[error("Invalid KDBX file signature (expected 0x9AA2D903 0xB54BFB67)")]
    InvalidSignature,

    /// Unsupported KDBX format version.
    #[error("Unsupported KDBX version {major}.{minor} (supported: 3.1 and 4.x)")]
    UnsupportedVersion {
        /// Major format version.
        major: u16,
        /// Minor format version.
        minor: u16,
    },

    /// Wrong master password, wrong key file, or tampered header HMAC.
    #[error("Invalid master credentials or corrupted database header")]
    InvalidCredentials,

    /// Cryptographic integrity verification failed (SHA-256 or HMAC-SHA-256 mismatch).
    #[error("Integrity check failed: {0}")]
    IntegrityMismatch(String),

    /// Malformed binary header, VariantDictionary, or block stream.
    #[error("Corrupted KDBX binary structure: {0}")]
    CorruptedFormat(String),

    /// XML parsing or serialization failure.
    #[error("KDBX XML error: {0}")]
    Xml(String),

    /// Cryptographic primitive or KDF parameter error.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Requested group path does not exist in the vault.
    #[error("Group not found: {0}")]
    GroupNotFound(String),

    /// Requested entry path or UUID does not exist in the vault.
    #[error("Entry not found: {0}")]
    EntryNotFound(String),

    /// Invalid or missing TOTP configuration on entry.
    #[error("TOTP error: {0}")]
    Totp(String),

    /// Invalid CLI or user input parameter.
    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    /// Explicit error for hardware features outside clean-room scope (e.g. YubiKey USB HID).
    #[error("Unsupported feature: {0}")]
    UnsupportedFeature(String),

    /// Zip-Slip / Path Traversal defense triggered during attachment or export writing.
    #[error("SecurityError: {0}")]
    SecurityError(String),

    /// OS clipboard could not be read or written (e.g. locked by another process).
    #[error("Clipboard error: {0}")]
    Clipboard(String),

    /// Wraps an error with the operation context (usually the file path) that failed,
    /// so messages name the culprit instead of a bare OS error.
    #[error("{context}: {source}")]
    WithContext {
        /// What operation / which path failed.
        context: String,
        /// The underlying error.
        #[source]
        source: Box<RustPassError>,
    },
}

impl RustPassError {
    /// Attaches `context` (e.g. `opening <path>`) to this error for better messages.
    #[must_use]
    pub fn with_context(self, context: impl Into<String>) -> Self {
        Self::WithContext {
            context: context.into(),
            source: Box::new(self),
        }
    }
}

/// Validates that `entry_name` resolves strictly inside `dest_dir` with no path traversal (`..`,
/// absolute root, drive prefix, or NUL bytes).
pub fn assert_safe_output_path(dest_dir: &Path, entry_name: &str) -> Result<PathBuf> {
    if entry_name.is_empty() || entry_name.contains('\0') {
        return Err(RustPassError::SecurityError(
            "Path traversal attempt detected in output file name".to_string(),
        ));
    }

    let rel = Path::new(entry_name);
    for comp in rel.components() {
        match comp {
            Component::Normal(_) | Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(RustPassError::SecurityError(
                    "Path traversal attempt detected in output file name".to_string(),
                ));
            }
        }
    }

    let base = if dest_dir.exists() {
        dest_dir.canonicalize()?
    } else {
        std::env::current_dir()?.join(dest_dir)
    };
    let joined = base.join(rel);
    if !joined.starts_with(&base) {
        return Err(RustPassError::SecurityError(
            "Path traversal attempt detected in output file name".to_string(),
        ));
    }
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_output_path_rejects_parent_traversal() {
        let dir = std::env::temp_dir();
        let res = assert_safe_output_path(&dir, "../../evil.dll");
        assert!(matches!(res, Err(RustPassError::SecurityError(_))));
    }

    #[test]
    fn safe_output_path_accepts_clean_filename() {
        let dir = std::env::temp_dir();
        let res = assert_safe_output_path(&dir, "document.pdf");
        assert!(res.is_ok());
    }
}
