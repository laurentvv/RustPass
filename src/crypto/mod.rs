//! Cryptographic primitives for KDBX 3.1 & 4.0: key files, composite key derivation,
//! Argon2d/Argon2id & AES-KDF, ChaCha20 & AES-256-CBC payload ciphers, Salsa20/ChaCha20 inner
//! stream protection, and HMAC-SHA-256 / SHA-256 block streams.

pub mod cipher;
pub mod hmac_stream;
pub mod kdf;
pub mod keyfile;

use crate::error::{Result, RustPassError};

/// Fills `dest` with cryptographically secure random bytes from the OS CSPRNG.
pub fn random_bytes(dest: &mut [u8]) -> Result<()> {
    getrandom::fill(dest).map_err(|e| RustPassError::Crypto(format!("OS CSPRNG error: {e}")))
}

/// Generates a fixed-size array of cryptographically secure random bytes.
pub fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut buf = [0u8; N];
    random_bytes(&mut buf)?;
    Ok(buf)
}
