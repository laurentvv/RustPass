//! KDBX 4.0 HMAC-SHA-256 Block Stream and KDBX 3.1 SHA-256 Hashed Block Stream framing.

use crate::error::{Result, RustPassError};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};

type HmacSha256 = Hmac<Sha256>;

/// Default block size (1 MiB) when writing KDBX block streams.
const DEFAULT_BLOCK_SIZE: usize = 1024 * 1024;

/// Computes the 64-byte per-block HMAC key in KDBX 4 (`SHA-512(block_index_u64_le || hmac_master_key)`).
#[must_use]
pub fn derive_block_hmac_key(block_index: u64, hmac_master_key: &[u8; 64]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(block_index.to_le_bytes());
    hasher.update(hmac_master_key);
    let digest = hasher.finalize();
    let mut key = [0u8; 64];
    key.copy_from_slice(&digest);
    key
}

/// Computes the KDBX 4 Header HMAC-SHA-256 (`block_index = u64::MAX`).
pub fn compute_header_hmac(header_bytes: &[u8], hmac_master_key: &[u8; 64]) -> Result<[u8; 32]> {
    let block_key = derive_block_hmac_key(u64::MAX, hmac_master_key);
    let mut mac = HmacSha256::new_from_slice(&block_key)
        .map_err(|e| RustPassError::Crypto(format!("HMAC init error: {e}")))?;
    mac.update(header_bytes);
    let bytes = mac.finalize().into_bytes();
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Verifies the KDBX 4 Header HMAC-SHA-256 in constant time.
pub fn verify_header_hmac(
    header_bytes: &[u8],
    hmac_master_key: &[u8; 64],
    expected_hmac: &[u8; 32],
) -> Result<()> {
    let block_key = derive_block_hmac_key(u64::MAX, hmac_master_key);
    let mut mac = HmacSha256::new_from_slice(&block_key)
        .map_err(|e| RustPassError::Crypto(format!("HMAC init error: {e}")))?;
    mac.update(header_bytes);
    mac.verify_slice(expected_hmac)
        .map_err(|_| RustPassError::InvalidCredentials)
}

/// Reads and authenticates a KDBX 4 HMAC-SHA-256 Block Stream into contiguous ciphertext bytes.
pub fn read_hmac_block_stream(stream: &[u8], hmac_master_key: &[u8; 64]) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut block_index = 0u64;
    let mut out = Vec::new();

    loop {
        if offset + 36 > stream.len() {
            return Err(RustPassError::CorruptedFormat(
                "Unexpected EOF in KDBX 4 HMAC block stream".to_string(),
            ));
        }
        let block_hmac = &stream[offset..offset + 32];
        let block_size = u32::from_le_bytes(
            stream[offset + 32..offset + 36]
                .try_into()
                .map_err(|_| RustPassError::CorruptedFormat("Block size slice".to_string()))?,
        ) as usize;
        offset += 36;

        if offset + block_size > stream.len() {
            return Err(RustPassError::CorruptedFormat(
                "Truncated payload block in KDBX 4 HMAC stream".to_string(),
            ));
        }
        let block_data = &stream[offset..offset + block_size];
        offset += block_size;

        let block_key = derive_block_hmac_key(block_index, hmac_master_key);
        let mut mac = HmacSha256::new_from_slice(&block_key)
            .map_err(|e| RustPassError::Crypto(format!("HMAC init error: {e}")))?;
        mac.update(&block_index.to_le_bytes());
        mac.update(&(block_size as u32).to_le_bytes());
        mac.update(block_data);
        mac.verify_slice(block_hmac).map_err(|_| {
            RustPassError::IntegrityMismatch(format!(
                "HMAC verification failed on KDBX 4 block #{block_index}"
            ))
        })?;

        if block_size == 0 {
            break;
        }
        out.extend_from_slice(block_data);
        block_index += 1;
    }

    Ok(out)
}

/// Encodes `ciphertext` into a KDBX 4 HMAC-SHA-256 Block Stream (including the terminal 0-length block).
pub fn write_hmac_block_stream(ciphertext: &[u8], hmac_master_key: &[u8; 64]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(ciphertext.len() + 128);
    let mut block_index = 0u64;

    for chunk in ciphertext.chunks(DEFAULT_BLOCK_SIZE) {
        let block_key = derive_block_hmac_key(block_index, hmac_master_key);
        let mut mac = HmacSha256::new_from_slice(&block_key)
            .map_err(|e| RustPassError::Crypto(format!("HMAC init error: {e}")))?;
        let size_u32 = chunk.len() as u32;
        mac.update(&block_index.to_le_bytes());
        mac.update(&size_u32.to_le_bytes());
        mac.update(chunk);
        let tag = mac.finalize().into_bytes();

        out.extend_from_slice(&tag);
        out.extend_from_slice(&size_u32.to_le_bytes());
        out.extend_from_slice(chunk);
        block_index += 1;
    }

    // Terminal EOF block (size = 0)
    let eof_key = derive_block_hmac_key(block_index, hmac_master_key);
    let mut eof_mac = HmacSha256::new_from_slice(&eof_key)
        .map_err(|e| RustPassError::Crypto(format!("HMAC init error: {e}")))?;
    eof_mac.update(&block_index.to_le_bytes());
    eof_mac.update(&0u32.to_le_bytes());
    let eof_tag = eof_mac.finalize().into_bytes();
    out.extend_from_slice(&eof_tag);
    out.extend_from_slice(&0u32.to_le_bytes());

    Ok(out)
}

/// Reads and verifies a KDBX 3.1 Hashed Block Stream (`index: u32, sha256: [u8; 32], size: u32, data`).
pub fn read_hashed_block_stream_v3(stream: &[u8]) -> Result<Vec<u8>> {
    let mut offset = 0usize;
    let mut expected_index = 0u32;
    let mut out = Vec::new();

    loop {
        if offset + 40 > stream.len() {
            return Err(RustPassError::CorruptedFormat(
                "Unexpected EOF in KDBX 3.1 hashed block stream".to_string(),
            ));
        }
        let idx = u32::from_le_bytes(stream[offset..offset + 4].try_into().unwrap_or_default());
        let expected_hash = &stream[offset + 4..offset + 36];
        let block_size = u32::from_le_bytes(
            stream[offset + 36..offset + 40]
                .try_into()
                .unwrap_or_default(),
        ) as usize;
        offset += 40;

        if idx != expected_index {
            return Err(RustPassError::IntegrityMismatch(format!(
                "Out-of-sequence KDBX 3.1 block index (expected {expected_index}, got {idx})"
            )));
        }

        if block_size == 0 {
            if expected_hash != [0u8; 32] {
                return Err(RustPassError::IntegrityMismatch(
                    "Non-zero hash on terminal KDBX 3.1 block".to_string(),
                ));
            }
            break;
        }

        if offset + block_size > stream.len() {
            return Err(RustPassError::CorruptedFormat(
                "Truncated payload block in KDBX 3.1 hashed stream".to_string(),
            ));
        }
        let block_data = &stream[offset..offset + block_size];
        offset += block_size;

        let actual_hash = Sha256::digest(block_data);
        if actual_hash.as_slice() != expected_hash {
            return Err(RustPassError::IntegrityMismatch(format!(
                "SHA-256 mismatch on KDBX 3.1 block #{idx}"
            )));
        }
        out.extend_from_slice(block_data);
        expected_index += 1;
    }

    Ok(out)
}

/// Encodes `payload` into a KDBX 3.1 Hashed Block Stream.
#[must_use]
pub fn write_hashed_block_stream_v3(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 128);
    let mut idx = 0u32;

    for chunk in payload.chunks(DEFAULT_BLOCK_SIZE) {
        let hash = Sha256::digest(chunk);
        out.extend_from_slice(&idx.to_le_bytes());
        out.extend_from_slice(&hash);
        out.extend_from_slice(&(chunk.len() as u32).to_le_bytes());
        out.extend_from_slice(chunk);
        idx += 1;
    }

    // Terminal EOF block
    out.extend_from_slice(&idx.to_le_bytes());
    out.extend_from_slice(&[0u8; 32]);
    out.extend_from_slice(&0u32.to_le_bytes());
    out
}
