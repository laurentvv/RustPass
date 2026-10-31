//! Binary KDBX 4 `VariantDictionary` v1.0 parser and encoder.

use crate::error::{Result, RustPassError};
use crate::model::{Argon2Variant, KdfConfig};
use std::collections::BTreeMap;

const VD_VERSION: u16 = 0x0100;
const VD_VERSION_MASK: u16 = 0xFF00;

const TYPE_END: u8 = 0x00;
const TYPE_UINT32: u8 = 0x04;
const TYPE_UINT64: u8 = 0x05;
const TYPE_BOOL: u8 = 0x08;
const TYPE_INT32: u8 = 0x0C;
const TYPE_INT64: u8 = 0x0D;
const TYPE_STRING: u8 = 0x18;
const TYPE_BYTEARRAY: u8 = 0x42;

/// Typed value inside a KDBX 4 `VariantDictionary`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValue {
    /// Unsigned 32-bit integer (`0x04`).
    UInt32(u32),
    /// Unsigned 64-bit integer (`0x05`).
    UInt64(u64),
    /// Boolean (`0x08`).
    Bool(bool),
    /// Signed 32-bit integer (`0x0C`).
    Int32(i32),
    /// Signed 64-bit integer (`0x0D`).
    Int64(i64),
    /// UTF-8 string (`0x18`).
    String(String),
    /// Raw byte buffer (`0x42`).
    ByteArray(Vec<u8>),
}

/// Ordered key-value map serialized in KDBX 4 outer headers (`KdfParameters`, `PublicCustomData`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VariantDictionary {
    /// Dictionary entries keyed by name.
    pub entries: BTreeMap<String, VariantValue>,
}

impl VariantDictionary {
    /// Decodes a binary `VariantDictionary` slice.
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 2 {
            return Err(RustPassError::CorruptedFormat(
                "VariantDictionary shorter than 2-byte version header".to_string(),
            ));
        }
        let version = u16::from_le_bytes([data[0], data[1]]);
        if (version & VD_VERSION_MASK) != VD_VERSION {
            return Err(RustPassError::CorruptedFormat(format!(
                "Unsupported VariantDictionary version: 0x{version:04x}"
            )));
        }

        let mut pos = 2usize;
        let mut entries = BTreeMap::new();

        while pos < data.len() {
            let value_type = data[pos];
            pos += 1;
            if value_type == TYPE_END {
                break;
            }
            if pos + 4 > data.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Truncated key length in VariantDictionary".to_string(),
                ));
            }
            let key_len = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default());
            pos += 4;
            if key_len < 0 || pos + (key_len as usize) > data.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Invalid key length in VariantDictionary".to_string(),
                ));
            }
            let key = std::str::from_utf8(&data[pos..pos + key_len as usize])
                .map_err(|e| RustPassError::CorruptedFormat(format!("VD key UTF-8 error: {e}")))?
                .to_string();
            pos += key_len as usize;

            if pos + 4 > data.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Truncated value length in VariantDictionary".to_string(),
                ));
            }
            let val_len = i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default());
            pos += 4;
            if val_len < 0 || pos + (val_len as usize) > data.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Invalid value length in VariantDictionary".to_string(),
                ));
            }
            let raw_val = &data[pos..pos + val_len as usize];
            pos += val_len as usize;

            let parsed = match value_type {
                TYPE_UINT32 if raw_val.len() == 4 => {
                    VariantValue::UInt32(u32::from_le_bytes(raw_val.try_into().unwrap_or_default()))
                }
                TYPE_UINT64 if raw_val.len() == 8 => {
                    VariantValue::UInt64(u64::from_le_bytes(raw_val.try_into().unwrap_or_default()))
                }
                TYPE_BOOL if raw_val.len() == 1 => VariantValue::Bool(raw_val[0] != 0),
                TYPE_INT32 if raw_val.len() == 4 => {
                    VariantValue::Int32(i32::from_le_bytes(raw_val.try_into().unwrap_or_default()))
                }
                TYPE_INT64 if raw_val.len() == 8 => {
                    VariantValue::Int64(i64::from_le_bytes(raw_val.try_into().unwrap_or_default()))
                }
                TYPE_STRING => VariantValue::String(
                    std::str::from_utf8(raw_val)
                        .map_err(|e| {
                            RustPassError::CorruptedFormat(format!("VD string UTF-8 error: {e}"))
                        })?
                        .to_string(),
                ),
                TYPE_BYTEARRAY => VariantValue::ByteArray(raw_val.to_vec()),
                other => {
                    return Err(RustPassError::CorruptedFormat(format!(
                        "Unknown or mismatched VariantDictionary value type 0x{other:02x} (len={})",
                        raw_val.len()
                    )));
                }
            };
            entries.insert(key, parsed);
        }

        Ok(Self { entries })
    }

    /// Encodes this `VariantDictionary` into KDBX 4 binary form.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&VD_VERSION.to_le_bytes());

        for (key, value) in &self.entries {
            let (type_id, val_bytes): (u8, Vec<u8>) = match value {
                VariantValue::UInt32(v) => (TYPE_UINT32, v.to_le_bytes().to_vec()),
                VariantValue::UInt64(v) => (TYPE_UINT64, v.to_le_bytes().to_vec()),
                VariantValue::Bool(v) => (TYPE_BOOL, vec![u8::from(*v)]),
                VariantValue::Int32(v) => (TYPE_INT32, v.to_le_bytes().to_vec()),
                VariantValue::Int64(v) => (TYPE_INT64, v.to_le_bytes().to_vec()),
                VariantValue::String(s) => (TYPE_STRING, s.as_bytes().to_vec()),
                VariantValue::ByteArray(b) => (TYPE_BYTEARRAY, b.clone()),
            };
            buf.push(type_id);
            let key_bytes = key.as_bytes();
            buf.extend_from_slice(&(key_bytes.len() as i32).to_le_bytes());
            buf.extend_from_slice(key_bytes);
            buf.extend_from_slice(&(val_bytes.len() as i32).to_le_bytes());
            buf.extend_from_slice(&val_bytes);
        }

        buf.push(TYPE_END);
        buf
    }

    /// Reads an integer entry coerced to `u64`.
    #[must_use]
    pub fn get_u64(&self, key: &str) -> Option<u64> {
        match self.entries.get(key)? {
            VariantValue::UInt64(v) => Some(*v),
            VariantValue::UInt32(v) => Some(u64::from(*v)),
            VariantValue::Int64(v) => u64::try_from(*v).ok(),
            VariantValue::Int32(v) => u64::try_from(*v).ok(),
            _ => None,
        }
    }

    /// Reads a byte-array entry.
    #[must_use]
    pub fn get_bytes(&self, key: &str) -> Option<&[u8]> {
        match self.entries.get(key)? {
            VariantValue::ByteArray(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    /// Extracts a `KdfConfig` from KDBX 4 `KdfParameters`.
    pub fn to_kdf_config(&self) -> Result<KdfConfig> {
        let uuid = self.get_bytes("$UUID").ok_or_else(|| {
            RustPassError::CorruptedFormat("KdfParameters missing $UUID".to_string())
        })?;

        if uuid == Argon2Variant::Argon2d.uuid_bytes()
            || uuid == Argon2Variant::Argon2id.uuid_bytes()
        {
            let variant = if uuid == Argon2Variant::Argon2d.uuid_bytes() {
                Argon2Variant::Argon2d
            } else {
                Argon2Variant::Argon2id
            };
            let salt_slice = self.get_bytes("S").ok_or_else(|| {
                RustPassError::CorruptedFormat("Argon2 KdfParameters missing salt 'S'".to_string())
            })?;
            let salt: [u8; 32] = salt_slice.try_into().map_err(|_| {
                RustPassError::CorruptedFormat(format!(
                    "Argon2 salt expected 32 bytes, got {}",
                    salt_slice.len()
                ))
            })?;
            let parallelism = self.get_u64("P").unwrap_or(2) as u32;
            let memory_bytes = self.get_u64("M").unwrap_or(64 * 1024 * 1024);
            let iterations = self.get_u64("I").unwrap_or(2);
            let version = self.get_u64("V").unwrap_or(0x13) as u32;
            Ok(KdfConfig::Argon2 {
                variant,
                memory_bytes,
                iterations,
                parallelism,
                version,
                salt,
            })
        } else if uuid == KdfConfig::AES_KDF_UUID {
            let rounds = self.get_u64("R").unwrap_or(600_000);
            let seed_slice = self.get_bytes("S").ok_or_else(|| {
                RustPassError::CorruptedFormat("AES-KDF missing seed 'S'".to_string())
            })?;
            let seed: [u8; 32] = seed_slice.try_into().map_err(|_| {
                RustPassError::CorruptedFormat(format!(
                    "AES-KDF seed expected 32 bytes, got {}",
                    seed_slice.len()
                ))
            })?;
            Ok(KdfConfig::AesKdf { rounds, seed })
        } else {
            Err(RustPassError::UnsupportedFeature(format!(
                "Unsupported KDF UUID: {}",
                hex::encode(uuid)
            )))
        }
    }

    /// Builds KDBX 4 `KdfParameters` from `KdfConfig`.
    #[must_use]
    pub fn from_kdf_config(kdf: &KdfConfig) -> Self {
        let mut entries = BTreeMap::new();
        match kdf {
            KdfConfig::Argon2 {
                variant,
                memory_bytes,
                iterations,
                parallelism,
                version,
                salt,
            } => {
                entries.insert(
                    "$UUID".to_string(),
                    VariantValue::ByteArray(variant.uuid_bytes().to_vec()),
                );
                entries.insert("S".to_string(), VariantValue::ByteArray(salt.to_vec()));
                entries.insert("P".to_string(), VariantValue::UInt32(*parallelism));
                entries.insert("M".to_string(), VariantValue::UInt64(*memory_bytes));
                entries.insert("I".to_string(), VariantValue::UInt64(*iterations));
                entries.insert("V".to_string(), VariantValue::UInt32(*version));
            }
            KdfConfig::AesKdf { rounds, seed } => {
                entries.insert(
                    "$UUID".to_string(),
                    VariantValue::ByteArray(KdfConfig::AES_KDF_UUID.to_vec()),
                );
                entries.insert("R".to_string(), VariantValue::UInt64(*rounds));
                entries.insert("S".to_string(), VariantValue::ByteArray(seed.to_vec()));
            }
        }
        Self { entries }
    }
}
