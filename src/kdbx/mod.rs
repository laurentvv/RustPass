//! Complete KDBX 3.1 & 4.0/4.1 container reader and atomic writer.

pub mod header;
pub mod variant_dict;
pub mod xml;

use crate::crypto::cipher::{InnerStream, decrypt_payload, encrypt_payload};
use crate::crypto::hmac_stream::{
    compute_header_hmac, read_hashed_block_stream_v3, read_hmac_block_stream, verify_header_hmac,
    write_hashed_block_stream_v3, write_hmac_block_stream,
};
use crate::crypto::kdf::{MasterCredentials, derive_master_and_hmac_keys, derive_transformed_key};
use crate::crypto::{random_array, random_bytes};
use crate::error::{Result, RustPassError};
use crate::kdbx::header::{InnerHeader, OuterHeader};
use crate::kdbx::xml::{
    XmlSerializeMode, gunzip_bytes, gzip_bytes, parse_keepass_xml, serialize_keepass_xml,
};
use crate::model::{CipherAlgorithm, Database, InnerStreamAlgorithm, KdbxVersion, KdfConfig};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

impl Database {
    /// Opens and decrypts a `.kdbx` file from disk (supporting both KDBX 3.1 and KDBX 4.0/4.1).
    pub fn open(path: &Path, credentials: &MasterCredentials) -> Result<Self> {
        let raw_bytes = std::fs::read(path)?;
        Self::from_kdbx_bytes(&raw_bytes, credentials)
    }

    /// Parses and decrypts an in-memory `.kdbx` byte slice.
    pub fn from_kdbx_bytes(file_bytes: &[u8], credentials: &MasterCredentials) -> Result<Self> {
        let header = OuterHeader::parse(file_bytes)?;
        let composite_key = credentials.composite_key()?;
        let transformed_key = derive_transformed_key(&composite_key, &header.kdf)?;
        let (master_key, hmac_master_key) =
            derive_master_and_hmac_keys(&header.master_seed, &transformed_key);

        let header_slice = &file_bytes[0..header.header_end_offset];

        match header.version {
            KdbxVersion::V4_0 { .. } => {
                if header.header_end_offset + 64 > file_bytes.len() {
                    return Err(RustPassError::CorruptedFormat(
                        "Truncated KDBX 4 header SHA-256 / HMAC".to_string(),
                    ));
                }
                let expected_sha256 =
                    &file_bytes[header.header_end_offset..header.header_end_offset + 32];
                let expected_hmac: &[u8; 32] = file_bytes
                    [header.header_end_offset + 32..header.header_end_offset + 64]
                    .try_into()
                    .unwrap_or(&[0u8; 32]);

                // 1. Verify Header SHA-256
                let actual_sha256 = Sha256::digest(header_slice);
                if actual_sha256.as_slice() != expected_sha256 {
                    return Err(RustPassError::IntegrityMismatch(
                        "KDBX 4 header SHA-256 mismatch".to_string(),
                    ));
                }

                // 2. Verify Header HMAC-SHA-256 (wrong password triggers InvalidCredentials here!)
                verify_header_hmac(header_slice, &hmac_master_key, expected_hmac)?;

                // 3. Authenticate & reassemble HMAC Block Stream
                let hmac_stream_bytes = &file_bytes[header.header_end_offset + 64..];
                let ciphertext = read_hmac_block_stream(hmac_stream_bytes, &hmac_master_key)?;

                // 4. Decrypt outer payload
                let decrypted = decrypt_payload(
                    header.cipher,
                    &master_key,
                    &header.encryption_iv,
                    &ciphertext,
                )?;

                // 5. Optional GZip decompression
                let inner_payload = Zeroizing::new(if header.compression_gzip {
                    gunzip_bytes(&decrypted)?
                } else {
                    decrypted.to_vec()
                });

                // 6. Parse KDBX 4 Inner Header + XML
                let inner = InnerHeader::parse(&inner_payload)?;
                let xml_bytes = &inner_payload[inner.xml_offset..];
                let xml_str = std::str::from_utf8(xml_bytes).map_err(|e| {
                    RustPassError::CorruptedFormat(format!("KDBX 4 XML UTF-8 error: {e}"))
                })?;

                let mut stream = InnerStream::new(inner.stream_algo, &inner.stream_key);
                let (meta, root, deleted_objects) =
                    parse_keepass_xml(xml_str, &mut stream, &inner.binaries)?;

                Ok(Self {
                    version: header.version,
                    cipher: header.cipher,
                    compression_gzip: header.compression_gzip,
                    kdf: header.kdf,
                    inner_stream: inner.stream_algo,
                    meta,
                    root,
                    deleted_objects,
                })
            }
            KdbxVersion::V3_1 => {
                let ciphertext = &file_bytes[header.header_end_offset..];
                let decrypted = decrypt_payload(
                    header.cipher,
                    &master_key,
                    &header.encryption_iv,
                    ciphertext,
                )?;

                if decrypted.len() < 32 {
                    return Err(RustPassError::InvalidCredentials);
                }
                if let Some(ref expected_start) = header.v3_stream_start_bytes
                    && &decrypted[0..32] != expected_start
                {
                    return Err(RustPassError::InvalidCredentials);
                }

                let raw_hashed = read_hashed_block_stream_v3(&decrypted[32..])?;
                let xml_bytes = Zeroizing::new(if header.compression_gzip {
                    gunzip_bytes(&raw_hashed)?
                } else {
                    raw_hashed
                });
                let xml_str = std::str::from_utf8(&xml_bytes).map_err(|e| {
                    RustPassError::CorruptedFormat(format!("KDBX 3.1 XML UTF-8 error: {e}"))
                })?;

                let stream_algo = header
                    .v3_inner_stream_algo
                    .unwrap_or(InnerStreamAlgorithm::Salsa20);
                let empty_key = Zeroizing::new(Vec::new());
                let stream_key = header.v3_inner_stream_key.as_ref().unwrap_or(&empty_key);
                let mut stream = InnerStream::new(stream_algo, stream_key);

                let (meta, root, deleted_objects) = parse_keepass_xml(xml_str, &mut stream, &[])?;

                Ok(Self {
                    version: KdbxVersion::V3_1,
                    cipher: header.cipher,
                    compression_gzip: header.compression_gzip,
                    kdf: header.kdf,
                    inner_stream: stream_algo,
                    meta,
                    root,
                    deleted_objects,
                })
            }
        }
    }

    /// Serializes and encrypts `self` into a complete `.kdbx` binary buffer with freshly generated
    /// nonces, master seed, KDF salt, and inner stream key.
    pub fn to_kdbx_bytes(&mut self, credentials: &MasterCredentials) -> Result<Vec<u8>> {
        // Always rotate salts/nonces on every save!
        let master_seed = random_array::<32>()?;
        let new_salt = random_array::<32>()?;
        match &mut self.kdf {
            KdfConfig::Argon2 { salt, .. } => *salt = new_salt,
            KdfConfig::AesKdf { seed, .. } => *seed = new_salt,
        }

        // KDBX 3.1 only supports AES-256-CBC + AES-KDF; enforce consistency if version == V3_1
        if self.version == KdbxVersion::V3_1 {
            self.cipher = CipherAlgorithm::Aes256Cbc;
            if matches!(self.kdf, KdfConfig::Argon2 { .. }) {
                self.kdf = KdfConfig::AesKdf {
                    rounds: 100_000,
                    seed: new_salt,
                };
            }
            if self.inner_stream == InnerStreamAlgorithm::ChaCha20 {
                self.inner_stream = InnerStreamAlgorithm::Salsa20;
            }
        }

        let mut iv = vec![0u8; self.cipher.iv_len()];
        random_bytes(&mut iv)?;

        let composite_key = credentials.composite_key()?;
        let transformed_key = derive_transformed_key(&composite_key, &self.kdf)?;
        let (master_key, hmac_master_key) =
            derive_master_and_hmac_keys(&master_seed, &transformed_key);

        match self.version {
            KdbxVersion::V4_0 { .. } => {
                let mut inner_key = Zeroizing::new(vec![0u8; 64]);
                random_bytes(&mut inner_key)?;
                let mut stream = InnerStream::new(self.inner_stream, &inner_key);

                let (xml_str, binaries) = serialize_keepass_xml(
                    self,
                    XmlSerializeMode {
                        is_kdbx4: true,
                        encrypt_protected: true,
                    },
                    &mut stream,
                )?;

                let inner_hdr = InnerHeader {
                    stream_algo: self.inner_stream,
                    stream_key: inner_key,
                    binaries,
                    xml_offset: 0,
                };
                let mut raw_inner = Zeroizing::new(inner_hdr.encode());
                raw_inner.extend_from_slice(xml_str.as_bytes());

                let compressed = if self.compression_gzip {
                    gzip_bytes(&raw_inner)?
                } else {
                    raw_inner.to_vec()
                };

                let ciphertext = encrypt_payload(self.cipher, &master_key, &iv, &compressed)?;

                let outer = OuterHeader {
                    version: self.version,
                    cipher: self.cipher,
                    compression_gzip: self.compression_gzip,
                    master_seed,
                    encryption_iv: iv,
                    kdf: self.kdf.clone(),
                    v3_stream_start_bytes: None,
                    v3_inner_stream_key: None,
                    v3_inner_stream_algo: None,
                    header_end_offset: 0,
                };
                let header_bytes = outer.encode();
                let header_sha256 = Sha256::digest(&header_bytes);
                let header_hmac = compute_header_hmac(&header_bytes, &hmac_master_key)?;
                let hmac_blocks = write_hmac_block_stream(&ciphertext, &hmac_master_key)?;

                let mut out = Vec::with_capacity(header_bytes.len() + 64 + hmac_blocks.len());
                out.extend_from_slice(&header_bytes);
                out.extend_from_slice(&header_sha256);
                out.extend_from_slice(&header_hmac);
                out.extend_from_slice(&hmac_blocks);
                Ok(out)
            }
            KdbxVersion::V3_1 => {
                let stream_start = random_array::<32>()?;
                let mut inner_key = Zeroizing::new(vec![0u8; 32]);
                random_bytes(&mut inner_key)?;
                let mut stream = InnerStream::new(self.inner_stream, &inner_key);

                let (xml_str, _) = serialize_keepass_xml(
                    self,
                    XmlSerializeMode {
                        is_kdbx4: false,
                        encrypt_protected: true,
                    },
                    &mut stream,
                )?;

                let payload = if self.compression_gzip {
                    gzip_bytes(xml_str.as_bytes())?
                } else {
                    xml_str.into_bytes()
                };
                let hashed_blocks = write_hashed_block_stream_v3(&payload);

                let mut plain_stream = Zeroizing::new(Vec::with_capacity(32 + hashed_blocks.len()));
                plain_stream.extend_from_slice(&stream_start);
                plain_stream.extend_from_slice(&hashed_blocks);

                let ciphertext = encrypt_payload(self.cipher, &master_key, &iv, &plain_stream)?;

                let outer = OuterHeader {
                    version: KdbxVersion::V3_1,
                    cipher: self.cipher,
                    compression_gzip: self.compression_gzip,
                    master_seed,
                    encryption_iv: iv,
                    kdf: self.kdf.clone(),
                    v3_stream_start_bytes: Some(stream_start),
                    v3_inner_stream_key: Some(inner_key),
                    v3_inner_stream_algo: Some(self.inner_stream),
                    header_end_offset: 0,
                };
                let mut out = outer.encode();
                out.extend_from_slice(&ciphertext);
                Ok(out)
            }
        }
    }

    /// Atomically saves the encrypted `.kdbx` vault to `path` via a sibling `.kdbx.tmp` file.
    pub fn save_atomic(&mut self, path: &Path, credentials: &MasterCredentials) -> Result<()> {
        let bytes = self.to_kdbx_bytes(credentials)?;
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let tmp_name = format!(
            "{}.tmp",
            path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("vault.kdbx")
        );
        let tmp_path = path.with_file_name(tmp_name);
        std::fs::write(&tmp_path, &bytes)?;
        std::fs::rename(&tmp_path, path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Attachment, Entry};

    #[test]
    fn kdbx4_chacha20_argon2id_roundtrip_with_attachments_and_history() {
        let mut db = Database::new("Engineering Vault");
        let mut entry = Entry::new("GitLab");
        entry.username = "laurent".to_string();
        entry.password = "Sup3r$ecret#2026".into();
        entry.url = "https://gitlab.example.com".to_string();
        entry.notes = "SSH & deploy token".to_string();
        entry.otp =
            Some("otpauth://totp/GitLab:laurent?secret=JBSWY3DPEHPK3PXP&issuer=GitLab".into());
        entry.set_custom_attribute("API_TOKEN", "glpat-12345", true);
        entry.attachments.push(Attachment {
            name: "recovery.txt".to_string(),
            data: b"code-1\ncode-2\n".to_vec(),
            protected: true,
        });
        entry.push_history_snapshot(10);
        entry.password = "Rotated$ecret#2026!".into();
        db.add_entry_at_path("Infra/GitLab", entry)
            .expect("add entry");

        // Keep Argon2 light in unit test
        db.kdf = KdfConfig::Argon2 {
            variant: crate::model::Argon2Variant::Argon2id,
            memory_bytes: 1024 * 1024,
            iterations: 2,
            parallelism: 1,
            version: 0x13,
            salt: [7u8; 32],
        };

        let creds = MasterCredentials::with_password("master-pass-42");
        let raw = db.to_kdbx_bytes(&creds).expect("encode kdbx4");

        // Wrong password must fail with InvalidCredentials
        let bad_creds = MasterCredentials::with_password("wrong-pass");
        assert!(matches!(
            Database::from_kdbx_bytes(&raw, &bad_creds),
            Err(RustPassError::InvalidCredentials)
        ));

        let reopened = Database::from_kdbx_bytes(&raw, &creds).expect("decode kdbx4");
        let e = reopened.resolve_entry("Infra/GitLab").expect("find entry");
        assert_eq!(e.username, "laurent");
        assert_eq!(e.password.as_str(), "Rotated$ecret#2026!");
        assert_eq!(e.get_attribute("API_TOKEN"), Some("glpat-12345"));
        assert_eq!(e.attachments.len(), 1);
        assert_eq!(e.attachments[0].data, b"code-1\ncode-2\n");
        assert_eq!(e.history.len(), 1);
        assert_eq!(e.history[0].password.as_str(), "Sup3r$ecret#2026");
    }

    #[test]
    fn kdbx31_aes_kdf_roundtrip() {
        let mut db = Database::new("Legacy Vault");
        db.version = KdbxVersion::V3_1;
        db.kdf = KdfConfig::AesKdf {
            rounds: 1_000,
            seed: [3u8; 32],
        };
        let mut entry = Entry::new("Router");
        entry.password = "admin1234!".into();
        db.add_entry_at_path("Network/Router", entry).expect("add");

        let creds = MasterCredentials::with_password("v3-pass");
        let raw = db.to_kdbx_bytes(&creds).expect("encode v3.1");
        let reopened = Database::from_kdbx_bytes(&raw, &creds).expect("decode v3.1");
        assert_eq!(reopened.version, KdbxVersion::V3_1);
        assert_eq!(
            reopened
                .resolve_entry("Network/Router")
                .expect("entry")
                .password
                .as_str(),
            "admin1234!"
        );
    }
}
