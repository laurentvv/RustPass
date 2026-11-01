//! KDBX 3.1 & 4.x Outer Header and KDBX 4 Inner Header binary TLV parsers and serializers.

use crate::error::{Result, RustPassError};
use crate::kdbx::variant_dict::VariantDictionary;
use crate::model::{CipherAlgorithm, InnerStreamAlgorithm, KdbxVersion, KdfConfig};
use zeroize::Zeroizing;

/// First KDBX 32-bit file magic (`0x9AA2D903`).
pub const KDBX_SIG1: u32 = 0x9AA2_D903;
/// Second KDBX 32-bit file magic (`0xB54BFB67`).
pub const KDBX_SIG2: u32 = 0xB54B_FB67;

const FIELD_END: u8 = 0;
const FIELD_CIPHER_ID: u8 = 2;
const FIELD_COMPRESSION_FLAGS: u8 = 3;
const FIELD_MASTER_SEED: u8 = 4;
const FIELD_TRANSFORM_SEED: u8 = 5;
const FIELD_TRANSFORM_ROUNDS: u8 = 6;
const FIELD_ENCRYPTION_IV: u8 = 7;
const FIELD_PROTECTED_STREAM_KEY: u8 = 8;
const FIELD_STREAM_START_BYTES: u8 = 9;
const FIELD_INNER_RANDOM_STREAM_ID: u8 = 10;
const FIELD_KDF_PARAMETERS: u8 = 11;

const INNER_END: u8 = 0x00;
const INNER_STREAM_ID: u8 = 0x01;
const INNER_STREAM_KEY: u8 = 0x02;
const INNER_BINARY: u8 = 0x03;

/// Parsed outer header of a KDBX 3.1 or 4.x file.
#[derive(Debug, Clone)]
pub struct OuterHeader {
    /// Format version (`V3_1` or `V4_0`).
    pub version: KdbxVersion,
    /// Outer payload cipher (`ChaCha20` or `Aes256Cbc`).
    pub cipher: CipherAlgorithm,
    /// `true` when `CompressionFlags == 1` (GZip).
    pub compression_gzip: bool,
    /// 32-byte per-save random `MasterSeed`.
    pub master_seed: [u8; 32],
    /// 12-byte (ChaCha20) or 16-byte (AES-256-CBC) outer IV/nonce.
    pub encryption_iv: Vec<u8>,
    /// Key derivation configuration (`Argon2d`, `Argon2id`, or `AesKdf`).
    pub kdf: KdfConfig,
    /// KDBX 3.1 only: 32-byte `StreamStartBytes` verified right after CBC decryption.
    pub v3_stream_start_bytes: Option<[u8; 32]>,
    /// KDBX 3.1 only: inner protected stream key (`ProtectedStreamKey`).
    pub v3_inner_stream_key: Option<Zeroizing<Vec<u8>>>,
    /// KDBX 3.1 only: inner protected stream cipher ID (`Salsa20` / `ChaCha20`).
    pub v3_inner_stream_algo: Option<InnerStreamAlgorithm>,
    /// Exact byte offset in the input buffer immediately following the `EndOfHeader` TLV field.
    pub header_end_offset: usize,
}

impl OuterHeader {
    /// Parses the KDBX outer header from the beginning of `file_bytes`.
    pub fn parse(file_bytes: &[u8]) -> Result<Self> {
        if file_bytes.len() < 12 {
            return Err(RustPassError::InvalidSignature);
        }
        let sig1 = u32::from_le_bytes(file_bytes[0..4].try_into().unwrap_or_default());
        let sig2 = u32::from_le_bytes(file_bytes[4..8].try_into().unwrap_or_default());
        if sig1 != KDBX_SIG1 || sig2 != KDBX_SIG2 {
            return Err(RustPassError::InvalidSignature);
        }

        let minor = u16::from_le_bytes([file_bytes[8], file_bytes[9]]);
        let major = u16::from_le_bytes([file_bytes[10], file_bytes[11]]);

        let (version, len_width) = match major {
            3 => (KdbxVersion::V3_1, 2usize),
            4 => (KdbxVersion::V4_0 { minor }, 4usize),
            _ => return Err(RustPassError::UnsupportedVersion { major, minor }),
        };

        let mut pos = 12usize;
        let mut cipher: Option<CipherAlgorithm> = None;
        let mut compression_gzip = true;
        let mut master_seed: Option<[u8; 32]> = None;
        let mut encryption_iv: Option<Vec<u8>> = None;
        let mut kdf_params: Option<KdfConfig> = None;
        let mut v3_transform_seed: Option<[u8; 32]> = None;
        let mut v3_transform_rounds: Option<u64> = None;
        let mut v3_stream_start: Option<[u8; 32]> = None;
        let mut v3_stream_key: Option<Zeroizing<Vec<u8>>> = None;
        let mut v3_stream_algo: Option<InnerStreamAlgorithm> = None;

        loop {
            if pos + 1 + len_width > file_bytes.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Unexpected EOF inside KDBX outer header".to_string(),
                ));
            }
            let field_id = file_bytes[pos];
            let field_len = if len_width == 4 {
                u32::from_le_bytes(file_bytes[pos + 1..pos + 5].try_into().unwrap_or_default())
                    as usize
            } else {
                u16::from_le_bytes([file_bytes[pos + 1], file_bytes[pos + 2]]) as usize
            };
            pos += 1 + len_width;

            if pos + field_len > file_bytes.len() {
                return Err(RustPassError::CorruptedFormat(format!(
                    "Truncated KDBX header field id={field_id} len={field_len}"
                )));
            }
            let val = &file_bytes[pos..pos + field_len];
            pos += field_len;

            match field_id {
                FIELD_END => break,
                FIELD_CIPHER_ID => {
                    cipher = Some(CipherAlgorithm::from_uuid_bytes(val)?);
                }
                FIELD_COMPRESSION_FLAGS => {
                    if val.len() != 4 {
                        return Err(RustPassError::CorruptedFormat(
                            "Invalid CompressionFlags length".to_string(),
                        ));
                    }
                    let flags = u32::from_le_bytes(val.try_into().unwrap_or_default());
                    compression_gzip = match flags {
                        0 => false,
                        1 => true,
                        other => {
                            return Err(RustPassError::UnsupportedFeature(format!(
                                "Unsupported compression algorithm ID: {other}"
                            )));
                        }
                    };
                }
                FIELD_MASTER_SEED => {
                    let seed: [u8; 32] = val.try_into().map_err(|_| {
                        RustPassError::CorruptedFormat("MasterSeed must be 32 bytes".to_string())
                    })?;
                    master_seed = Some(seed);
                }
                FIELD_TRANSFORM_SEED => {
                    let seed: [u8; 32] = val.try_into().map_err(|_| {
                        RustPassError::CorruptedFormat("TransformSeed must be 32 bytes".to_string())
                    })?;
                    v3_transform_seed = Some(seed);
                }
                FIELD_TRANSFORM_ROUNDS => {
                    let raw: [u8; 8] = <[u8; 8]>::try_from(val).map_err(|_| {
                        RustPassError::CorruptedFormat(
                            "TransformRounds must be 8 bytes".to_string(),
                        )
                    })?;
                    v3_transform_rounds = Some(u64::from_le_bytes(raw));
                }
                FIELD_ENCRYPTION_IV => {
                    encryption_iv = Some(val.to_vec());
                }
                FIELD_PROTECTED_STREAM_KEY => {
                    v3_stream_key = Some(Zeroizing::new(val.to_vec()));
                }
                FIELD_STREAM_START_BYTES => {
                    let ssb: [u8; 32] = val.try_into().map_err(|_| {
                        RustPassError::CorruptedFormat(
                            "StreamStartBytes must be 32 bytes".to_string(),
                        )
                    })?;
                    v3_stream_start = Some(ssb);
                }
                FIELD_INNER_RANDOM_STREAM_ID => {
                    let raw: [u8; 4] = <[u8; 4]>::try_from(val).map_err(|_| {
                        RustPassError::CorruptedFormat(
                            "InnerRandomStreamID must be 4 bytes".to_string(),
                        )
                    })?;
                    v3_stream_algo = Some(InnerStreamAlgorithm::from_id(u32::from_le_bytes(raw))?);
                }
                FIELD_KDF_PARAMETERS => {
                    let vd = VariantDictionary::decode(val)?;
                    kdf_params = Some(vd.to_kdf_config()?);
                }
                _ => {
                    // Preserve forward compatibility with unknown/comment TLV fields (e.g. id=1, 12)
                }
            }
        }

        let cipher = cipher.ok_or_else(|| {
            RustPassError::CorruptedFormat("Missing CipherID in KDBX header".to_string())
        })?;
        let master_seed = master_seed.ok_or_else(|| {
            RustPassError::CorruptedFormat("Missing MasterSeed in KDBX header".to_string())
        })?;
        let encryption_iv = encryption_iv.ok_or_else(|| {
            RustPassError::CorruptedFormat("Missing EncryptionIV in KDBX header".to_string())
        })?;

        let kdf = match kdf_params {
            Some(k) => k,
            None => {
                if !matches!(version, KdbxVersion::V3_1) {
                    return Err(RustPassError::CorruptedFormat(
                        "KDBX 4 header is missing KdfParameters".to_string(),
                    ));
                }
                let seed = v3_transform_seed.ok_or_else(|| {
                    RustPassError::CorruptedFormat(
                        "Missing TransformSeed in KDBX 3.1 header".to_string(),
                    )
                })?;
                // Rounds come straight from the unauthenticated v3 header: bound
                // them like the KDBX 4 KdfParameters to block hang/overflow abuse.
                let rounds = v3_transform_rounds.ok_or_else(|| {
                    RustPassError::CorruptedFormat(
                        "Missing TransformRounds in KDBX 3.1 header".to_string(),
                    )
                })?;
                if !(1..=crate::kdbx::variant_dict::AES_KDF_MAX_ROUNDS).contains(&rounds) {
                    return Err(RustPassError::CorruptedFormat(format!(
                        "TransformRounds outside the safe range in KDBX 3.1 header: {rounds}"
                    )));
                }
                KdfConfig::AesKdf { rounds, seed }
            }
        };

        Ok(Self {
            version,
            cipher,
            compression_gzip,
            master_seed,
            encryption_iv,
            kdf,
            v3_stream_start_bytes: v3_stream_start,
            v3_inner_stream_key: v3_stream_key,
            v3_inner_stream_algo: v3_stream_algo,
            header_end_offset: pos,
        })
    }

    /// Encodes this outer header into raw bytes (ready for SHA-256 & Header HMAC computation).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&KDBX_SIG1.to_le_bytes());
        out.extend_from_slice(&KDBX_SIG2.to_le_bytes());

        let is_v4 = match self.version {
            KdbxVersion::V3_1 => {
                out.extend_from_slice(&1u16.to_le_bytes()); // minor = 1
                out.extend_from_slice(&3u16.to_le_bytes()); // major = 3
                false
            }
            KdbxVersion::V4_0 { minor } => {
                out.extend_from_slice(&minor.to_le_bytes());
                out.extend_from_slice(&4u16.to_le_bytes());
                true
            }
        };

        let push_field = |buf: &mut Vec<u8>, id: u8, data: &[u8]| {
            buf.push(id);
            if is_v4 {
                buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            } else {
                buf.extend_from_slice(&(data.len() as u16).to_le_bytes());
            }
            buf.extend_from_slice(data);
        };

        push_field(&mut out, FIELD_CIPHER_ID, &self.cipher.uuid_bytes());
        let comp: u32 = u32::from(self.compression_gzip);
        push_field(&mut out, FIELD_COMPRESSION_FLAGS, &comp.to_le_bytes());
        push_field(&mut out, FIELD_MASTER_SEED, &self.master_seed);

        if is_v4 {
            push_field(&mut out, FIELD_ENCRYPTION_IV, &self.encryption_iv);
            let vd = VariantDictionary::from_kdf_config(&self.kdf).encode();
            push_field(&mut out, FIELD_KDF_PARAMETERS, &vd);
        } else {
            let (rounds, seed) = match &self.kdf {
                KdfConfig::AesKdf { rounds, seed } => (*rounds, *seed),
                KdfConfig::Argon2 { salt, .. } => (100_000, *salt),
            };
            push_field(&mut out, FIELD_TRANSFORM_SEED, &seed);
            push_field(&mut out, FIELD_TRANSFORM_ROUNDS, &rounds.to_le_bytes());
            push_field(&mut out, FIELD_ENCRYPTION_IV, &self.encryption_iv);
            if let Some(ref key) = self.v3_inner_stream_key {
                push_field(&mut out, FIELD_PROTECTED_STREAM_KEY, key.as_slice());
            }
            if let Some(ref ssb) = self.v3_stream_start_bytes {
                push_field(&mut out, FIELD_STREAM_START_BYTES, ssb);
            }
            if let Some(algo) = self.v3_inner_stream_algo {
                push_field(
                    &mut out,
                    FIELD_INNER_RANDOM_STREAM_ID,
                    &algo.id().to_le_bytes(),
                );
            }
        }

        push_field(&mut out, FIELD_END, b"\r\n\r\n");
        out
    }
}

/// Binary attachment entry stored inside the KDBX 4 Inner Header.
#[derive(Debug, Clone)]
pub struct InnerBinary {
    /// `true` when protected flag (`0x01`) is set.
    pub protected: bool,
    /// Uncompressed binary content.
    pub data: Vec<u8>,
}

/// Parsed KDBX 4 Inner Header preceding the XML document inside the encrypted & decompressed payload.
#[derive(Debug, Clone)]
pub struct InnerHeader {
    /// Inner stream cipher (`ChaCha20` or `Salsa20`).
    pub stream_algo: InnerStreamAlgorithm,
    /// Inner stream key material (64 bytes in KDBX 4).
    pub stream_key: Zeroizing<Vec<u8>>,
    /// Indexed binary attachment pool (`0..N`).
    pub binaries: Vec<InnerBinary>,
    /// Byte offset where the UTF-8 `<KeePassFile>` XML begins.
    pub xml_offset: usize,
}

impl InnerHeader {
    /// Parses the KDBX 4 Inner Header from the decompressed inner payload.
    pub fn parse(payload: &[u8]) -> Result<Self> {
        let mut pos = 0usize;
        let mut stream_algo = InnerStreamAlgorithm::None;
        let mut stream_key = Zeroizing::new(Vec::new());
        let mut binaries = Vec::new();

        loop {
            if pos + 5 > payload.len() {
                return Err(RustPassError::CorruptedFormat(
                    "Unexpected EOF inside KDBX 4 inner header".to_string(),
                ));
            }
            let id = payload[pos];
            let len = u32::from_le_bytes(payload[pos + 1..pos + 5].try_into().unwrap_or_default())
                as usize;
            pos += 5;
            if pos + len > payload.len() {
                return Err(RustPassError::CorruptedFormat(format!(
                    "Truncated KDBX 4 inner header field id={id} len={len}"
                )));
            }
            let val = &payload[pos..pos + len];
            pos += len;

            match id {
                INNER_END => break,
                INNER_STREAM_ID => {
                    if val.len() != 4 {
                        return Err(RustPassError::CorruptedFormat(
                            "Invalid InnerRandomStreamID length".to_string(),
                        ));
                    }
                    let raw_id = u32::from_le_bytes(val.try_into().unwrap_or_default());
                    stream_algo = InnerStreamAlgorithm::from_id(raw_id)?;
                }
                INNER_STREAM_KEY => {
                    stream_key = Zeroizing::new(val.to_vec());
                }
                INNER_BINARY => {
                    if val.is_empty() {
                        binaries.push(InnerBinary {
                            protected: false,
                            data: Vec::new(),
                        });
                    } else {
                        binaries.push(InnerBinary {
                            protected: (val[0] & 0x01) != 0,
                            data: val[1..].to_vec(),
                        });
                    }
                }
                _ => {
                    // Forward-compatible ignore
                }
            }
        }

        Ok(Self {
            stream_algo,
            stream_key,
            binaries,
            xml_offset: pos,
        })
    }

    /// Encodes this KDBX 4 Inner Header into bytes preceding the XML payload.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();

        // 0x01 InnerRandomStreamID
        out.push(INNER_STREAM_ID);
        out.extend_from_slice(&4u32.to_le_bytes());
        out.extend_from_slice(&self.stream_algo.id().to_le_bytes());

        // 0x02 InnerRandomStreamKey
        out.push(INNER_STREAM_KEY);
        out.extend_from_slice(&(self.stream_key.len() as u32).to_le_bytes());
        out.extend_from_slice(self.stream_key.as_slice());

        // 0x03 Binaries
        for bin in &self.binaries {
            out.push(INNER_BINARY);
            let total_len = 1 + bin.data.len();
            out.extend_from_slice(&(total_len as u32).to_le_bytes());
            out.push(u8::from(bin.protected));
            out.extend_from_slice(&bin.data);
        }

        // 0x00 End
        out.push(INNER_END);
        out.extend_from_slice(&0u32.to_le_bytes());
        out
    }
}
