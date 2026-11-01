//! Master composite key assembly and Key Derivation Functions (Argon2d, Argon2id, AES-KDF).

use crate::crypto::keyfile::load_keyfile;
use crate::crypto::random_array;
use crate::error::{Result, RustPassError};
use crate::model::{Argon2Variant, KdfConfig, ProtectedString};
use aes::Aes256;
use aes::cipher::{Array, BlockCipherEncrypt, KeyInit};
use argon2::{Algorithm, Argon2, Params, Version};
use sha2::{Digest, Sha256, Sha512};
use std::path::{Path, PathBuf};
use std::time::Instant;
use zeroize::Zeroizing;

/// Composite master credentials used to open or encrypt a KDBX database.
#[derive(Debug, Clone, Default)]
pub struct MasterCredentials {
    /// Master password (`None` when `--no-password` is active; `Some("")` is a valid empty password).
    pub password: Option<ProtectedString>,
    /// Optional path to a key file (`.keyx`, `.key`, or arbitrary file).
    pub keyfile_path: Option<PathBuf>,
    /// Optional pre-parsed 32-byte key file material.
    pub keyfile_key: Option<Zeroizing<[u8; 32]>>,
}

impl MasterCredentials {
    /// Credentials consisting solely of a master password.
    #[must_use]
    pub fn with_password(password: impl Into<String>) -> Self {
        Self {
            password: Some(ProtectedString::new(password)),
            keyfile_path: None,
            keyfile_key: None,
        }
    }

    /// Credentials combining an optional password and an optional key file path.
    pub fn new(password: Option<String>, keyfile_path: Option<&Path>) -> Result<Self> {
        let keyfile_key = match keyfile_path {
            Some(p) => Some(load_keyfile(p)?),
            None => None,
        };
        Ok(Self {
            password: password.map(ProtectedString::new),
            keyfile_path: keyfile_path.map(Path::to_path_buf),
            keyfile_key,
        })
    }

    /// Computes `CompositeKey = SHA-256(SHA-256(password) || keyfile_32_bytes)` over active components.
    pub fn composite_key(&self) -> Result<Zeroizing<[u8; 32]>> {
        let loaded;
        let resolved_kf = match (&self.keyfile_key, &self.keyfile_path) {
            (Some(k), _) => Some(k),
            (None, Some(path)) => {
                loaded = Some(load_keyfile(path)?);
                loaded.as_ref()
            }
            (None, None) => None,
        };

        if self.password.is_none() && resolved_kf.is_none() {
            return Err(RustPassError::InvalidArgument(
                "At least a password or a key file must be provided".to_string(),
            ));
        }

        let mut outer = Sha256::new();
        if let Some(ref pw) = self.password {
            let pw_hash = Zeroizing::new(Sha256::digest(pw.as_str().as_bytes()));
            outer.update(*pw_hash);
        }
        if let Some(kf) = resolved_kf {
            outer.update(**kf);
        }

        let digest = outer.finalize();
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&digest);
        Ok(out)
    }
}

/// Derives the 32-byte `TransformedKey` from `composite_key` according to `kdf`.
pub fn derive_transformed_key(
    composite_key: &[u8; 32],
    kdf: &KdfConfig,
) -> Result<Zeroizing<[u8; 32]>> {
    match kdf {
        KdfConfig::Argon2 {
            variant,
            memory_bytes,
            iterations,
            parallelism,
            version,
            salt,
        } => {
            let alg = match variant {
                Argon2Variant::Argon2d => Algorithm::Argon2d,
                Argon2Variant::Argon2id => Algorithm::Argon2id,
            };
            let ver = match version {
                0x10 => Version::V0x10,
                0x13 => Version::V0x13,
                other => {
                    return Err(RustPassError::Crypto(format!(
                        "Unsupported Argon2 version 0x{other:x}"
                    )));
                }
            };
            let m_cost_kib = u32::try_from(*memory_bytes / 1024).map_err(|_| {
                RustPassError::Crypto("Argon2 memory cost exceeds u32 KiB limit".to_string())
            })?;
            let t_cost = u32::try_from(*iterations).map_err(|_| {
                RustPassError::Crypto("Argon2 iteration count exceeds u32 limit".to_string())
            })?;
            let params = Params::new(
                m_cost_kib.max(8),
                t_cost.max(1),
                (*parallelism).max(1),
                Some(32),
            )
            .map_err(|e| RustPassError::Crypto(format!("Invalid Argon2 parameters: {e}")))?;

            let mut out = Zeroizing::new([0u8; 32]);
            Argon2::new(alg, ver, params)
                .hash_password_into(composite_key, salt, &mut *out)
                .map_err(|e| RustPassError::Crypto(format!("Argon2 derivation failed: {e}")))?;
            Ok(out)
        }
        KdfConfig::AesKdf { rounds, seed } => {
            if *rounds == 0 || *rounds > crate::kdbx::variant_dict::AES_KDF_MAX_ROUNDS {
                return Err(RustPassError::Crypto(format!(
                    "AES-KDF round count outside the safe range: {rounds}"
                )));
            }
            let key = Array::from(*seed);
            let cipher = Aes256::new(&key);

            let mut left = [0u8; 16];
            let mut right = [0u8; 16];
            left.copy_from_slice(&composite_key[0..16]);
            right.copy_from_slice(&composite_key[16..32]);

            let mut blocks = [Array::from(left), Array::from(right)];
            left.fill(0);
            right.fill(0);
            for _ in 0..*rounds {
                cipher.encrypt_blocks(&mut blocks);
            }

            let mut hasher = Sha256::new();
            hasher.update(blocks[0].as_slice());
            hasher.update(blocks[1].as_slice());
            blocks[0].fill(0);
            blocks[1].fill(0);

            let digest = hasher.finalize();
            let mut out = Zeroizing::new([0u8; 32]);
            out.copy_from_slice(&digest);
            Ok(out)
        }
    }
}

/// Derives `(master_key_32B, hmac_master_key_64B)` from `master_seed` and `transformed_key`.
#[must_use]
pub fn derive_master_and_hmac_keys(
    master_seed: &[u8; 32],
    transformed_key: &[u8; 32],
) -> (Zeroizing<[u8; 32]>, Zeroizing<[u8; 64]>) {
    let mut mk_hasher = Sha256::new();
    mk_hasher.update(master_seed);
    mk_hasher.update(transformed_key);
    let mk_digest = mk_hasher.finalize();
    let mut master_key = Zeroizing::new([0u8; 32]);
    master_key.copy_from_slice(&mk_digest);

    let mut hmac_hasher = Sha512::new();
    hmac_hasher.update(master_seed);
    hmac_hasher.update(transformed_key);
    hmac_hasher.update([0x01]);
    let hmac_digest = hmac_hasher.finalize();
    let mut hmac_key = Zeroizing::new([0u8; 64]);
    hmac_key.copy_from_slice(&hmac_digest);

    (master_key, hmac_key)
}

/// Calibrates a fresh `KdfConfig::Argon2` (`Argon2id`, 64 MiB, 4 lanes) for `target_ms` (`100..=5000`).
pub fn calibrate_argon2id(target_ms: u64) -> Result<KdfConfig> {
    if !(100..=5000).contains(&target_ms) {
        return Err(RustPassError::InvalidArgument(
            "Target decryption time must be between 100 and 5000 ms".to_string(),
        ));
    }
    let salt = random_array::<32>()?;
    let dummy_key = [0x42u8; 32];
    let memory_bytes: u64 = 64 * 1024 * 1024;
    let parallelism: u32 = 4;

    let probe = KdfConfig::Argon2 {
        variant: Argon2Variant::Argon2id,
        memory_bytes,
        iterations: 1,
        parallelism,
        version: 0x13,
        salt,
    };
    let t0 = Instant::now();
    let _ = derive_transformed_key(&dummy_key, &probe)?;
    let one_iter_ms = t0.elapsed().as_millis().max(1) as u64;
    let iterations = (target_ms / one_iter_ms).clamp(2, 64);

    Ok(KdfConfig::Argon2 {
        variant: Argon2Variant::Argon2id,
        memory_bytes,
        iterations,
        parallelism,
        version: 0x13,
        salt,
    })
}
