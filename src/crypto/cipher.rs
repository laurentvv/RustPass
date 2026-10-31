//! Symmetric outer payload encryption (`ChaCha20` & `AES-256-CBC`) and stateful inner random
//! stream cipher (`Salsa20` & `ChaCha20`) for `<Value Protected="True">` XML nodes.

use crate::error::{Result, RustPassError};
use crate::model::{CipherAlgorithm, InnerStreamAlgorithm};
use aes::Aes256;
use base64::Engine as _;
use cbc::cipher::{
    BlockModeDecrypt, BlockModeEncrypt, KeyIvInit, StreamCipher, block_padding::Pkcs7,
};
use chacha20::ChaCha20;
use salsa20::Salsa20;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

type Aes256CbcEnc = cbc::Encryptor<Aes256>;
type Aes256CbcDec = cbc::Decryptor<Aes256>;

/// Fixed 8-byte KDBX Salsa20 inner stream nonce (`E8 30 09 4B 97 20 5D 2A`).
const KDBX_SALSA20_NONCE: [u8; 8] = [0xE8, 0x30, 0x09, 0x4B, 0x97, 0x20, 0x5D, 0x2A];

/// Encrypts `plaintext` using the outer payload cipher (`ChaCha20` or `AES-256-CBC` PKCS#7).
pub fn encrypt_payload(
    algorithm: CipherAlgorithm,
    master_key: &[u8; 32],
    iv: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    match algorithm {
        CipherAlgorithm::Aes256Cbc => {
            let iv_arr: [u8; 16] = iv.try_into().map_err(|_| {
                RustPassError::Crypto(format!("AES-256-CBC requires 16-byte IV, got {}", iv.len()))
            })?;
            let enc = Aes256CbcEnc::new(master_key.into(), (&iv_arr).into());
            Ok(enc.encrypt_padded_vec::<Pkcs7>(plaintext))
        }
        CipherAlgorithm::ChaCha20 => {
            let nonce_arr: [u8; 12] = iv.try_into().map_err(|_| {
                RustPassError::Crypto(format!("ChaCha20 requires 12-byte nonce, got {}", iv.len()))
            })?;
            let mut buf = plaintext.to_vec();
            let mut stream = ChaCha20::new(master_key.into(), (&nonce_arr).into());
            stream.apply_keystream(&mut buf);
            Ok(buf)
        }
    }
}

/// Decrypts `ciphertext` using the outer payload cipher (`ChaCha20` or `AES-256-CBC` PKCS#7).
pub fn decrypt_payload(
    algorithm: CipherAlgorithm,
    master_key: &[u8; 32],
    iv: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    match algorithm {
        CipherAlgorithm::Aes256Cbc => {
            let iv_arr: [u8; 16] = iv.try_into().map_err(|_| {
                RustPassError::Crypto(format!("AES-256-CBC requires 16-byte IV, got {}", iv.len()))
            })?;
            let dec = Aes256CbcDec::new(master_key.into(), (&iv_arr).into());
            let pt = dec
                .decrypt_padded_vec::<Pkcs7>(ciphertext)
                .map_err(|_| RustPassError::InvalidCredentials)?;
            Ok(Zeroizing::new(pt))
        }
        CipherAlgorithm::ChaCha20 => {
            let nonce_arr: [u8; 12] = iv.try_into().map_err(|_| {
                RustPassError::Crypto(format!("ChaCha20 requires 12-byte nonce, got {}", iv.len()))
            })?;
            let mut buf = Zeroizing::new(ciphertext.to_vec());
            let mut stream = ChaCha20::new(master_key.into(), (&nonce_arr).into());
            stream.apply_keystream(&mut buf);
            Ok(buf)
        }
    }
}

/// Stateful inner random stream cipher that masks/unmasks `<Value Protected="True">` attributes
/// sequentially in XML document order.
pub enum InnerStream {
    /// Unencrypted pass-through (`ID = 0`).
    None,
    /// Salsa20 stream (`ID = 2`).
    Salsa(Box<Salsa20>),
    /// RFC 8439 ChaCha20 stream (`ID = 3`).
    ChaCha(Box<ChaCha20>),
}

impl InnerStream {
    /// Initializes the inner random stream from `algorithm` and `raw_key`.
    #[must_use]
    pub fn new(algorithm: InnerStreamAlgorithm, raw_key: &[u8]) -> Self {
        match algorithm {
            InnerStreamAlgorithm::None => Self::None,
            InnerStreamAlgorithm::Salsa20 => {
                let key_digest = Zeroizing::new(Sha256::digest(raw_key));
                let mut key = Zeroizing::new([0u8; 32]);
                key.copy_from_slice(&key_digest);
                let cipher = Salsa20::new((&*key).into(), (&KDBX_SALSA20_NONCE).into());
                Self::Salsa(Box::new(cipher))
            }
            InnerStreamAlgorithm::ChaCha20 => {
                let hash = Zeroizing::new(Sha512::digest(raw_key));
                let mut key = Zeroizing::new([0u8; 32]);
                let mut nonce = Zeroizing::new([0u8; 12]);
                key.copy_from_slice(&hash[0..32]);
                nonce.copy_from_slice(&hash[32..44]);
                let cipher = ChaCha20::new((&*key).into(), (&*nonce).into());
                Self::ChaCha(Box::new(cipher))
            }
        }
    }

    /// Applies the keystream in-place to `data`.
    pub fn apply(&mut self, data: &mut [u8]) {
        match self {
            Self::None => {}
            Self::Salsa(c) => c.apply_keystream(data),
            Self::ChaCha(c) => c.apply_keystream(data),
        }
    }

    /// Decrypts a Base64-encoded `<Value Protected="True">` string into UTF-8 plaintext.
    /// Note: Even empty strings advance 0 bytes; non-empty Base64 advances `decoded.len()` bytes!
    pub fn decrypt_base64(&mut self, b64_text: &str) -> Result<Zeroizing<String>> {
        let clean: String = b64_text.chars().filter(|c| !c.is_whitespace()).collect();
        if clean.is_empty() {
            return Ok(Zeroizing::new(String::new()));
        }
        let mut bytes = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(clean.as_bytes())
                .map_err(|e| {
                    RustPassError::CorruptedFormat(format!("Invalid protected Base64 value: {e}"))
                })?,
        );
        self.apply(&mut bytes);
        let s = std::str::from_utf8(&bytes)
            .map_err(|e| RustPassError::CorruptedFormat(format!("Protected UTF-8 error: {e}")))?
            .to_string();
        Ok(Zeroizing::new(s))
    }

    /// Encrypts plaintext UTF-8 bytes with the advancing stream and returns Base64 text.
    #[must_use]
    pub fn encrypt_to_base64(&mut self, plaintext: &str) -> String {
        if plaintext.is_empty() {
            return String::new();
        }
        let mut buf = Zeroizing::new(plaintext.as_bytes().to_vec());
        self.apply(&mut buf);
        base64::engine::general_purpose::STANDARD.encode(&*buf)
    }
}
