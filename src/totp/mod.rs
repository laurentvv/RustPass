//! RFC 4226 (HOTP), RFC 6238 (TOTP), Steam Guard 5-char encoder, `otpauth://` URI parser, and
//! clean-room QR code matrix encoder.

pub mod qr;

use crate::error::{Result, RustPassError};
use crate::model::{Entry, ProtectedString};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, KeyInit, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use zeroize::Zeroizing;

/// Alphabet used by Steam Guard 5-character TOTP tokens.
const STEAM_ALPHABET: &[u8; 26] = b"23456789BCDFGHJKMNPQRTVWXY";

/// Hash function used by HMAC-based OTP calculation (RFC 6238).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum OtpAlgorithm {
    /// HMAC-SHA-1 (RFC 4226 / RFC 6238 default).
    #[default]
    Sha1,
    /// HMAC-SHA-256.
    Sha256,
    /// HMAC-SHA-512.
    Sha512,
}

impl OtpAlgorithm {
    /// Canonical uppercase URI string (`"SHA1"`, `"SHA256"`, `"SHA512"`).
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "SHA1",
            Self::Sha256 => "SHA256",
            Self::Sha512 => "SHA512",
        }
    }

    /// Parses algorithm identifier case-insensitively.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_uppercase().as_str() {
            "SHA1" | "HMAC-SHA1" | "SHA-1" => Ok(Self::Sha1),
            "SHA256" | "HMAC-SHA256" | "SHA-256" => Ok(Self::Sha256),
            "SHA512" | "HMAC-SHA512" | "SHA-512" => Ok(Self::Sha512),
            other => Err(RustPassError::Totp(format!(
                "Unsupported TOTP hash algorithm: {other}"
            ))),
        }
    }
}

/// Complete TOTP configuration parsed from or serialized to an `otpauth://` URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TotpConfig {
    /// Service / issuer label (e.g. `"GitHub"`).
    pub issuer: String,
    /// Account identifier (e.g. `"alice@example.com"`).
    pub account: String,
    /// Clean normalized Base32 secret (without padding or whitespace).
    pub secret_base32: ProtectedString,
    /// Underlying HMAC digest algorithm.
    pub algorithm: OtpAlgorithm,
    /// Output code length (`6..=8` for numeric, `5` for Steam).
    pub digits: u8,
    /// Time step in seconds (`30` default).
    pub period: u64,
    /// Whether Steam Guard 26-symbol encoding is active.
    pub steam: bool,
}

impl TotpConfig {
    /// Parses either a full `otpauth://totp/...` (or `otpauth://steam/...`) URI or a raw Base32
    /// shared secret.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err(RustPassError::Totp("Empty TOTP secret or URI".to_string()));
        }

        if let Some(rest) = trimmed
            .strip_prefix("otpauth://")
            .or_else(|| trimmed.strip_prefix("OTPAUTH://"))
        {
            return Self::parse_otpauth_body(rest);
        }

        let clean_secret = normalize_base32(trimmed)?;
        Ok(Self {
            issuer: String::new(),
            account: String::new(),
            secret_base32: ProtectedString::new(clean_secret.as_str()),
            algorithm: OtpAlgorithm::Sha1,
            digits: 6,
            period: 30,
            steam: false,
        })
    }

    fn parse_otpauth_body(rest: &str) -> Result<Self> {
        let (kind_and_label, query) = match rest.split_once('?') {
            Some((lhs, rhs)) => (lhs, rhs),
            None => (rest, ""),
        };

        let (kind, raw_label) = kind_and_label
            .split_once('/')
            .unwrap_or((kind_and_label, ""));
        let kind_lower = kind.to_ascii_lowercase();
        if kind_lower != "totp" && kind_lower != "steam" && kind_lower != "hotp" {
            return Err(RustPassError::Totp(format!(
                "Unsupported otpauth scheme type: {kind}"
            )));
        }

        let decoded_label = urlencoding::decode(raw_label)
            .map(std::borrow::Cow::into_owned)
            .unwrap_or_else(|_| raw_label.to_string());
        let (mut issuer, account) = match decoded_label.split_once(':') {
            Some((iss, acc)) => (iss.trim().to_string(), acc.trim().to_string()),
            None => (String::new(), decoded_label.trim().to_string()),
        };

        let mut secret_opt: Option<Zeroizing<String>> = None;
        let mut algorithm = OtpAlgorithm::Sha1;
        let mut steam = kind_lower == "steam";
        let mut digits: u8 = if steam { 5 } else { 6 };
        let mut period: u64 = 30;

        for pair in query.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
            let val = urlencoding::decode(v)
                .map(std::borrow::Cow::into_owned)
                .unwrap_or_else(|_| v.to_string());
            match k.to_ascii_lowercase().as_str() {
                "secret" => {
                    secret_opt = Some(normalize_base32(&val)?);
                }
                "issuer" if !val.trim().is_empty() => {
                    issuer = val.trim().to_string();
                }
                "algorithm" => {
                    algorithm = OtpAlgorithm::parse(&val)?;
                }
                "digits" => {
                    let parsed = val.trim().parse::<u8>().map_err(|_| {
                        RustPassError::Totp(format!("Invalid TOTP digits parameter: {val}"))
                    })?;
                    digits = parsed;
                }
                "period" | "step" => {
                    let parsed = val.trim().parse::<u64>().map_err(|_| {
                        RustPassError::Totp(format!("Invalid TOTP period parameter: {val}"))
                    })?;
                    if parsed == 0 {
                        return Err(RustPassError::Totp(
                            "TOTP period must be greater than zero".to_string(),
                        ));
                    }
                    period = parsed;
                }
                "encoder" if val.eq_ignore_ascii_case("steam") => {
                    steam = true;
                }
                _ => {}
            }
        }

        if steam {
            digits = 5;
        } else if !(6..=10).contains(&digits) {
            return Err(RustPassError::Totp(format!(
                "TOTP digits must be between 6 and 10 (got {digits})"
            )));
        }

        let Some(clean_secret) = secret_opt else {
            return Err(RustPassError::Totp(
                "otpauth:// URI is missing required 'secret' parameter".to_string(),
            ));
        };

        Ok(Self {
            issuer,
            account,
            secret_base32: ProtectedString::new(clean_secret.as_str()),
            algorithm,
            digits,
            period,
            steam,
        })
    }

    /// Extracts a `TotpConfig` from an `Entry` (checking `entry.otp`, then KeePassXC legacy
    /// `TOTP Seed` / `TOTP Settings` custom attributes).
    pub fn from_entry(entry: &Entry) -> Result<Self> {
        if let Some(ref otp) = entry.otp
            && !otp.is_empty()
        {
            let mut cfg = Self::parse(otp.as_str())?;
            if cfg.issuer.is_empty() {
                cfg.issuer.clone_from(&entry.title);
            }
            if cfg.account.is_empty() {
                cfg.account.clone_from(&entry.username);
            }
            return Ok(cfg);
        }

        if let Some(seed) = entry.get_attribute("TOTP Seed") {
            let clean = normalize_base32(seed)?;
            let mut period = 30u64;
            let mut digits = 6u8;
            let mut steam = false;
            if let Some(settings) = entry.get_attribute("TOTP Settings") {
                let parts: Vec<&str> = settings.split(';').map(str::trim).collect();
                if let Some(p) = parts.first().and_then(|s| s.parse::<u64>().ok())
                    && p > 0
                {
                    period = p;
                }
                if let Some(&d_part) = parts.get(1) {
                    if d_part.eq_ignore_ascii_case("S") {
                        steam = true;
                        digits = 5;
                    } else if let Ok(d) = d_part.parse::<u8>() {
                        digits = d.clamp(6, 10);
                    }
                }
            }
            return Ok(Self {
                issuer: entry.title.clone(),
                account: entry.username.clone(),
                secret_base32: ProtectedString::new(clean.as_str()),
                algorithm: OtpAlgorithm::Sha1,
                digits,
                period,
                steam,
            });
        }

        Err(RustPassError::Totp(format!(
            "Entry '{}' has no TOTP configuration",
            entry.title
        )))
    }

    /// Formats this configuration as a canonical `otpauth://totp/...` URI compatible with
    /// KeePassXC and mobile authenticators.
    #[must_use]
    pub fn to_otpauth_uri(&self) -> String {
        let label = match (self.issuer.is_empty(), self.account.is_empty()) {
            (false, false) => format!(
                "{}:{}",
                urlencoding::encode(&self.issuer),
                urlencoding::encode(&self.account)
            ),
            (false, true) => urlencoding::encode(&self.issuer).into_owned(),
            (true, false) => urlencoding::encode(&self.account).into_owned(),
            (true, true) => "RustPass".to_string(),
        };

        let mut params = format!(
            "secret={}&period={}&digits={}&algorithm={}",
            self.secret_base32.as_str(),
            self.period,
            if self.steam { 5 } else { self.digits },
            self.algorithm.as_str()
        );
        if !self.issuer.is_empty() {
            params.push_str("&issuer=");
            params.push_str(&urlencoding::encode(&self.issuer));
        }
        if self.steam {
            params.push_str("&encoder=steam");
        }
        format!("otpauth://totp/{label}?{params}")
    }

    /// Decodes the Base32 shared secret into raw key bytes.
    pub fn secret_bytes(&self) -> Result<Zeroizing<Vec<u8>>> {
        decode_base32_secret(self.secret_base32.as_str())
    }

    /// Generates the current TOTP token and remaining validity seconds at `Utc::now()`.
    pub fn generate_now(&self) -> Result<(String, u64)> {
        let now_secs = u64::try_from(chrono::Utc::now().timestamp().max(0)).unwrap_or(0);
        self.generate_at(now_secs)
    }

    /// Generates the TOTP token and remaining validity seconds at `unix_seconds`.
    pub fn generate_at(&self, unix_seconds: u64) -> Result<(String, u64)> {
        let period = self.period.max(1);
        let counter = unix_seconds / period;
        let remaining = period - (unix_seconds % period);
        let key = self.secret_bytes()?;
        let code = compute_hotp(&key, counter, self.algorithm, self.digits, self.steam)?;
        Ok((code, remaining))
    }
}

/// Normalizes a user-supplied Base32 string (removes whitespace, hyphens, and `=` padding;
/// validates RFC 4648 Base32 alphabet).
pub fn normalize_base32(raw: &str) -> Result<Zeroizing<String>> {
    let cleaned: Zeroizing<String> = Zeroizing::new(
        raw.chars()
            .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
            .map(|c| c.to_ascii_uppercase())
            .collect(),
    );
    if cleaned.is_empty() {
        return Err(RustPassError::Totp("Base32 secret is empty".to_string()));
    }
    let _ = decode_base32_secret(&cleaned)?;
    Ok(cleaned)
}

fn decode_base32_secret(normalized_upper: &str) -> Result<Zeroizing<Vec<u8>>> {
    BASE32_NOPAD
        .decode(normalized_upper.as_bytes())
        .map(Zeroizing::new)
        .map_err(|e| RustPassError::Totp(format!("Invalid Base32 secret: {e}")))
}

/// Computes an RFC 4226 / RFC 6238 dynamic truncation code for `counter`.
pub fn compute_hotp(
    secret: &[u8],
    counter: u64,
    algorithm: OtpAlgorithm,
    digits: u8,
    steam: bool,
) -> Result<String> {
    let counter_be = counter.to_be_bytes();
    let digest: Zeroizing<Vec<u8>> = match algorithm {
        OtpAlgorithm::Sha1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                .map_err(|e| RustPassError::Totp(format!("HMAC-SHA1 key error: {e}")))?;
            mac.update(&counter_be);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        OtpAlgorithm::Sha256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                .map_err(|e| RustPassError::Totp(format!("HMAC-SHA256 key error: {e}")))?;
            mac.update(&counter_be);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
        OtpAlgorithm::Sha512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                .map_err(|e| RustPassError::Totp(format!("HMAC-SHA512 key error: {e}")))?;
            mac.update(&counter_be);
            Zeroizing::new(mac.finalize().into_bytes().to_vec())
        }
    };

    let last = *digest.last().unwrap_or(&0);
    let offset = (last & 0x0f) as usize;
    let slice = digest
        .get(offset..offset + 4)
        .ok_or_else(|| RustPassError::Totp("Invalid HMAC digest length".to_string()))?;
    let binary = u32::from_be_bytes([slice[0] & 0x7f, slice[1], slice[2], slice[3]]);

    if steam {
        let mut full = binary;
        let mut chars = String::with_capacity(5);
        for _ in 0..5 {
            let idx = (full % 26) as usize;
            chars.push(STEAM_ALPHABET[idx] as char);
            full /= 26;
        }
        return Ok(chars);
    }

    let width = usize::from(digits.clamp(6, 10));
    let modulus = 10u64.pow(u32::from(digits.clamp(6, 10)));
    let otp = u64::from(binary) % modulus;
    Ok(format!("{otp:0width$}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc6238_official_sha1_sha256_sha512_vectors() {
        // RFC 6238 Appendix B test secrets:
        // SHA1   (20 bytes): "12345678901234567890"
        // SHA256 (32 bytes): "12345678901234567890123456789012"
        // SHA512 (64 bytes): "1234567890123456789012345678901234567890123456789012345678901234"
        let s1 = b"12345678901234567890";
        let s256 = b"12345678901234567890123456789012";
        let s512 = b"1234567890123456789012345678901234567890123456789012345678901234";

        // Time = 59s -> counter = 1 (period = 30, 8 digits)
        assert_eq!(
            compute_hotp(s1, 1, OtpAlgorithm::Sha1, 8, false).expect("sha1"),
            "94287082"
        );
        assert_eq!(
            compute_hotp(s256, 1, OtpAlgorithm::Sha256, 8, false).expect("sha256"),
            "46119246"
        );
        assert_eq!(
            compute_hotp(s512, 1, OtpAlgorithm::Sha512, 8, false).expect("sha512"),
            "90693936"
        );

        // Time = 1111111109 -> counter = 37037036
        let c2 = 1_111_111_109 / 30;
        assert_eq!(
            compute_hotp(s1, c2, OtpAlgorithm::Sha1, 8, false).expect("sha1"),
            "07081804"
        );
        assert_eq!(
            compute_hotp(s256, c2, OtpAlgorithm::Sha256, 8, false).expect("sha256"),
            "68084774"
        );
        assert_eq!(
            compute_hotp(s512, c2, OtpAlgorithm::Sha512, 8, false).expect("sha512"),
            "25091201"
        );
    }

    #[test]
    fn otpauth_uri_and_steam_roundtrip() {
        let uri = "otpauth://totp/Steam:gabe?secret=JBSWY3DPEHPK3PXP&issuer=Steam&encoder=steam";
        let cfg = TotpConfig::parse(uri).expect("parse steam otpauth");
        assert!(cfg.steam);
        assert_eq!(cfg.digits, 5);
        let (code, rem) = cfg.generate_at(1_700_000_000).expect("gen steam");
        assert_eq!(code.len(), 5);
        assert!((1..=30).contains(&rem));
        assert!(code.chars().all(|c| STEAM_ALPHABET.contains(&(c as u8))));
    }
}
