//! Google Authenticator export import (`otpauth-migration://offline?data=…`).
//!
//! Hand-rolled minimal protobuf decoder for the well-known migration payload —
//! no protobuf dependency, matching the clean-room scope. Wire schema (field
//! numbers fixed by the Google Authenticator app):
//!
//! ```text
//! MigrationPayload { repeated OtpParameters otp_parameters = 1;
//!                    int32 version = 2; int32 batch_size = 3;
//!                    int32 batch_index = 4; int32 batch_id = 5; }
//! OtpParameters  { bytes secret = 1; string name = 2; string issuer = 3;
//!                  enum algorithm = 4 (1=SHA1 2=SHA256 3=SHA512);
//!                  enum digits = 5 (1=SIX 2=EIGHT);
//!                  enum type = 6 (1=HOTP 2=TOTP);
//!                  int64 counter = 7; }
//! ```

use super::{OtpAlgorithm, TotpConfig};
use crate::error::{Result, RustPassError};

/// One decoded authenticator parameter set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationOtp {
    /// Label as exported (often `Issuer:Account`).
    pub name: String,
    /// Issuer string if the export carried one.
    pub issuer: String,
    /// Raw shared secret bytes.
    pub secret: Vec<u8>,
    /// HMAC algorithm.
    pub algorithm: OtpAlgorithm,
    /// Code length (6 or 8; anything else clamps to the nearest supported).
    pub digits: u8,
    /// `true` for counter-based HOTP exports.
    pub hotp: bool,
    /// HOTP start counter.
    pub counter: Option<u64>,
}

/// Decoded migration payload.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MigrationPayload {
    /// Decoded OTP parameter sets, in export order.
    pub entries: Vec<MigrationOtp>,
    /// Payload schema version (expected 1).
    pub version: i64,
    /// Number of payloads in the whole export batch.
    pub batch_size: i64,
    /// Zero-based index of this payload inside the batch.
    pub batch_index: i64,
}

impl MigrationOtp {
    /// Builds the importable `TotpConfig` (secret re-encoded as padded-free Base32).
    #[must_use]
    pub fn to_totp_config(&self) -> TotpConfig {
        // Google exports the label as "Issuer:Account" AND a separate issuer field;
        // when they agree, split them, otherwise keep the whole label as the account.
        let (issuer, account) = match self.name.split_once(':') {
            Some((iss, acc)) if self.issuer.is_empty() => {
                (iss.trim().to_string(), acc.trim().to_string())
            }
            _ if self.issuer.is_empty() => (String::new(), self.name.trim().to_string()),
            _ => (
                self.issuer.clone(),
                self.name
                    .strip_prefix(&format!("{}:", self.issuer))
                    .unwrap_or(self.name.trim())
                    .trim()
                    .to_string(),
            ),
        };
        let secret = data_encoding::BASE32_NOPAD.encode(&self.secret);
        TotpConfig {
            issuer,
            account,
            secret_base32: crate::model::ProtectedString::new(secret),
            algorithm: self.algorithm,
            digits: self.digits.clamp(6, 8),
            period: 30,
            steam: false,
            counter: if self.hotp {
                Some(self.counter.unwrap_or(0))
            } else {
                None
            },
        }
    }
}

/// Parses a full `otpauth-migration://offline?data=<base64>` URI.
pub fn parse_migration_uri(uri: &str) -> Result<MigrationPayload> {
    let rest = uri
        .trim()
        .strip_prefix("otpauth-migration://")
        .ok_or_else(|| {
            RustPassError::InvalidArgument("Not an otpauth-migration:// URI".to_string())
        })?;
    let query = rest.split_once('?').map_or(rest, |(_, q)| q);
    let data = query
        .split('&')
        .find_map(|pair| pair.strip_prefix("data="))
        .ok_or_else(|| {
            RustPassError::InvalidArgument(
                "otpauth-migration URI is missing the data parameter".to_string(),
            )
        })?;

    let decoded = decode_lenient_base64(data)?;
    parse_migration_payload(&decoded)
}

/// Decodes standard or URL-safe Base64, with or without padding.
fn decode_lenient_base64(raw: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    let clean: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
    for engine in [
        &base64::engine::general_purpose::URL_SAFE,
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &base64::engine::general_purpose::STANDARD,
        &base64::engine::general_purpose::STANDARD_NO_PAD,
    ] {
        if let Ok(bytes) = engine.decode(clean.as_bytes()) {
            return Ok(bytes);
        }
    }
    Err(RustPassError::InvalidArgument(
        "migration data is not valid Base64".to_string(),
    ))
}

/// Minimal protobuf wire reader: enough for the migration schema.
fn read_varint(buf: &[u8]) -> Result<(u64, &[u8])> {
    let mut value: u64 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= 10 {
            return Err(RustPassError::CorruptedFormat(
                "migration protobuf varint too long".to_string(),
            ));
        }
        value |= u64::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Ok((value, &buf[i + 1..]));
        }
    }
    Err(RustPassError::CorruptedFormat(
        "truncated migration protobuf varint".to_string(),
    ))
}

fn read_field_header(buf: &[u8]) -> Result<(u32, u8, &[u8])> {
    let (key, rest) = read_varint(buf)?;
    Ok((
        u32::try_from(key >> 3).unwrap_or(0),
        (key & 0x7) as u8,
        rest,
    ))
}

fn read_len_delimited(buf: &[u8]) -> Result<(&[u8], &[u8])> {
    let (len, rest) = read_varint(buf)?;
    let len = usize::try_from(len).map_err(|_| {
        RustPassError::CorruptedFormat("migration protobuf length overflow".to_string())
    })?;
    if rest.len() < len {
        return Err(RustPassError::CorruptedFormat(
            "truncated migration protobuf field".to_string(),
        ));
    }
    Ok((&rest[..len], &rest[len..]))
}

/// Decodes a raw `MigrationPayload` protobuf message.
pub fn parse_migration_payload(bytes: &[u8]) -> Result<MigrationPayload> {
    let mut payload = MigrationPayload::default();
    let mut rest = bytes;
    while !rest.is_empty() {
        let (field, wire, next) = read_field_header(rest)?;
        rest = next;
        match (field, wire) {
            (1, 2) => {
                let (msg, tail) = read_len_delimited(rest)?;
                rest = tail;
                payload.entries.push(parse_otp_parameters(msg)?);
            }
            (2, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                payload.version = i64::from_ne_bytes(v.to_ne_bytes());
            }
            (3, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                payload.batch_size = i64::from_ne_bytes(v.to_ne_bytes());
            }
            (4, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                payload.batch_index = i64::from_ne_bytes(v.to_ne_bytes());
            }
            (_, 0) => {
                let (_, tail) = read_varint(rest)?;
                rest = tail;
            }
            (_, 2) => {
                let (_, tail) = read_len_delimited(rest)?;
                rest = tail;
            }
            (_, other) => {
                return Err(RustPassError::CorruptedFormat(format!(
                    "unsupported migration protobuf wire type {other}"
                )));
            }
        }
    }
    Ok(payload)
}

fn parse_otp_parameters(bytes: &[u8]) -> Result<MigrationOtp> {
    let mut otp = MigrationOtp {
        name: String::new(),
        issuer: String::new(),
        secret: Vec::new(),
        algorithm: OtpAlgorithm::Sha1,
        digits: 6,
        hotp: false,
        counter: None,
    };
    let mut rest = bytes;
    while !rest.is_empty() {
        let (field, wire, next) = read_field_header(rest)?;
        rest = next;
        match (field, wire) {
            (1, 2) => {
                let (v, tail) = read_len_delimited(rest)?;
                rest = tail;
                otp.secret = v.to_vec();
            }
            (2, 2) => {
                let (v, tail) = read_len_delimited(rest)?;
                rest = tail;
                otp.name = String::from_utf8_lossy(v).into_owned();
            }
            (3, 2) => {
                let (v, tail) = read_len_delimited(rest)?;
                rest = tail;
                otp.issuer = String::from_utf8_lossy(v).into_owned();
            }
            (4, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                otp.algorithm = match v {
                    2 => OtpAlgorithm::Sha256,
                    3 => OtpAlgorithm::Sha512,
                    _ => OtpAlgorithm::Sha1,
                };
            }
            (5, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                otp.digits = match v {
                    2 => 8,
                    _ => 6,
                };
            }
            (6, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                otp.hotp = v == 1;
            }
            (7, 0) => {
                let (v, tail) = read_varint(rest)?;
                rest = tail;
                otp.counter = Some(v);
            }
            (_, 0) => {
                let (_, tail) = read_varint(rest)?;
                rest = tail;
            }
            (_, 2) => {
                let (_, tail) = read_len_delimited(rest)?;
                rest = tail;
            }
            (_, other) => {
                return Err(RustPassError::CorruptedFormat(format!(
                    "unsupported migration protobuf wire type {other}"
                )));
            }
        }
    }
    if otp.secret.is_empty() {
        return Err(RustPassError::CorruptedFormat(
            "migration OtpParameters has an empty secret".to_string(),
        ));
    }
    Ok(otp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ProtectedString;

    /// Builds a protobuf payload by hand (field 1 repeated, wrapped).
    fn otp_parameters_bytes(
        secret: &[u8],
        name: &str,
        issuer: &str,
        typ: u64,
        counter: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        let ld = |field: u32, data: &[u8]| {
            let mut b = vec![((field << 3) | 2) as u8];
            b.push(data.len() as u8);
            b.extend_from_slice(data);
            b
        };
        out.extend_from_slice(&ld(1, secret));
        out.extend_from_slice(&ld(2, name.as_bytes()));
        out.extend_from_slice(&ld(3, issuer.as_bytes()));
        out.push((6 << 3) as u8);
        out.push(typ as u8);
        if typ == 1 {
            out.push((7 << 3) as u8);
            out.push(counter as u8);
        }
        out
    }

    fn wrap(params: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for p in params {
            out.push((1 << 3) | 2);
            out.push(p.len() as u8);
            out.extend_from_slice(p);
        }
        out
    }

    #[test]
    fn decodes_totp_and_hotp_parameters() {
        let payload = wrap(&[
            otp_parameters_bytes(&[0x31; 10], "GitHub:alice", "GitHub", 2, 0),
            otp_parameters_bytes(&[0x42; 20], "Legacy:Server", "Legacy", 1, 5),
        ]);
        let decoded = parse_migration_payload(&payload).expect("decode");
        assert_eq!(decoded.entries.len(), 2);

        let totp = &decoded.entries[0];
        assert!(!totp.hotp);
        assert_eq!(totp.issuer, "GitHub");
        assert_eq!(totp.secret, vec![0x31; 10]);

        let hotp = &decoded.entries[1];
        assert!(hotp.hotp);
        assert_eq!(hotp.counter, Some(5));

        let cfg = hotp.to_totp_config();
        assert!(cfg.is_hotp());
        assert_eq!(cfg.counter, Some(5));
        assert_eq!(cfg.account, "Server");
        assert_eq!(cfg.issuer, "Legacy");
        assert_ne!(cfg.secret_base32.as_str(), "");
    }

    #[test]
    fn parses_full_migration_uri() {
        use base64::Engine as _;
        let payload = wrap(&[otp_parameters_bytes(&[0x11; 16], "Test:me", "", 2, 0)]);
        let b64 = base64::engine::general_purpose::URL_SAFE.encode(&payload);
        let uri = format!("otpauth-migration://offline?data={b64}");
        let decoded = parse_migration_uri(&uri).expect("decode uri");
        assert_eq!(decoded.entries.len(), 1);
        assert_eq!(decoded.entries[0].to_totp_config().account, "me");
    }

    #[test]
    fn hotp_uri_roundtrip_keeps_counter() {
        let payload = wrap(&[otp_parameters_bytes(&[0x22; 12], "Vault:H", "Vault", 1, 9)]);
        let decoded = parse_migration_payload(&payload).expect("decode");
        let cfg = decoded.entries[0].to_totp_config();
        let uri = cfg.to_otpauth_uri();
        assert!(uri.starts_with("otpauth://hotp/"));
        assert!(uri.contains("counter=9"));
        let reparsed = TotpConfig::parse(&uri).expect("reparse");
        assert_eq!(reparsed.counter, Some(9));
        // ProtectedString sanity: secret survives via as_str.
        assert!(!ProtectedString::new("x").as_str().is_empty());
    }
}
