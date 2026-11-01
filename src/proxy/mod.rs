//! Chrome / Firefox / Edge Native Messaging framing (`u32 LE` length + UTF-8 JSON) and
//! KeePassXC-Browser compatible protocol responder (`rustpass-proxy`).

use crate::error::{Result, RustPassError};
use crate::generator::PasswordGeneratorOptions;
use crate::model::Database;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// Maximum Native Messaging frame size accepted from a browser extension (1 MiB, per Chrome spec).
pub const MAX_NATIVE_MESSAGE_BYTES: usize = 1024 * 1024;

/// Reads a single `u32 LE`-prefixed JSON frame from `reader`. Returns `Ok(None)` on clean EOF.
pub fn read_native_message<R: Read>(reader: &mut R) -> Result<Option<Value>> {
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(RustPassError::Io(e)),
    }
    let len = u32::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_NATIVE_MESSAGE_BYTES {
        return Err(RustPassError::CorruptedFormat(format!(
            "Invalid Native Messaging frame length: {len} bytes"
        )));
    }
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    let parsed: Value = serde_json::from_slice(&payload).map_err(|e| {
        RustPassError::CorruptedFormat(format!("Invalid Native Messaging JSON: {e}"))
    })?;
    Ok(Some(parsed))
}

/// Writes a single `u32 LE`-prefixed JSON frame to `writer` and flushes.
pub fn write_native_message<W: Write>(writer: &mut W, message: &Value) -> Result<()> {
    let encoded = serde_json::to_vec(message)
        .map_err(|e| RustPassError::CorruptedFormat(format!("JSON serialize error: {e}")))?;
    let len_u32 = u32::try_from(encoded.len()).map_err(|_| {
        RustPassError::InvalidArgument("Native Messaging response exceeds u32".to_string())
    })?;
    writer.write_all(&len_u32.to_le_bytes())?;
    writer.write_all(&encoded)?;
    writer.flush()?;
    Ok(())
}

/// Incoming browser request envelope.
#[derive(Debug, Clone, Deserialize)]
pub struct BrowserRequest {
    /// Protocol action (`change-public-keys`, `get-databasehash`, `test-associate`, `get-logins`, `generate-password`).
    pub action: String,
    /// Optional client nonce echoed back in response.
    #[serde(default)]
    pub nonce: Option<String>,
    /// Optional client ID.
    #[serde(rename = "clientID", default)]
    pub client_id: Option<String>,
    /// Optional target URL for `get-logins`.
    #[serde(default)]
    pub url: Option<String>,
}

/// Outgoing browser response metadata when handling requests against an optional unlocked `Database`.
#[derive(Debug, Clone, Serialize)]
pub struct BrowserLoginEntry {
    /// Entry UUID.
    pub uuid: String,
    /// Entry title.
    pub name: String,
    /// Username.
    pub login: String,
    /// Password.
    pub password: String,
    /// Optional group name.
    pub group: String,
}

/// Session context for processing browser requests.
#[derive(Debug, Clone, Copy, Default)]
pub struct BrowserSession<'a> {
    /// Optional unlocked `Database`.
    pub db: Option<&'a Database>,
    /// Explicit opt-in to return plaintext credentials from `get-logins`.
    ///
    /// The KeePassXC-Browser encrypted channel (NaCl box over `change-public-keys`) is
    /// not implemented, so by default credentials are **never** returned: any local
    /// process that reaches the Native Messaging pipe must not be able to read vault
    /// passwords. This flag exists for documented local integration tests only.
    pub allow_plaintext_logins: bool,
}

impl<'a> BrowserSession<'a> {
    /// Session over an optional database with plaintext logins refused.
    #[must_use]
    pub fn new(db: Option<&'a Database>) -> Self {
        Self {
            db,
            allow_plaintext_logins: false,
        }
    }
}

/// Processes a `KeePassXC-Browser` JSON request against a [`BrowserSession`].
#[must_use]
pub fn handle_browser_message(req_val: &Value, session: &BrowserSession<'_>) -> Value {
    let action = req_val
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let nonce = req_val.get("nonce").and_then(Value::as_str).unwrap_or("");
    let open_db = session.db;

    let no_encrypted_channel = || {
        json!({
            "action": action,
            "error": "rustpass-proxy does not implement the encrypted KeePassXC-Browser channel; credentials are never returned in plaintext",
            "errorCode": "15",
            "nonce": nonce,
        })
    };

    match action {
        "ping" => json!({
            "action": "ping",
            "version": env!("CARGO_PKG_VERSION"),
            "success": "true",
            "nonce": nonce,
        }),
        "change-public-keys" => json!({
            "action": "change-public-keys",
            "version": env!("CARGO_PKG_VERSION"),
            "publicKey": base64_dummy_ephemeral_key(),
            "nonce": nonce,
            "success": "true",
        }),
        "get-databasehash" => match open_db {
            Some(db) => {
                let mut hasher = Sha256::new();
                hasher.update(db.root.uuid.as_bytes());
                hasher.update(db.meta.database_name.as_bytes());
                let hash_hex = hex::encode(hasher.finalize());
                json!({
                    "action": "get-databasehash",
                    "version": env!("CARGO_PKG_VERSION"),
                    "hash": hash_hex,
                    "nonce": nonce,
                    "success": "true",
                })
            }
            None => json!({
                "action": "get-databasehash",
                "error": "Database not opened",
                "errorCode": "1",
                "nonce": nonce,
            }),
        },
        // There is no association store: answering `success` here would only lure the
        // extension into a channel that cannot protect credentials. Refuse honestly.
        "test-associate" | "associate" => {
            if session.allow_plaintext_logins && open_db.is_some() {
                json!({
                    "action": action,
                    "id": open_db.map(|db| db.root.uuid.to_string()).unwrap_or_default(),
                    "nonce": nonce,
                    "success": "true",
                })
            } else {
                no_encrypted_channel()
            }
        }
        "generate-password" => {
            let opts = PasswordGeneratorOptions::default();
            match opts.generate() {
                Ok(pw) => json!({
                    "action": "generate-password",
                    "password": pw.as_str(),
                    "nonce": nonce,
                    "success": "true",
                }),
                Err(e) => json!({
                    "action": "generate-password",
                    "error": e.to_string(),
                    "errorCode": "15",
                    "nonce": nonce,
                }),
            }
        }
        "get-logins" => {
            if !session.allow_plaintext_logins {
                return no_encrypted_channel();
            }
            let Some(db) = open_db else {
                return json!({
                    "action": "get-logins",
                    "error": "Database not opened",
                    "errorCode": "1",
                    "nonce": nonce,
                });
            };
            let target_url = req_val.get("url").and_then(Value::as_str).unwrap_or("");
            let host = extract_url_host(target_url);
            let mut matches = Vec::new();
            if !host.is_empty() {
                for (group_path, entry) in db.all_entries(false) {
                    let entry_host = extract_url_host(&entry.url);
                    if !entry_host.is_empty()
                        && (entry_host.eq_ignore_ascii_case(&host)
                            || entry_host.ends_with(&format!(".{host}"))
                            || host.ends_with(&format!(".{entry_host}")))
                    {
                        matches.push(BrowserLoginEntry {
                            uuid: entry.uuid.to_string(),
                            name: entry.title.clone(),
                            login: entry.username.clone(),
                            password: entry.password.as_str().to_string(),
                            group: group_path,
                        });
                    }
                }
            }
            json!({
                "action": "get-logins",
                "count": matches.len(),
                "entries": matches,
                "nonce": nonce,
                "success": "true",
            })
        }
        other => json!({
            "action": other,
            "error": format!("Unsupported action: {other}"),
            "errorCode": "15",
            "nonce": nonce,
        }),
    }
}

fn base64_dummy_ephemeral_key() -> String {
    use base64::Engine as _;
    let key = crate::crypto::random_array::<32>().unwrap_or([0xA5u8; 32]);
    base64::engine::general_purpose::STANDARD.encode(key)
}

fn extract_url_host(url: &str) -> String {
    let trimmed = url.trim();
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let authority = without_scheme.split(['/', '?', '#']).next().unwrap_or("");
    let host_port = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    host_port
        .split(':')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

/// Generates a Chrome/Edge Native Messaging host manifest JSON pointing at `proxy_exe_path`.
#[must_use]
pub fn generate_chromium_native_manifest(proxy_exe_path: &str) -> String {
    let manifest = json!({
        "name": "org.keepassxc.keepassxc_browser",
        "description": "RustPass Native Messaging Host (KeePassXC-Browser compatible)",
        "path": proxy_exe_path,
        "type": "stdio",
        "allowed_origins": [
            "chrome-extension://oboonakemofpalcgghocfoadofidjkkk/",
            "chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/"
        ]
    });
    serde_json::to_string_pretty(&manifest).expect("static manifest JSON serializes")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Entry;
    use std::io::Cursor;

    fn test_db() -> Database {
        let mut db = Database::new("BrowserVault");
        let mut e = Entry::new("GitHub");
        e.username = "octocat".to_string();
        e.password = "ghp_secret".into();
        e.url = "https://github.com/login".to_string();
        db.add_entry_at_path("Web/GitHub", e).expect("add");
        db
    }

    fn decode_frame(req: &Value) -> Value {
        let mut wire = Vec::new();
        write_native_message(&mut wire, req).expect("write frame");
        let mut cursor = Cursor::new(wire);
        read_native_message(&mut cursor)
            .expect("read frame")
            .expect("frame present")
    }

    #[test]
    fn get_logins_refuses_plaintext_credentials_by_default() {
        let db = test_db();
        let decoded = decode_frame(&json!({
            "action": "get-logins",
            "url": "https://gist.github.com/octocat",
            "nonce": "n-123"
        }));
        let resp = handle_browser_message(&decoded, &BrowserSession::new(Some(&db)));
        assert!(resp.get("error").is_some(), "must refuse: {resp}");
        assert_eq!(resp["errorCode"], "15");
        assert!(resp.get("entries").is_none(), "no credentials may leave");
        // Same for association handshake.
        let resp = handle_browser_message(
            &json!({"action": "test-associate", "nonce": "n"}),
            &BrowserSession::new(Some(&db)),
        );
        assert!(resp.get("error").is_some());
    }

    #[test]
    fn native_messaging_frame_roundtrip_and_login_lookup_in_explicit_test_mode() {
        let db = test_db();
        let decoded = decode_frame(&json!({
            "action": "get-logins",
            "url": "https://gist.github.com/octocat",
            "nonce": "n-123"
        }));
        let session = BrowserSession {
            db: Some(&db),
            allow_plaintext_logins: true,
        };
        let resp = handle_browser_message(&decoded, &session);
        assert_eq!(resp["count"], 1);
        assert_eq!(resp["entries"][0]["login"], "octocat");
    }
}
