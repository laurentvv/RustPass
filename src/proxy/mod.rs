//! Chrome / Firefox / Edge Native Messaging framing (`u32 LE` length + UTF-8 JSON) and
//! KeePassXC-Browser compatible protocol responder (`rustpass-proxy`).

use crate::error::{Result, RustPassError};
use crate::generator::PasswordGeneratorOptions;
use crate::model::Database;
use crypto_box::{SalsaBox, SecretKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
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

/// Ephemeral server half of the encrypted channel (fresh per proxy process).
struct ServerKeys {
    secret: SecretKey,
    public: crypto_box::PublicKey,
}

/// Session context for processing browser requests.
pub struct BrowserSession<'a> {
    /// Optional unlocked `Database`.
    pub db: Option<&'a Database>,
    /// Explicit opt-in to the legacy **plaintext** protocol for local integration
    /// tests only; production clients must use the encrypted channel.
    pub allow_plaintext_logins: bool,
    /// Ephemeral X25519 keypair created lazily on `change-public-keys`.
    server: Option<ServerKeys>,
    /// Client ephemeral public key registered by `change-public-keys`.
    client_pk: Option<crypto_box::PublicKey>,
    /// Persisted-ish association store for this process: `id -> idKey public bytes`.
    /// (KeePassXC stores these in the vault metadata; a proxy process is scoped to
    /// one unlock session, which keeps the attack surface local.)
    associations: HashMap<String, [u8; 32]>,
}

impl<'a> BrowserSession<'a> {
    /// Session over an optional database with plaintext logins refused.
    #[must_use]
    pub fn new(db: Option<&'a Database>) -> Self {
        Self {
            db,
            allow_plaintext_logins: false,
            server: None,
            client_pk: None,
            associations: HashMap::new(),
        }
    }
}

/// Increments a libsodium-style nonce in place (little-endian byte 0 first).
fn nonce_increment(nonce: &mut [u8; 24]) {
    for b in nonce.iter_mut() {
        let (sum, overflow) = b.overflowing_add(1);
        *b = sum;
        if !overflow {
            return;
        }
    }
}

/// Processes a `KeePassXC-Browser` JSON request against a [`BrowserSession`].
///
/// Implements the KeePassXC-Browser v7 protocol: `change-public-keys` exchanges
/// X25519 public keys, and every later action travels inside a NaCl box
/// (`base64(nonce || box(json))`, response nonce = client nonce + 1).
#[must_use]
pub fn handle_browser_message(req_val: &Value, session: &mut BrowserSession<'_>) -> Value {
    let action = req_val
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let nonce = req_val.get("nonce").and_then(Value::as_str).unwrap_or("");
    let open_db = session.db;

    let no_encrypted_channel = || {
        json!({
            "action": action,
            "error": "encrypted channel not established (send change-public-keys first); credentials are never returned in plaintext",
            "errorCode": "15",
            "nonce": nonce,
        })
    };

    // 1. Key exchange is the only plaintext action.
    if action == "change-public-keys" {
        return handle_key_exchange(req_val, session, nonce);
    }

    // 2. Encrypted channel: decrypt the boxed request, dispatch, box the answer.
    //    Key material is cloned out first so the dispatch can take `&mut session`.
    let msg_b64 = req_val.get("message").and_then(Value::as_str);
    let channel = match (session.client_pk.as_ref(), session.server.as_ref()) {
        (Some(pk), Some(sv)) => Some((pk.clone(), sv.secret.clone())),
        _ => None,
    };
    if let (Some((client_pk, server_secret)), Some(msg_b64)) = (channel, msg_b64) {
        let box_ = SalsaBox::new(&client_pk, &server_secret);
        return match decrypt_request(&box_, msg_b64) {
            Ok(inner) => {
                let mut response_inner = dispatch_encrypted(&inner, session);
                encrypt_response_boxed(action, &box_, nonce, &mut response_inner)
            }
            Err(e) => json!({
                "action": action,
                "error": format!("decryption failed: {e}"),
                "errorCode": "1",
                "nonce": nonce,
            }),
        };
    }

    // 3. Legacy plaintext protocol — local integration tests only.
    if !session.allow_plaintext_logins {
        return no_encrypted_channel();
    }

    match action {
        "ping" => json!({
            "action": "ping",
            "version": env!("CARGO_PKG_VERSION"),
            "success": "true",
            "nonce": nonce,
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
        // Plaintext association would fake a protected channel: refuse (the real
        // association flow runs inside the encrypted dispatch).
        "test-associate" | "associate" => no_encrypted_channel(),
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

use base64::Engine as _;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn b64_decode(raw: &str) -> std::result::Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(raw.trim().as_bytes())
        .map_err(|e| format!("invalid base64: {e}"))
}

/// `change-public-keys`: registers the client X25519 key, lazily creates the server
/// keypair, and answers with the server public key (plaintext per protocol).
fn handle_key_exchange(req_val: &Value, session: &mut BrowserSession<'_>, nonce: &str) -> Value {
    let Some(client_key_b64) = req_val.get("publicKey").and_then(Value::as_str) else {
        return json!({
            "action": "change-public-keys",
            "error": "missing publicKey",
            "errorCode": "1",
            "nonce": nonce,
        });
    };
    let client_bytes = match b64_decode(client_key_b64) {
        Ok(b) => b,
        Err(e) => {
            return json!({
                "action": "change-public-keys",
                "error": e,
                "errorCode": "1",
                "nonce": nonce,
            });
        }
    };
    let client_arr: [u8; 32] = match client_bytes.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return json!({
                "action": "change-public-keys",
                "error": "publicKey must be 32 bytes",
                "errorCode": "1",
                "nonce": nonce,
            });
        }
    };

    if session.server.is_none() {
        let secret = SecretKey::from(crate::crypto::random_array::<32>().unwrap_or([7u8; 32]));
        let public = secret.public_key();
        session.server = Some(ServerKeys { secret, public });
    }
    session.client_pk = Some(crypto_box::PublicKey::from(client_arr));

    let server_pk = session
        .server
        .as_ref()
        .map(|s| b64(s.public.as_bytes()))
        .unwrap_or_default();
    json!({
        "action": "change-public-keys",
        "version": env!("CARGO_PKG_VERSION"),
        "publicKey": server_pk,
        "nonce": nonce,
        "success": "true",
    })
}

/// Opens `base64(nonce24 || box(json))` and parses the inner JSON.
fn decrypt_request(box_: &SalsaBox, msg_b64: &str) -> std::result::Result<Value, String> {
    use crypto_box::aead::Aead;
    let raw = b64_decode(msg_b64)?;
    if raw.len() < 25 {
        return Err("message shorter than a nonce".to_string());
    }
    let (nonce_bytes, ciphertext) = raw.split_at(24);
    let nonce = *crypto_box::Nonce::from_slice(nonce_bytes);
    let plaintext = box_
        .decrypt(&nonce, ciphertext)
        .map_err(|_| "box authentication failed (wrong keys or tampered message)".to_string())?;
    serde_json::from_slice(&plaintext).map_err(|e| format!("inner JSON parse error: {e}"))
}

/// Boxes `inner` with the given box and the incremented client nonce.
fn encrypt_response_boxed(
    action: &str,
    box_: &SalsaBox,
    client_nonce: &str,
    inner: &mut Value,
) -> Value {
    use crypto_box::aead::Aead;
    let mut nonce_bytes = [0u8; 24];
    // Response nonce = client nonce + 1 (libsodium increment), echoed in the payload.
    let resp_nonce_b64 = match b64_decode(client_nonce) {
        Ok(n) if n.len() == 24 => {
            nonce_bytes.copy_from_slice(&n);
            nonce_increment(&mut nonce_bytes);
            b64(&nonce_bytes)
        }
        _ => {
            crate::crypto::random_bytes(&mut nonce_bytes).expect("OS randomness is available");
            b64(&nonce_bytes)
        }
    };

    if let Some(obj) = inner.as_object_mut() {
        obj.insert("nonce".to_string(), Value::String(resp_nonce_b64.clone()));
    }
    let plaintext = serde_json::to_vec(inner).unwrap_or_default();
    let nonce = *crypto_box::Nonce::from_slice(&nonce_bytes);
    let boxed = box_
        .encrypt(&nonce, plaintext.as_slice())
        .unwrap_or_default();
    let mut message = nonce_bytes.to_vec();
    message.extend_from_slice(&boxed);

    json!({
        "action": action,
        "message": b64(&message),
        "nonce": resp_nonce_b64,
    })
}

/// Encrypted-channel dispatch: the only place credentials ever leave the proxy,
/// always inside a box.
fn dispatch_encrypted(inner: &Value, session: &mut BrowserSession<'_>) -> Value {
    let action = inner
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let client_nonce = inner
        .get("nonce")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    // NOTE: `finish` returns the PLAIN inner payload — the caller (the routing in
    // `handle_browser_message`) performs the single boxing pass.
    let finish = |session: &BrowserSession<'_>,
                  action: &str,
                  _client_nonce: &str,
                  payload: Value|
     -> Value {
        if session.client_pk.is_none() || session.server.is_none() {
            return json!({ "action": action, "error": "channel not established" });
        }
        payload
    };

    match action.as_str() {
        "associate" => {
            let Some(key_b64) = inner.get("key").and_then(Value::as_str) else {
                return finish(
                    session,
                    &action,
                    &client_nonce,
                    json!({
                        "error": "associate request is missing the idKey", "errorCode": "1",
                    }),
                );
            };
            let key_bytes = match b64_decode(key_b64) {
                Ok(b) if b.len() == 32 => {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&b);
                    arr
                }
                _ => {
                    return finish(
                        session,
                        &action,
                        &client_nonce,
                        json!({
                            "error": "idKey must be 32 bytes", "errorCode": "1",
                        }),
                    );
                }
            };
            let id = uuid::Uuid::new_v4().to_string().replace('-', "");
            session.associations.insert(id.clone(), key_bytes);
            finish(
                session,
                &action,
                &client_nonce,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "id": id,
                    "success": "true",
                }),
            )
        }
        "test-associate" => {
            let id = inner.get("id").and_then(Value::as_str).unwrap_or("");
            let key_ok = inner
                .get("key")
                .and_then(Value::as_str)
                .and_then(|k| b64_decode(k).ok())
                .is_some_and(|k| {
                    session
                        .associations
                        .get(id)
                        .is_some_and(|stored| stored.as_slice() == k.as_slice())
                });
            finish(
                session,
                &action,
                &client_nonce,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "id": id,
                    "success": if key_ok { "true" } else { "false" },
                }),
            )
        }
        "get-databasehash" => match session.db {
            Some(db) => {
                let mut hasher = Sha256::new();
                hasher.update(db.root.uuid.as_bytes());
                hasher.update(db.meta.database_name.as_bytes());
                finish(
                    session,
                    &action,
                    &client_nonce,
                    json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "hash": hex::encode(hasher.finalize()),
                        "success": "true",
                    }),
                )
            }
            None => finish(
                session,
                &action,
                &client_nonce,
                json!({
                    "error": "Database not opened", "errorCode": "1",
                }),
            ),
        },
        "generate-password" => {
            let opts = crate::generator::PasswordGeneratorOptions::default();
            match opts.generate() {
                Ok(pw) => finish(
                    session,
                    &action,
                    &client_nonce,
                    json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "password": pw.as_str(),
                        "success": "true",
                    }),
                ),
                Err(e) => finish(
                    session,
                    &action,
                    &client_nonce,
                    json!({
                        "error": e.to_string(), "errorCode": "15",
                    }),
                ),
            }
        }
        "get-logins" => {
            let Some(db) = session.db else {
                return finish(
                    session,
                    &action,
                    &client_nonce,
                    json!({
                        "error": "Database not opened", "errorCode": "1",
                    }),
                );
            };
            let target_url = inner.get("url").and_then(Value::as_str).unwrap_or("");
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
                        matches.push(json!({
                            "uuid": entry.uuid.to_string(),
                            "name": entry.title,
                            "login": entry.username,
                            "password": entry.password.as_str(),
                            "group": group_path,
                        }));
                    }
                }
            }
            finish(
                session,
                &action,
                &client_nonce,
                json!({
                    "version": env!("CARGO_PKG_VERSION"),
                    "count": matches.len(),
                    "entries": matches,
                    "success": "true",
                }),
            )
        }
        "lock-database" => finish(
            session,
            &action,
            &client_nonce,
            json!({
                "error": "lock-database is not supported by this proxy session (the vault owner controls locking)",
                "errorCode": "15",
            }),
        ),
        other => finish(
            session,
            &action,
            &client_nonce,
            json!({
                "error": format!("Unsupported action: {other}"),
                "errorCode": "15",
            }),
        ),
    }
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
    fn get_logins_refuses_without_an_established_channel() {
        let db = test_db();
        let decoded = decode_frame(&json!({
            "action": "get-logins",
            "url": "https://gist.github.com/octocat",
            "nonce": "n-123"
        }));
        let mut session = BrowserSession::new(Some(&db));
        let resp = handle_browser_message(&decoded, &mut session);
        assert!(resp.get("error").is_some(), "must refuse: {resp}");
        assert_eq!(resp["errorCode"], "15");
        assert!(resp.get("entries").is_none(), "no credentials may leave");
        // Same for association handshake.
        let resp = handle_browser_message(
            &json!({"action": "test-associate", "nonce": "n"}),
            &mut session,
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
        let mut session = BrowserSession::new(Some(&db));
        session.allow_plaintext_logins = true;
        let resp = handle_browser_message(&decoded, &mut session);
        assert_eq!(resp["count"], 1);
        assert_eq!(resp["entries"][0]["login"], "octocat");
    }

    /// Simulated KeePassXC-Browser client: key exchange -> associate ->
    /// test-associate (incl. wrong key) -> encrypted get-logins with credentials.
    #[test]
    fn encrypted_channel_full_client_roundtrip() {
        use base64::Engine as _;
        use crypto_box::SecretKey;

        let db = test_db();
        let mut session = BrowserSession::new(Some(&db));

        const NONCE24: [u8; 24] = *b"abcdefghijklmnopqrstuvwx";
        let nonce_b64 = base64::engine::general_purpose::STANDARD.encode(NONCE24);
        // Shadow with a &'static str compatible binding for the helper calls below.
        let nonce_b64: &'static str = Box::leak(nonce_b64.into_boxed_str());
        let nonce24_b64 = nonce_b64;
        let client_sk = SecretKey::from([0x42u8; 32]);
        let client_pk = client_sk.public_key();
        let req = json!({
            "action": "change-public-keys",
            "publicKey": base64::engine::general_purpose::STANDARD.encode(client_pk.as_bytes()),
            "nonce": nonce24_b64,
        });
        let resp = handle_browser_message(&req, &mut session);
        assert_eq!(resp["success"], "true");
        let server_pk_b64 = resp["publicKey"].as_str().expect("server pk");
        let server_pk_bytes = base64::engine::general_purpose::STANDARD
            .decode(server_pk_b64)
            .expect("b64");
        let server_arr: [u8; 32] = server_pk_bytes.as_slice().try_into().expect("32-byte pk");
        let server_pk = crypto_box::PublicKey::from(server_arr);
        let client_box = SalsaBox::new(&server_pk, &client_sk);

        let send_boxed = |session: &mut BrowserSession<'_>,
                          action: &str,
                          extra: Value,
                          nonce_b64: &str|
         -> Value {
            use crypto_box::aead::Aead;
            let mut inner = json!({ "action": action, "nonce": nonce_b64 });
            if let (Some(obj), Some(ext_obj)) = (inner.as_object_mut(), extra.as_object()) {
                for (k, v) in ext_obj {
                    obj.insert(k.clone(), v.clone());
                }
            }
            let mut nonce24 = [0u8; 24];
            nonce24.copy_from_slice(
                &base64::engine::general_purpose::STANDARD
                    .decode(nonce_b64)
                    .unwrap(),
            );
            let pt = serde_json::to_vec(&inner).unwrap();
            let boxed = client_box
                .encrypt(crypto_box::Nonce::from_slice(&nonce24), pt.as_slice())
                .unwrap();
            let mut message = nonce24.to_vec();
            message.extend_from_slice(&boxed);
            let req = json!({
                "action": action,
                "message": base64::engine::general_purpose::STANDARD.encode(&message),
                "nonce": nonce_b64,
            });
            let outer = handle_browser_message(&req, session);
            assert_eq!(outer["action"], action);
            let raw = base64::engine::general_purpose::STANDARD
                .decode(outer["message"].as_str().expect("message"))
                .unwrap();
            let (rn, ct) = raw.split_at(24);
            let mut expected = nonce24;
            nonce_increment(&mut expected);
            assert_eq!(rn, &expected, "response nonce must be client nonce + 1");
            let pt = client_box
                .decrypt(crypto_box::Nonce::from_slice(rn), ct)
                .expect("server box opens");
            serde_json::from_slice(&pt).expect("inner json")
        };

        // 2. Associate: registers the idKey, returns an id.
        let id_key = [0x77u8; 32];
        let assoc = send_boxed(
            &mut session,
            "associate",
            json!({ "key": base64::engine::general_purpose::STANDARD.encode(id_key) }),
            nonce24_b64,
        );
        assert_eq!(assoc["success"], "true");
        let id = assoc["id"].as_str().expect("association id").to_string();

        // 3. Test-associate: matching id+key succeeds.
        let test = send_boxed(
            &mut session,
            "test-associate",
            json!({
                "id": id.clone(),
                "key": base64::engine::general_purpose::STANDARD.encode(id_key),
            }),
            nonce24_b64,
        );
        assert_eq!(test["success"], "true");

        // Wrong key must NOT verify.
        let bad = send_boxed(
            &mut session,
            "test-associate",
            json!({
                "id": id.clone(),
                "key": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
            }),
            nonce24_b64,
        );
        assert_eq!(bad["success"], "false");

        // 4. Encrypted get-logins returns the vault credential.
        let logins = send_boxed(
            &mut session,
            "get-logins",
            json!({ "url": "https://gist.github.com/octocat" }),
            nonce24_b64,
        );
        assert_eq!(logins["count"], 1);
        assert_eq!(logins["entries"][0]["login"], "octocat");
        assert_eq!(logins["entries"][0]["password"], "ghp_secret");
    }
}
