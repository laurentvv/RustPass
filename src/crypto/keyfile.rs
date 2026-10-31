//! KeePass / KeePassXC key file parser and v2.0 `.keyx` XML generator.

use crate::crypto::random_array;
use crate::error::{Result, RustPassError};
use base64::Engine as _;
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroizing;

/// Reads a key file from disk and derives its 32-byte key component according to the KeePass
/// specification (XML v2.0 `.keyx`, XML v1.00, 64-byte hex, 32-byte raw binary, or SHA-256 fallback).
pub fn load_keyfile(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(std::fs::read(path)?);
    parse_keyfile_bytes(&raw)
}

/// Parses raw key-file bytes into a 32-byte key component.
pub fn parse_keyfile_bytes(raw: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if raw.is_empty() {
        return Err(RustPassError::InvalidArgument(
            "Key file cannot be empty".to_string(),
        ));
    }

    // 1. Try XML KeyFile (v2.0 or v1.00)
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim_start_matches('\u{feff}').trim();
        if trimmed.contains("<KeyFile")
            && let Some(parsed) = try_parse_xml_keyfile(trimmed)?
        {
            return Ok(parsed);
        }

        // 2. 64-character ASCII hexadecimal key file (ignoring trailing CR/LF if exact 64 trimmed or raw 64)
        if raw.len() == 64 && raw.iter().all(u8::is_ascii_hexdigit) {
            let mut key = Zeroizing::new([0u8; 32]);
            hex::decode_to_slice(raw, &mut *key)
                .map_err(|e| RustPassError::CorruptedFormat(format!("Hex key file error: {e}")))?;
            return Ok(key);
        }
    }

    // 3. Exact 32-byte raw key file
    if raw.len() == 32 {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(raw);
        return Ok(key);
    }

    // 4. Arbitrary file: SHA-256 over all bytes
    let digest = Sha256::digest(raw);
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&digest);
    Ok(key)
}

fn try_parse_xml_keyfile(xml_text: &str) -> Result<Option<Zeroizing<[u8; 32]>>> {
    let Ok(doc) = roxmltree::Document::parse(xml_text) else {
        return Ok(None);
    };
    let root = doc.root_element();
    if root.tag_name().name() != "KeyFile" {
        return Ok(None);
    }

    let version = root
        .children()
        .find(|n| n.has_tag_name("Meta"))
        .and_then(|m| m.children().find(|n| n.has_tag_name("Version")))
        .and_then(|v| v.text())
        .unwrap_or("1.0")
        .trim();

    let Some(data_node) = root
        .children()
        .find(|n| n.has_tag_name("Key"))
        .and_then(|k| k.children().find(|n| n.has_tag_name("Data")))
    else {
        return Err(RustPassError::CorruptedFormat(
            "XML KeyFile missing <Key><Data> element".to_string(),
        ));
    };

    let compact: Zeroizing<String> = Zeroizing::new(
        data_node
            .text()
            .unwrap_or("")
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect(),
    );

    if version.starts_with("2.") {
        let decoded = Zeroizing::new(hex::decode(compact.as_bytes()).map_err(|e| {
            RustPassError::CorruptedFormat(format!("Invalid KeyFile v2.0 hex data: {e}"))
        })?);
        if decoded.len() != 32 {
            return Err(RustPassError::CorruptedFormat(format!(
                "KeyFile v2.0 expected 32 bytes, got {}",
                decoded.len()
            )));
        }
        if let Some(expected_hash_hex) = data_node.attribute("Hash") {
            let clean_hash: String = expected_hash_hex
                .chars()
                .filter(|c| !c.is_whitespace())
                .collect();
            let actual_digest = Sha256::digest(&*decoded);
            let actual_prefix = hex::encode_upper(&actual_digest[0..4]);
            if !clean_hash.eq_ignore_ascii_case(&actual_prefix) {
                return Err(RustPassError::IntegrityMismatch(format!(
                    "KeyFile v2.0 hash mismatch (expected {clean_hash}, computed {actual_prefix})"
                )));
            }
        }
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&decoded);
        return Ok(Some(key));
    }

    // Version 1.0 / 1.00: Base64-encoded 32 bytes
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(compact.as_bytes())
        && decoded.len() == 32
    {
        let mut key = Zeroizing::new([0u8; 32]);
        key.copy_from_slice(&decoded);
        return Ok(Some(key));
    }

    Ok(None)
}

/// Generates a new KeePass v2.0 XML `.keyx` document with 256 bits of OS entropy and a 4-byte
/// SHA-256 verification hash, identical to `keepassxc-cli db-create --set-key-file`.
pub fn generate_xml_v2_keyfile() -> Result<Zeroizing<String>> {
    let raw_key = Zeroizing::new(random_array::<32>()?);
    let digest = Sha256::digest(*raw_key);
    let hash_attr = hex::encode_upper(&digest[0..4]);
    let hex_full = Zeroizing::new(hex::encode_upper(*raw_key));

    let row1 = format!(
        "{} {} {} {}",
        &hex_full[0..8],
        &hex_full[8..16],
        &hex_full[16..24],
        &hex_full[24..32]
    );
    let row2 = format!(
        "{} {} {} {}",
        &hex_full[32..40],
        &hex_full[40..48],
        &hex_full[48..56],
        &hex_full[56..64]
    );

    let xml = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <KeyFile>\n\
         \x20   <Meta>\n\
         \x20       <Version>2.0</Version>\n\
         \x20   </Meta>\n\
         \x20   <Key>\n\
         \x20       <Data Hash=\"{hash_attr}\">\n\
         \x20           {row1}\n\
         \x20           {row2}\n\
         \x20       </Data>\n\
         \x20   </Key>\n\
         </KeyFile>\n"
    );
    Ok(Zeroizing::new(xml))
}

/// Generates and writes a new v2.0 `.keyx` file to `path` (refusing to overwrite an existing file
/// unless `overwrite` is `true`).
pub fn write_new_keyfile(path: &Path, overwrite: bool) -> Result<()> {
    if path.exists() && !overwrite {
        return Err(RustPassError::InvalidArgument(format!(
            "Key file already exists: {}",
            path.display()
        )));
    }
    let content = generate_xml_v2_keyfile()?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content.as_bytes())?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xml_v2_keyfile_roundtrips_and_verifies_hash() {
        let sample = r#"<?xml version="1.0" encoding="UTF-8"?>
<KeyFile>
    <Meta>
        <Version>2.0</Version>
    </Meta>
    <Key>
        <Data Hash="C29915D6">
            7D20ED71 A0D69F69 99B0FD98 05ACC142
            FC8CC97A E356A751 34A1DEB0 2F24512E
        </Data>
    </Key>
</KeyFile>"#;
        let parsed = parse_keyfile_bytes(sample.as_bytes()).expect("valid v2.0 keyx");
        assert_eq!(parsed[0], 0x7D);
        assert_eq!(parsed[31], 0x2E);

        let generated = generate_xml_v2_keyfile().expect("generate keyx");
        let reparsed = parse_keyfile_bytes(generated.as_bytes()).expect("reparse generated keyx");
        assert_eq!(reparsed.len(), 32);
    }
}
