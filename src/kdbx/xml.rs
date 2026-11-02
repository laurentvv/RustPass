//! KDBX `<KeePassFile>` XML parser (`roxmltree`) and deterministic serializer, handling both
//! KDBX 4.x (Base64 epoch timestamps, Inner Header `Ref` attachments) and KDBX 3.1 / plain XML
//! (ISO-8601 timestamps, `<Meta><Binaries>` GZip-compressed attachments).

use crate::crypto::cipher::InnerStream;
use crate::error::{Result, RustPassError};
use crate::kdbx::header::InnerBinary;
use crate::model::{
    Attachment, AutoType, AutoTypeAssociation, CustomAttribute, CustomIcon, Database,
    DeletedObject, Entry, Group, Meta, ProtectedString, Times,
};
use base64::Engine as _;
use chrono::{DateTime, TimeZone, Utc};
use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use roxmltree::Node;
use std::collections::HashMap;
use std::io::{Read, Write};
use uuid::Uuid;
use zeroize::Zeroizing;

/// Seconds between `0001-01-01T00:00:00Z` (KDBX 4 binary epoch) and `1970-01-01T00:00:00Z`.
const KDBX4_EPOCH_OFFSET_SECS: i64 = 62_135_596_800;

/// Parses a `<KeePassFile>` XML document into `(Meta, Group, Vec<DeletedObject>)`, advancing
/// `inner_stream` strictly in XML document order for every `Protected="True"` value.
pub fn parse_keepass_xml(
    xml_text: &str,
    inner_stream: &mut InnerStream,
    v4_binaries: &[InnerBinary],
) -> Result<(Meta, Group, Vec<DeletedObject>)> {
    let trimmed = xml_text.trim_start_matches('\u{feff}');
    let doc = roxmltree::Document::parse(trimmed)
        .map_err(|e| RustPassError::Xml(format!("Invalid KDBX XML: {e}")))?;

    let kp_root = doc.root_element();
    if kp_root.tag_name().name() != "KeePassFile" {
        return Err(RustPassError::Xml(format!(
            "Expected <KeePassFile>, got <{}>",
            kp_root.tag_name().name()
        )));
    }

    let mut meta = Meta::default();
    let mut v3_binaries: HashMap<usize, InnerBinary> = HashMap::new();
    let mut root_group: Option<Group> = None;
    let mut deleted_objects = Vec::new();

    for section in kp_root.children().filter(Node::is_element) {
        match section.tag_name().name() {
            "Meta" => {
                meta = parse_meta(section, &mut v3_binaries)?;
            }
            "Root" => {
                for child in section.children().filter(Node::is_element) {
                    match child.tag_name().name() {
                        "Group" => {
                            if root_group.is_none() {
                                root_group = Some(parse_group(
                                    child,
                                    inner_stream,
                                    v4_binaries,
                                    &v3_binaries,
                                )?);
                            }
                        }
                        "DeletedObjects" => {
                            for del_node in child
                                .children()
                                .filter(|n| n.is_element() && n.has_tag_name("DeletedObject"))
                            {
                                let del = parse_deleted_object(del_node)?;
                                {
                                    deleted_objects.push(del);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }

    let root = root_group
        .ok_or_else(|| RustPassError::Xml("Missing <Root><Group> in KDBX XML".to_string()))?;

    Ok((meta, root, deleted_objects))
}

fn parse_meta(node: Node<'_, '_>, v3_binaries: &mut HashMap<usize, InnerBinary>) -> Result<Meta> {
    let mut meta = Meta::default();

    for child in node.children().filter(Node::is_element) {
        let text = child.text().unwrap_or("").trim();
        match child.tag_name().name() {
            "Generator" => meta.generator = text.to_string(),
            "DatabaseName" => meta.database_name = text.to_string(),
            "DatabaseNameChanged" => meta.database_name_changed = parse_timestamp(text)?,
            "DatabaseDescription" => meta.database_description = text.to_string(),
            "DatabaseDescriptionChanged" => {
                meta.database_description_changed = parse_timestamp(text)?;
            }
            "DefaultUserName" => meta.default_username = text.to_string(),
            "DefaultUserNameChanged" => meta.default_username_changed = parse_timestamp(text)?,
            "MaintenanceHistoryDays" => {
                meta.maintenance_history_days = text.parse().unwrap_or(365);
            }
            "Color" => meta.color = text.to_string(),
            "MasterKeyChanged" => meta.master_key_changed = parse_timestamp(text)?,
            "MemoryProtection" => {
                for mp in child.children().filter(Node::is_element) {
                    let val = parse_bool(mp.text().unwrap_or("False"));
                    match mp.tag_name().name() {
                        "ProtectTitle" => meta.protect_title = val,
                        "ProtectUserName" => meta.protect_username = val,
                        "ProtectPassword" => meta.protect_password = val,
                        "ProtectURL" => meta.protect_url = val,
                        "ProtectNotes" => meta.protect_notes = val,
                        _ => {}
                    }
                }
            }
            "RecycleBinEnabled" => meta.recycle_bin_enabled = parse_bool(text),
            "RecycleBinUUID" => meta.recycle_bin_uuid = parse_uuid(text)?,
            "RecycleBinChanged" => meta.recycle_bin_changed = parse_timestamp(text)?,
            "HistoryMaxItems" => {
                if let Ok(n) = text.parse::<isize>() {
                    meta.history_max_items = usize::try_from(n).unwrap_or(10);
                }
            }
            "HistoryMaxSize" => {
                if let Ok(n) = text.parse::<i64>() {
                    meta.history_max_size = u64::try_from(n).unwrap_or(6_291_456);
                }
            }
            "Binaries" => {
                for bin_node in child
                    .children()
                    .filter(|n| n.is_element() && n.has_tag_name("Binary"))
                {
                    if let Some(id_str) = bin_node.attribute("ID")
                        && let Ok(id) = id_str.parse::<usize>()
                    {
                        let compressed = bin_node.attribute("Compressed").is_some_and(parse_bool);
                        let raw_b64: String = bin_node
                            .text()
                            .unwrap_or("")
                            .chars()
                            .filter(|c| !c.is_whitespace())
                            .collect();
                        let decoded = base64::engine::general_purpose::STANDARD
                            .decode(raw_b64.as_bytes())
                            .map_err(|e| {
                                RustPassError::Xml(format!("Invalid <Binary> Base64: {e}"))
                            })?;
                        let data = if compressed {
                            gunzip_bytes(&decoded)?
                        } else {
                            decoded
                        };
                        v3_binaries.insert(
                            id,
                            InnerBinary {
                                protected: false,
                                data,
                            },
                        );
                    }
                }
            }
            "CustomData" => {
                meta.custom_data = parse_custom_data_items(child);
            }
            "CustomIcons" => {
                for icon_node in child
                    .children()
                    .filter(|n| n.is_element() && n.has_tag_name("Icon"))
                {
                    let uuid_text = icon_node
                        .children()
                        .find(|n| n.has_tag_name("UUID"))
                        .and_then(|n| n.text())
                        .unwrap_or("");
                    let data_text = icon_node
                        .children()
                        .find(|n| n.has_tag_name("Data"))
                        .and_then(|n| n.text())
                        .unwrap_or("");
                    if uuid_text.is_empty() || data_text.is_empty() {
                        continue;
                    }
                    let Ok(bytes) = base64::engine::general_purpose::STANDARD
                        .decode(data_text.trim().as_bytes())
                    else {
                        continue;
                    };
                    if let Ok(uuid) = parse_uuid(uuid_text) {
                        meta.custom_icons.push(CustomIcon { uuid, data: bytes });
                    }
                }
            }
            "EntryTemplatesGroup" => meta.entry_templates_group = parse_uuid(text).ok(),
            "LastSelectedGroup" => meta.last_selected_group = parse_uuid(text).ok(),
            "LastTopVisibleGroup" => meta.last_top_visible_group = parse_uuid(text).ok(),
            _ => {}
        }
    }

    Ok(meta)
}

/// Parses a `<CustomData>` block of `<Item><Key/><Value/></Item>` pairs.
fn parse_custom_data_items(node: Node<'_, '_>) -> HashMap<String, String> {
    let mut out = HashMap::new();
    for item in node
        .children()
        .filter(|n| n.is_element() && n.has_tag_name("Item"))
    {
        let key = item
            .children()
            .find(|n| n.has_tag_name("Key"))
            .and_then(|n| n.text())
            .unwrap_or("")
            .to_string();
        let val = item
            .children()
            .find(|n| n.has_tag_name("Value"))
            .and_then(|n| n.text())
            .unwrap_or("")
            .to_string();
        if !key.is_empty() {
            out.insert(key, val);
        }
    }
    out
}

/// Writes a `<CustomData>` block when `data` is non-empty (no-op otherwise).
fn write_custom_data_block(xml: &mut String, depth: usize, data: &HashMap<String, String>) {
    if data.is_empty() {
        return;
    }
    let indent = "\t".repeat(depth);
    xml.push_str(&format!("{indent}<CustomData>\n"));
    for (key, val) in data {
        xml.push_str(&format!("{indent}\t<Item>\n"));
        write_tag(xml, depth + 2, "Key", key);
        write_tag(xml, depth + 2, "Value", val);
        xml.push_str(&format!("{indent}\t</Item>\n"));
    }
    xml.push_str(&format!("{indent}</CustomData>\n"));
}

fn parse_group(
    node: Node<'_, '_>,
    inner_stream: &mut InnerStream,
    v4_binaries: &[InnerBinary],
    v3_binaries: &HashMap<usize, InnerBinary>,
) -> Result<Group> {
    let mut group = Group::new("Group");

    // Traverse children in exact XML document order so InnerStream stays strictly synchronized!
    for child in node.children().filter(Node::is_element) {
        let text = child.text().unwrap_or("").trim();
        match child.tag_name().name() {
            "UUID" => group.uuid = parse_uuid(text)?,
            "Name" => group.name = child.text().unwrap_or("").to_string(),
            "Notes" => group.notes = child.text().unwrap_or("").to_string(),
            "IconID" => group.icon_id = text.parse().unwrap_or(48),
            "Times" => group.times = parse_times(child)?,
            "PreviousParentGroup" => group.previous_parent_group = parse_uuid(text).ok(),
            "CustomData" => group.custom_data = parse_custom_data_items(child),
            "IsExpanded" => group.is_expanded = parse_bool(text),
            "DefaultAutoTypeSequence" => {
                group.default_autotype_sequence = child.text().unwrap_or("").to_string();
            }
            "EnableAutoType" => group.enable_autotype = parse_opt_bool(text),
            "EnableSearching" => group.enable_searching = parse_opt_bool(text),
            "Entry" => {
                let entry = parse_entry(child, inner_stream, v4_binaries, v3_binaries)?;
                group.entries.push(entry);
            }
            "Group" => {
                let sub = parse_group(child, inner_stream, v4_binaries, v3_binaries)?;
                group.children.push(sub);
            }
            _ => {}
        }
    }

    Ok(group)
}

fn parse_entry(
    node: Node<'_, '_>,
    inner_stream: &mut InnerStream,
    v4_binaries: &[InnerBinary],
    v3_binaries: &HashMap<usize, InnerBinary>,
) -> Result<Entry> {
    let mut entry = Entry::new("");

    for child in node.children().filter(Node::is_element) {
        let text = child.text().unwrap_or("").trim();
        match child.tag_name().name() {
            "UUID" => entry.uuid = parse_uuid(text)?,
            "IconID" => entry.icon_id = text.parse().unwrap_or(0),
            "ForegroundColor" => entry.foreground_color = text.to_string(),
            "BackgroundColor" => entry.background_color = text.to_string(),
            "OverrideURL" => entry.override_url = child.text().unwrap_or("").to_string(),
            "Tags" => {
                entry.tags = text
                    .split([',', ';'])
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "Times" => entry.times = parse_times(child)?,
            "QualityCheck" => entry.quality_check = Some(parse_bool(text)),
            "CustomData" => entry.custom_data = parse_custom_data_items(child),
            "String" => {
                let key = child
                    .children()
                    .find(|n| n.has_tag_name("Key"))
                    .and_then(|n| n.text())
                    .unwrap_or("");
                let val_node = child.children().find(|n| n.has_tag_name("Value"));
                let is_stream_protected = val_node
                    .and_then(|v| v.attribute("Protected"))
                    .is_some_and(parse_bool);
                let protect_in_mem = is_stream_protected
                    || val_node
                        .and_then(|v| v.attribute("ProtectInMemory"))
                        .is_some_and(parse_bool);
                let raw_val = val_node.and_then(|v| v.text()).unwrap_or("");

                let decoded_val = if is_stream_protected {
                    inner_stream.decrypt_base64(raw_val)?
                } else {
                    zeroize::Zeroizing::new(raw_val.to_string())
                };

                match key {
                    "Title" => entry.title = decoded_val.as_str().to_string(),
                    "UserName" => entry.username = decoded_val.as_str().to_string(),
                    "Password" => entry.password = ProtectedString::new(decoded_val.as_str()),
                    "URL" => entry.url = decoded_val.as_str().to_string(),
                    "Notes" => entry.notes = decoded_val.as_str().to_string(),
                    "otp" => entry.otp = Some(ProtectedString::new(decoded_val.as_str())),
                    other if !other.is_empty() => {
                        entry.custom_attributes.push(CustomAttribute {
                            key: other.to_string(),
                            value: ProtectedString::new(decoded_val.as_str()),
                            protected: protect_in_mem,
                        });
                    }
                    _ => {}
                }
            }
            "Binary" => {
                let key = child
                    .children()
                    .find(|n| n.has_tag_name("Key"))
                    .and_then(|n| n.text())
                    .unwrap_or("attachment.bin")
                    .to_string();
                if let Some(val_node) = child.children().find(|n| n.has_tag_name("Value")) {
                    if let Some(ref_str) = val_node.attribute("Ref")
                        && let Ok(idx) = ref_str.parse::<usize>()
                    {
                        if let Some(bin) = v4_binaries.get(idx).or_else(|| v3_binaries.get(&idx)) {
                            entry.attachments.push(Attachment {
                                name: key,
                                data: bin.data.clone(),
                                protected: bin.protected,
                            });
                        }
                    } else if let Some(inline_text) = val_node.text() {
                        let clean: String =
                            inline_text.chars().filter(|c| !c.is_whitespace()).collect();
                        if let Ok(decoded) =
                            base64::engine::general_purpose::STANDARD.decode(clean.as_bytes())
                        {
                            let compressed =
                                val_node.attribute("Compressed").is_some_and(parse_bool);
                            let data = if compressed {
                                gunzip_bytes(&decoded)?
                            } else {
                                decoded
                            };
                            entry.attachments.push(Attachment {
                                name: key,
                                data,
                                protected: false,
                            });
                        }
                    }
                }
            }
            "AutoType" => {
                entry.auto_type = parse_autotype(child);
            }
            "History" => {
                for hist_node in child
                    .children()
                    .filter(|n| n.is_element() && n.has_tag_name("Entry"))
                {
                    let mut snap = parse_entry(hist_node, inner_stream, v4_binaries, v3_binaries)?;
                    snap.history.clear();
                    entry.history.push(snap);
                }
            }
            _ => {}
        }
    }

    Ok(entry)
}

fn parse_times(node: Node<'_, '_>) -> Result<Times> {
    let mut times = Times::default();
    for child in node.children().filter(Node::is_element) {
        let text = child.text().unwrap_or("").trim();
        match child.tag_name().name() {
            "CreationTime" => times.creation_time = parse_timestamp(text)?,
            "LastModificationTime" => times.last_modification_time = parse_timestamp(text)?,
            "LastAccessTime" => times.last_access_time = parse_timestamp(text)?,
            "ExpiryTime" => times.expiry_time = parse_timestamp(text)?,
            "Expires" => times.expires = parse_bool(text),
            "UsageCount" => times.usage_count = text.parse().unwrap_or(0),
            "LocationChanged" => times.location_changed = parse_timestamp(text)?,
            _ => {}
        }
    }
    Ok(times)
}

fn parse_autotype(node: Node<'_, '_>) -> AutoType {
    let mut at = AutoType::default();
    for child in node.children().filter(Node::is_element) {
        let text = child.text().unwrap_or("").trim();
        match child.tag_name().name() {
            "Enabled" => at.enabled = parse_bool(text),
            "DataTransferObfuscation" => at.obfuscation = text.parse().unwrap_or(0),
            "DefaultSequence" => at.default_sequence = child.text().unwrap_or("").to_string(),
            "Association" => {
                let win = child
                    .children()
                    .find(|n| n.has_tag_name("Window"))
                    .and_then(|n| n.text())
                    .unwrap_or("")
                    .to_string();
                let seq = child
                    .children()
                    .find(|n| n.has_tag_name("KeystrokeSequence"))
                    .and_then(|n| n.text())
                    .unwrap_or("")
                    .to_string();
                at.associations.push(AutoTypeAssociation {
                    window: win,
                    keystroke_sequence: seq,
                });
            }
            _ => {}
        }
    }
    at
}

fn parse_deleted_object(node: Node<'_, '_>) -> Result<DeletedObject> {
    let uuid_str = node
        .children()
        .find(|n| n.has_tag_name("UUID"))
        .and_then(|n| n.text())
        .ok_or_else(|| RustPassError::Xml("DeletedObject missing UUID".to_string()))?;
    let time_str = node
        .children()
        .find(|n| n.has_tag_name("DeletionTime"))
        .and_then(|n| n.text())
        .unwrap_or("");
    Ok(DeletedObject {
        uuid: parse_uuid(uuid_str.trim())?,
        deletion_time: parse_timestamp(time_str.trim())?,
    })
}

/// Options controlling `<KeePassFile>` XML serialization.
#[derive(Debug, Clone, Copy)]
pub struct XmlSerializeMode {
    /// `true` for KDBX 4 encrypted XML (Base64 `i64 LE` timestamps, Inner Header `Ref` attachments);
    /// `false` for KDBX 3.1 or plain XML export (ISO-8601 timestamps).
    pub is_kdbx4: bool,
    /// `true` when serializing inside an encrypted `.kdbx` container (`Protected="True"` Base64);
    /// `false` when exporting plaintext XML (`ProtectInMemory="True"` cleartext).
    pub encrypt_protected: bool,
}

/// Serializes `db` into UTF-8 `<KeePassFile>` XML and returns `(xml_string, deduplicated_binaries)`.
///
/// The XML string contains every vault secret in cleartext, so it is returned
/// wrapped in [`Zeroizing`] and callers must keep it that way.
pub fn serialize_keepass_xml(
    db: &Database,
    mode: XmlSerializeMode,
    inner_stream: &mut InnerStream,
) -> Result<(Zeroizing<String>, Vec<InnerBinary>)> {
    // 1. Collect and deduplicate binary attachments across all entries + history
    let mut binaries: Vec<InnerBinary> = Vec::new();
    let mut bin_index_map: HashMap<Vec<u8>, usize> = HashMap::new();
    collect_binaries_from_group(&db.root, &mut binaries, &mut bin_index_map);

    let mut xml = String::with_capacity(8192);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n");
    xml.push_str("<KeePassFile>\n");

    // <Meta>
    write_meta(&mut xml, &db.meta, mode, &binaries)?;

    // <Root>
    xml.push_str("\t<Root>\n");
    write_group(
        &mut xml,
        &db.root,
        2,
        &db.meta,
        mode,
        inner_stream,
        &bin_index_map,
    );

    if db.deleted_objects.is_empty() {
        xml.push_str("\t\t<DeletedObjects/>\n");
    } else {
        xml.push_str("\t\t<DeletedObjects>\n");
        for del in &db.deleted_objects {
            xml.push_str("\t\t\t<DeletedObject>\n");
            xml.push_str(&format!("\t\t\t\t<UUID>{}</UUID>\n", encode_uuid(del.uuid)));
            xml.push_str(&format!(
                "\t\t\t\t<DeletionTime>{}</DeletionTime>\n",
                format_timestamp(del.deletion_time, mode.is_kdbx4 && mode.encrypt_protected)
            ));
            xml.push_str("\t\t\t</DeletedObject>\n");
        }
        xml.push_str("\t\t</DeletedObjects>\n");
    }

    xml.push_str("\t</Root>\n");
    xml.push_str("</KeePassFile>\n");

    Ok((Zeroizing::new(xml), binaries))
}

fn collect_binaries_from_group(
    group: &Group,
    pool: &mut Vec<InnerBinary>,
    map: &mut HashMap<Vec<u8>, usize>,
) {
    for entry in &group.entries {
        collect_binaries_from_entry(entry, pool, map);
        for hist in &entry.history {
            collect_binaries_from_entry(hist, pool, map);
        }
    }
    for child in &group.children {
        collect_binaries_from_group(child, pool, map);
    }
}

fn collect_binaries_from_entry(
    entry: &Entry,
    pool: &mut Vec<InnerBinary>,
    map: &mut HashMap<Vec<u8>, usize>,
) {
    for att in &entry.attachments {
        if !map.contains_key(&att.data) {
            let idx = pool.len();
            pool.push(InnerBinary {
                protected: att.protected,
                data: att.data.clone(),
            });
            map.insert(att.data.clone(), idx);
        }
    }
}

fn write_meta(
    xml: &mut String,
    meta: &Meta,
    mode: XmlSerializeMode,
    binaries: &[InnerBinary],
) -> Result<()> {
    let bin_ts = mode.is_kdbx4 && mode.encrypt_protected;
    xml.push_str("\t<Meta>\n");
    write_tag(xml, 2, "Generator", &meta.generator);
    write_tag(xml, 2, "DatabaseName", &meta.database_name);
    write_tag(
        xml,
        2,
        "DatabaseNameChanged",
        &format_timestamp(meta.database_name_changed, bin_ts),
    );
    write_tag(xml, 2, "DatabaseDescription", &meta.database_description);
    write_tag(
        xml,
        2,
        "DatabaseDescriptionChanged",
        &format_timestamp(meta.database_description_changed, bin_ts),
    );
    write_tag(xml, 2, "DefaultUserName", &meta.default_username);
    write_tag(
        xml,
        2,
        "DefaultUserNameChanged",
        &format_timestamp(meta.default_username_changed, bin_ts),
    );
    write_tag(
        xml,
        2,
        "MaintenanceHistoryDays",
        &meta.maintenance_history_days.to_string(),
    );
    write_tag(xml, 2, "Color", &meta.color);
    write_tag(
        xml,
        2,
        "MasterKeyChanged",
        &format_timestamp(meta.master_key_changed, bin_ts),
    );
    write_tag(xml, 2, "MasterKeyChangeRec", "-1");
    write_tag(xml, 2, "MasterKeyChangeForce", "-1");

    xml.push_str("\t\t<MemoryProtection>\n");
    write_tag(xml, 3, "ProtectTitle", bool_str(meta.protect_title));
    write_tag(xml, 3, "ProtectUserName", bool_str(meta.protect_username));
    write_tag(xml, 3, "ProtectPassword", bool_str(meta.protect_password));
    write_tag(xml, 3, "ProtectURL", bool_str(meta.protect_url));
    write_tag(xml, 3, "ProtectNotes", bool_str(meta.protect_notes));
    xml.push_str("\t\t</MemoryProtection>\n");

    if meta.custom_icons.is_empty() {
        xml.push_str("\t\t<CustomIcons/>\n");
    } else {
        xml.push_str("\t\t<CustomIcons>\n");
        for icon in &meta.custom_icons {
            xml.push_str("\t\t\t<Icon>\n");
            write_tag(xml, 4, "UUID", &encode_uuid(icon.uuid));
            write_tag(
                xml,
                4,
                "Data",
                &base64::engine::general_purpose::STANDARD.encode(&icon.data),
            );
            xml.push_str("\t\t\t</Icon>\n");
        }
        xml.push_str("\t\t</CustomIcons>\n");
    }
    write_tag(
        xml,
        2,
        "RecycleBinEnabled",
        bool_str(meta.recycle_bin_enabled),
    );
    write_tag(
        xml,
        2,
        "RecycleBinUUID",
        &encode_uuid(meta.recycle_bin_uuid),
    );
    write_tag(
        xml,
        2,
        "RecycleBinChanged",
        &format_timestamp(meta.recycle_bin_changed, bin_ts),
    );
    write_tag(
        xml,
        2,
        "EntryTemplatesGroup",
        &encode_uuid(meta.entry_templates_group.unwrap_or(Uuid::nil())),
    );
    write_tag(
        xml,
        2,
        "EntryTemplatesGroupChanged",
        &format_timestamp(meta.recycle_bin_changed, bin_ts),
    );
    write_tag(
        xml,
        2,
        "LastSelectedGroup",
        &encode_uuid(meta.last_selected_group.unwrap_or(Uuid::nil())),
    );
    write_tag(
        xml,
        2,
        "LastTopVisibleGroup",
        &encode_uuid(meta.last_top_visible_group.unwrap_or(Uuid::nil())),
    );
    write_tag(
        xml,
        2,
        "HistoryMaxItems",
        &meta.history_max_items.to_string(),
    );
    write_tag(xml, 2, "HistoryMaxSize", &meta.history_max_size.to_string());

    // In KDBX 3.1 or plain XML export, attachments live in <Meta><Binaries>
    if !mode.is_kdbx4 {
        if binaries.is_empty() {
            xml.push_str("\t\t<Binaries/>\n");
        } else {
            xml.push_str("\t\t<Binaries>\n");
            for (idx, bin) in binaries.iter().enumerate() {
                let gz = gzip_bytes(&bin.data)?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(&gz);
                xml.push_str(&format!(
                    "\t\t\t<Binary ID=\"{idx}\" Compressed=\"True\">{b64}</Binary>\n"
                ));
            }
            xml.push_str("\t\t</Binaries>\n");
        }
    }

    if meta.custom_data.is_empty() {
        xml.push_str("\t\t<CustomData/>\n");
    } else {
        xml.push_str("\t\t<CustomData>\n");
        let mut sorted: Vec<(&String, &String)> = meta.custom_data.iter().collect();
        sorted.sort_by_key(|(k, _)| *k);
        for (k, v) in sorted {
            xml.push_str("\t\t\t<Item>\n");
            write_tag(xml, 4, "Key", k);
            write_tag(xml, 4, "Value", v);
            xml.push_str("\t\t\t</Item>\n");
        }
        xml.push_str("\t\t</CustomData>\n");
    }

    xml.push_str("\t</Meta>\n");
    Ok(())
}

fn write_group(
    xml: &mut String,
    group: &Group,
    depth: usize,
    meta: &Meta,
    mode: XmlSerializeMode,
    inner_stream: &mut InnerStream,
    bin_index_map: &HashMap<Vec<u8>, usize>,
) {
    let indent = "\t".repeat(depth);
    let bin_ts = mode.is_kdbx4 && mode.encrypt_protected;

    xml.push_str(&format!("{indent}<Group>\n"));
    write_tag(xml, depth + 1, "UUID", &encode_uuid(group.uuid));
    write_tag(xml, depth + 1, "Name", &group.name);
    write_tag(xml, depth + 1, "Notes", &group.notes);
    write_tag(xml, depth + 1, "IconID", &group.icon_id.to_string());
    write_times(xml, depth + 1, &group.times, bin_ts);
    write_tag(xml, depth + 1, "IsExpanded", bool_str(group.is_expanded));
    write_tag(
        xml,
        depth + 1,
        "DefaultAutoTypeSequence",
        &group.default_autotype_sequence,
    );
    write_tag(
        xml,
        depth + 1,
        "EnableAutoType",
        opt_bool_str(group.enable_autotype),
    );
    write_tag(
        xml,
        depth + 1,
        "EnableSearching",
        opt_bool_str(group.enable_searching),
    );
    write_tag(
        xml,
        depth + 1,
        "LastTopVisibleEntry",
        &encode_uuid(Uuid::nil()),
    );
    if let Some(prev) = group.previous_parent_group {
        write_tag(xml, depth + 1, "PreviousParentGroup", &encode_uuid(prev));
    }
    write_custom_data_block(xml, depth + 1, &group.custom_data);

    for entry in &group.entries {
        write_entry(
            xml,
            entry,
            depth + 1,
            meta,
            mode,
            inner_stream,
            bin_index_map,
            true,
        );
    }
    for child in &group.children {
        write_group(
            xml,
            child,
            depth + 1,
            meta,
            mode,
            inner_stream,
            bin_index_map,
        );
    }

    xml.push_str(&format!("{indent}</Group>\n"));
}

#[expect(
    clippy::too_many_arguments,
    reason = "Recursive XML writer carries indentation, metadata, mode, stream state, and attachment pool"
)]
fn write_entry(
    xml: &mut String,
    entry: &Entry,
    depth: usize,
    meta: &Meta,
    mode: XmlSerializeMode,
    inner_stream: &mut InnerStream,
    bin_index_map: &HashMap<Vec<u8>, usize>,
    include_history: bool,
) {
    let indent = "\t".repeat(depth);
    let bin_ts = mode.is_kdbx4 && mode.encrypt_protected;

    xml.push_str(&format!("{indent}<Entry>\n"));
    write_tag(xml, depth + 1, "UUID", &encode_uuid(entry.uuid));
    write_tag(xml, depth + 1, "IconID", &entry.icon_id.to_string());
    write_tag(xml, depth + 1, "ForegroundColor", &entry.foreground_color);
    write_tag(xml, depth + 1, "BackgroundColor", &entry.background_color);
    write_tag(xml, depth + 1, "OverrideURL", &entry.override_url);
    write_tag(xml, depth + 1, "Tags", &entry.tags.join(","));
    write_times(xml, depth + 1, &entry.times, bin_ts);

    write_string_kv(
        xml,
        depth + 1,
        "Notes",
        &entry.notes,
        meta.protect_notes,
        mode.encrypt_protected,
        inner_stream,
    );
    write_string_kv(
        xml,
        depth + 1,
        "Password",
        entry.password.as_str(),
        meta.protect_password,
        mode.encrypt_protected,
        inner_stream,
    );
    write_string_kv(
        xml,
        depth + 1,
        "Title",
        &entry.title,
        meta.protect_title,
        mode.encrypt_protected,
        inner_stream,
    );
    write_string_kv(
        xml,
        depth + 1,
        "URL",
        &entry.url,
        meta.protect_url,
        mode.encrypt_protected,
        inner_stream,
    );
    write_string_kv(
        xml,
        depth + 1,
        "UserName",
        &entry.username,
        meta.protect_username,
        mode.encrypt_protected,
        inner_stream,
    );
    if let Some(ref otp) = entry.otp {
        write_string_kv(
            xml,
            depth + 1,
            "otp",
            otp.as_str(),
            true,
            mode.encrypt_protected,
            inner_stream,
        );
    }
    for attr in &entry.custom_attributes {
        write_string_kv(
            xml,
            depth + 1,
            &attr.key,
            attr.value.as_str(),
            attr.protected,
            mode.encrypt_protected,
            inner_stream,
        );
    }

    for att in &entry.attachments {
        if let Some(&ref_id) = bin_index_map.get(&att.data) {
            let sub_indent = "\t".repeat(depth + 1);
            xml.push_str(&format!("{sub_indent}<Binary>\n"));
            write_tag(xml, depth + 2, "Key", &att.name);
            xml.push_str(&format!("{sub_indent}\t<Value Ref=\"{ref_id}\"/>\n"));
            xml.push_str(&format!("{sub_indent}</Binary>\n"));
        }
    }

    if let Some(qc) = entry.quality_check {
        write_tag(xml, depth + 1, "QualityCheck", bool_str(qc));
    }
    write_custom_data_block(xml, depth + 1, &entry.custom_data);

    // <AutoType>
    let at_indent = "\t".repeat(depth + 1);
    xml.push_str(&format!("{at_indent}<AutoType>\n"));
    write_tag(xml, depth + 2, "Enabled", bool_str(entry.auto_type.enabled));
    write_tag(
        xml,
        depth + 2,
        "DataTransferObfuscation",
        &entry.auto_type.obfuscation.to_string(),
    );
    write_tag(
        xml,
        depth + 2,
        "DefaultSequence",
        &entry.auto_type.default_sequence,
    );
    for assoc in &entry.auto_type.associations {
        xml.push_str(&format!("{at_indent}\t<Association>\n"));
        write_tag(xml, depth + 3, "Window", &assoc.window);
        write_tag(
            xml,
            depth + 3,
            "KeystrokeSequence",
            &assoc.keystroke_sequence,
        );
        xml.push_str(&format!("{at_indent}\t</Association>\n"));
    }
    xml.push_str(&format!("{at_indent}</AutoType>\n"));

    if include_history {
        if entry.history.is_empty() {
            xml.push_str(&format!("{at_indent}<History/>\n"));
        } else {
            xml.push_str(&format!("{at_indent}<History>\n"));
            for snap in &entry.history {
                write_entry(
                    xml,
                    snap,
                    depth + 2,
                    meta,
                    mode,
                    inner_stream,
                    bin_index_map,
                    false,
                );
            }
            xml.push_str(&format!("{at_indent}</History>\n"));
        }
    }

    xml.push_str(&format!("{indent}</Entry>\n"));
}

fn write_times(xml: &mut String, depth: usize, times: &Times, binary_ts: bool) {
    let indent = "\t".repeat(depth);
    xml.push_str(&format!("{indent}<Times>\n"));
    write_tag(
        xml,
        depth + 1,
        "LastModificationTime",
        &format_timestamp(times.last_modification_time, binary_ts),
    );
    write_tag(
        xml,
        depth + 1,
        "CreationTime",
        &format_timestamp(times.creation_time, binary_ts),
    );
    write_tag(
        xml,
        depth + 1,
        "LastAccessTime",
        &format_timestamp(times.last_access_time, binary_ts),
    );
    write_tag(
        xml,
        depth + 1,
        "ExpiryTime",
        &format_timestamp(times.expiry_time, binary_ts),
    );
    write_tag(xml, depth + 1, "Expires", bool_str(times.expires));
    write_tag(xml, depth + 1, "UsageCount", &times.usage_count.to_string());
    write_tag(
        xml,
        depth + 1,
        "LocationChanged",
        &format_timestamp(times.location_changed, binary_ts),
    );
    xml.push_str(&format!("{indent}</Times>\n"));
}

fn write_string_kv(
    xml: &mut String,
    depth: usize,
    key: &str,
    value: &str,
    protected: bool,
    encrypt_protected: bool,
    inner_stream: &mut InnerStream,
) {
    let indent = "\t".repeat(depth);
    xml.push_str(&format!("{indent}<String>\n"));
    write_tag(xml, depth + 1, "Key", key);
    if protected && encrypt_protected {
        let b64 = inner_stream.encrypt_to_base64(value);
        if b64.is_empty() {
            xml.push_str(&format!("{indent}\t<Value Protected=\"True\"/>\n"));
        } else {
            xml.push_str(&format!(
                "{indent}\t<Value Protected=\"True\">{b64}</Value>\n"
            ));
        }
    } else if protected {
        let escaped = escape_xml(value);
        if escaped.is_empty() {
            xml.push_str(&format!("{indent}\t<Value ProtectInMemory=\"True\"/>\n"));
        } else {
            xml.push_str(&format!(
                "{indent}\t<Value ProtectInMemory=\"True\">{escaped}</Value>\n"
            ));
        }
    } else {
        write_tag(xml, depth + 1, "Value", value);
    }
    xml.push_str(&format!("{indent}</String>\n"));
}

fn write_tag(xml: &mut String, depth: usize, tag: &str, value: &str) {
    let indent = "\t".repeat(depth);
    let escaped = escape_xml(value);
    if escaped.is_empty() {
        xml.push_str(&format!("{indent}<{tag}/>\n"));
    } else {
        xml.push_str(&format!("{indent}<{tag}>{escaped}</{tag}>\n"));
    }
}

/// Escapes XML special characters (`&`, `<`, `>`, `"`, `'`).
///
/// Characters forbidden by XML 1.0 (C0 controls other than tab/LF/CR, and the
/// `U+FFFE`/`U+FFFF` non-characters) are dropped: emitting them verbatim would
/// produce a document that no XML parser (including this one and KeePassXC)
/// can read back, silently bricking the vault on the next save.
#[must_use]
pub fn escape_xml(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\u{FFFE}' | '\u{FFFF}' => {}
            c if (c as u32) < 0x20 && !matches!(c, '\t' | '\n' | '\r') => {}
            c => out.push(c),
        }
    }
    out
}

fn bool_str(v: bool) -> &'static str {
    if v { "True" } else { "False" }
}

fn opt_bool_str(v: Option<bool>) -> &'static str {
    match v {
        None => "null",
        Some(true) => "True",
        Some(false) => "False",
    }
}

fn parse_bool(s: &str) -> bool {
    s.eq_ignore_ascii_case("true") || s == "1"
}

fn parse_opt_bool(s: &str) -> Option<bool> {
    if s.eq_ignore_ascii_case("null") || s.is_empty() {
        None
    } else {
        Some(parse_bool(s))
    }
}

fn parse_uuid(b64: &str) -> Result<Uuid> {
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.is_empty() {
        // An omitted UUID means "none" in KeePass semantics (e.g. `<RecycleBinUUID/>`).
        return Ok(Uuid::nil());
    }
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean.as_bytes())
        .map_err(|e| RustPassError::Xml(format!("invalid UUID base64: {e}")))?;
    let arr: [u8; 16] = bytes.as_slice().try_into().map_err(|_| {
        RustPassError::Xml(format!("UUID must decode to 16 bytes, got {}", bytes.len()))
    })?;
    Ok(Uuid::from_bytes(arr))
}

fn encode_uuid(uuid: Uuid) -> String {
    base64::engine::general_purpose::STANDARD.encode(uuid.as_bytes())
}

fn parse_timestamp(s: &str) -> Result<DateTime<Utc>> {
    if s.is_empty() {
        // An omitted time is "unknown": deterministic epoch, never `Utc::now()`
        // (which would churn the data on every open and could flip expiry).
        return Ok(DateTime::from_timestamp(0, 0).unwrap_or_default());
    }
    if (s.contains('-') || s.contains(':'))
        && let Ok(dt) = DateTime::parse_from_rfc3339(s)
    {
        return Ok(dt.with_timezone(&Utc));
    }
    if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s.as_bytes())
        && let Ok(arr) = <[u8; 8]>::try_from(bytes.as_slice())
    {
        let kdbx_secs = i64::from_le_bytes(arr);
        let unix_secs = kdbx_secs.saturating_sub(KDBX4_EPOCH_OFFSET_SECS);
        if let Some(dt) = Utc.timestamp_opt(unix_secs, 0).single() {
            return Ok(dt);
        }
    }
    Err(RustPassError::Xml(format!(
        "unparseable KeePass timestamp: {s:?}"
    )))
}

fn format_timestamp(dt: DateTime<Utc>, binary_kdbx4: bool) -> String {
    if binary_kdbx4 {
        let secs = dt.timestamp().saturating_add(KDBX4_EPOCH_OFFSET_SECS);
        base64::engine::general_purpose::STANDARD.encode(secs.to_le_bytes())
    } else {
        dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
    }
}

/// Safety cap on decompressed inner payloads (1 GiB).
pub const MAX_DECOMPRESSED_BYTES: u64 = 1 << 30;

/// Decompresses a GZip byte buffer, capped at [`MAX_DECOMPRESSED_BYTES`].
///
/// The payload comes from a (possibly shared or hostile) vault: without a cap,
/// a tiny ciphertext can expand into an out-of-memory abort.
pub fn gunzip_bytes(compressed: &[u8]) -> Result<Vec<u8>> {
    gunzip_bytes_capped(compressed, MAX_DECOMPRESSED_BYTES)
}

/// [`gunzip_bytes`] with an explicit cap, so the cap mechanism is testable cheaply.
pub fn gunzip_bytes_capped(compressed: &[u8], max_bytes: u64) -> Result<Vec<u8>> {
    let decoder = GzDecoder::new(compressed);
    let mut out = Vec::new();
    decoder
        .take(max_bytes + 1)
        .read_to_end(&mut out)
        .map_err(|e| RustPassError::CorruptedFormat(format!("GZip decompression error: {e}")))?;
    if out.len() as u64 > max_bytes {
        return Err(RustPassError::CorruptedFormat(
            "Decompressed payload exceeds the safety limit".to_string(),
        ));
    }
    Ok(out)
}

/// Compresses `raw` bytes with GZip.
pub fn gzip_bytes(raw: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(raw)?;
    Ok(encoder.finish()?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::DateTime;
    use uuid::Uuid;

    fn none_stream() -> InnerStream {
        InnerStream::new(crate::model::InnerStreamAlgorithm::None, &[])
    }

    #[test]
    fn escape_xml_drops_chars_forbidden_by_xml_1_0() {
        assert_eq!(escape_xml("a\u{0001}b\u{0002}c"), "abc");
        assert_eq!(escape_xml("x\u{FFFE}y\u{FFFF}z"), "xyz");
        // Permitted whitespace survives.
        assert_eq!(escape_xml("tab\tlf\nr\r"), "tab\tlf\nr\r");
        assert_eq!(escape_xml("<&\"'>"), "&lt;&amp;&quot;&apos;&gt;");
    }

    #[test]
    fn control_char_in_field_survives_full_kdbx_roundtrip_sanitized() {
        use crate::crypto::kdf::MasterCredentials;
        use crate::model::{Database, Entry, KdfConfig};

        let mut db = Database::new("Sanitize Vault");
        let mut entry = Entry::new("CtrlField");
        entry.notes = "be\u{0001}ta".to_string();
        db.add_entry_at_path("G/CtrlField", entry).expect("add");
        db.kdf = KdfConfig::AesKdf {
            rounds: 1_000,
            seed: [9u8; 32],
        };
        let creds = MasterCredentials::with_password("pw");
        let raw = db.to_kdbx_bytes(&creds).expect("encode");
        let reopened = Database::from_kdbx_bytes(&raw, &creds).expect("decode");
        assert_eq!(
            reopened.resolve_entry("G/CtrlField").expect("entry").notes,
            "beta"
        );
    }

    #[test]
    fn gzip_decompression_cap_rejects_oversized_payload() {
        let big = vec![0u8; 8192];
        let gz = gzip_bytes(&big).expect("gzip");
        assert!(gunzip_bytes_capped(&gz, 4096).is_err());
        assert_eq!(gunzip_bytes_capped(&gz, 16384).expect("gunzip").len(), 8192);
    }

    #[test]
    fn malformed_uuid_and_timestamp_rejected() {
        let bad_uuid = "<KeePassFile><Root><Group><UUID>!!!not-base64!!!</UUID><Name>g</Name></Group></Root></KeePassFile>";
        assert!(parse_keepass_xml(bad_uuid, &mut none_stream(), &[]).is_err());
        let bad_time = "<KeePassFile><Root><Group><UUID/><Name>g</Name><Times><CreationTime>garbage!!</CreationTime></Times></Group></Root></KeePassFile>";
        assert!(parse_keepass_xml(bad_time, &mut none_stream(), &[]).is_err());
    }

    #[test]
    fn kdbx41_fidelity_roundtrip() {
        use crate::crypto::kdf::MasterCredentials;
        use crate::model::{CustomIcon, Database, Entry, KdfConfig, Meta};

        let mut db = Database::new("Fidelity");
        db.meta.custom_icons.push(CustomIcon {
            uuid: uuid::Uuid::from_u128(0xAAAA_1111),
            data: b"PNGICON-bytes".to_vec(),
        });
        db.meta.entry_templates_group = Some(uuid::Uuid::from_u128(0xBB22));
        db.meta.last_selected_group = Some(uuid::Uuid::from_u128(0xCC33));
        db.meta.last_top_visible_group = Some(uuid::Uuid::from_u128(0xDD44));
        db.meta
            .custom_data
            .insert("meta.key".into(), "meta.val".into());

        let mut entry = Entry::new("KeePassXC-Browser");
        entry.quality_check = Some(false);
        entry
            .custom_data
            .insert("KeePassXC-Browser Settings".into(), "{\"id\":42}".into());
        db.add_entry_at_path("Web/KeePassXC-Browser", entry)
            .expect("add");

        let group_id = db.resolve_group("Web").expect("grp").uuid;
        db.root
            .find_group_by_uuid_mut(group_id)
            .expect("grp mut")
            .previous_parent_group = Some(uuid::Uuid::from_u128(0xEE55));
        db.root
            .find_group_by_uuid_mut(group_id)
            .expect("grp mut")
            .custom_data
            .insert("grp.key".into(), "grp.val".into());

        db.kdf = KdfConfig::AesKdf {
            rounds: 1_000,
            seed: [4u8; 32],
        };
        let creds = MasterCredentials::with_password("pw");
        let raw = db.to_kdbx_bytes(&creds).expect("encode");
        let reopened = Database::from_kdbx_bytes(&raw, &creds).expect("decode");

        let m: &Meta = &reopened.meta;
        assert_eq!(m.custom_icons.len(), 1);
        assert_eq!(m.custom_icons[0].uuid, uuid::Uuid::from_u128(0xAAAA_1111));
        assert_eq!(m.custom_icons[0].data, b"PNGICON-bytes");
        assert_eq!(m.entry_templates_group, Some(uuid::Uuid::from_u128(0xBB22)));
        assert_eq!(m.last_selected_group, Some(uuid::Uuid::from_u128(0xCC33)));
        assert_eq!(
            m.last_top_visible_group,
            Some(uuid::Uuid::from_u128(0xDD44))
        );
        assert_eq!(
            m.custom_data.get("meta.key").map(String::as_str),
            Some("meta.val")
        );

        let e = reopened
            .resolve_entry("Web/KeePassXC-Browser")
            .expect("entry");
        assert_eq!(e.quality_check, Some(false));
        assert_eq!(
            e.custom_data
                .get("KeePassXC-Browser Settings")
                .map(String::as_str),
            Some("{\"id\":42}")
        );
        let g = reopened.resolve_group("Web").expect("grp");
        assert_eq!(g.previous_parent_group, Some(uuid::Uuid::from_u128(0xEE55)));
        assert_eq!(
            g.custom_data.get("grp.key").map(String::as_str),
            Some("grp.val")
        );
    }

    #[test]
    fn empty_uuid_is_nil_and_empty_timestamp_is_epoch() {
        let xml = "<KeePassFile><Root><Group><UUID/><Name>g</Name><Times><CreationTime/></Times></Group></Root></KeePassFile>";
        let (_, root, _) = parse_keepass_xml(xml, &mut none_stream(), &[]).expect("parse");
        assert_eq!(root.uuid, Uuid::nil());
        assert_eq!(
            root.times.creation_time,
            DateTime::from_timestamp(0, 0).expect("epoch")
        );
    }
}
