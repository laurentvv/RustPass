//! Domain model for KDBX 3.1 & 4.0 password vaults (`Database`, `Group`, `Entry`, `Meta`).

use crate::error::{Result, RustPassError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

/// Memory-zeroized secret string that redacts itself in `Debug` output.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProtectedString(Zeroizing<String>);

impl ProtectedString {
    /// Wraps a plaintext string inside a `Zeroizing<String>` allocation.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(Zeroizing::new(value.into()))
    }

    /// Borrows the underlying secret string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }

    /// Returns `true` if the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Length of the secret in UTF-8 bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl fmt::Debug for ProtectedString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedString(***)")
    }
}

impl From<&str> for ProtectedString {
    fn from(s: &str) -> Self {
        Self::new(s)
    }
}

impl From<String> for ProtectedString {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

impl Serialize for ProtectedString {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProtectedString {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(Self::new(s))
    }
}

impl Zeroize for ProtectedString {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

/// KDBX container format version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdbxVersion {
    /// Legacy KDBX 3.1 (AES-KDF, Hashed Block Stream, XML `<Binaries>`).
    V3_1,
    /// Modern KDBX 4.0 / 4.1 (VariantDictionary KDF, HMAC-SHA-256 Block Stream, Inner Header).
    V4_0 {
        /// Minor version (`0` for KDBX 4.0, `1` for KDBX 4.1).
        minor: u16,
    },
}

impl Default for KdbxVersion {
    fn default() -> Self {
        Self::V4_0 { minor: 0 }
    }
}

impl KdbxVersion {
    /// Human-readable label (`"KDBX 4.0"`, `"KDBX 4.1"`, `"KDBX 3.1"`).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::V3_1 => "KDBX 3.1",
            Self::V4_0 { minor: 0 } => "KDBX 4.0",
            Self::V4_0 { .. } => "KDBX 4.1",
        }
    }
}

/// Outer payload symmetric cipher algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum CipherAlgorithm {
    /// RFC 8439 ChaCha20 256-bit stream cipher (default in modern KDBX 4).
    #[default]
    ChaCha20,
    /// AES-256-CBC with PKCS#7 padding (supported in both KDBX 3.1 and KDBX 4).
    Aes256Cbc,
}

impl CipherAlgorithm {
    /// Canonical KDBX 16-byte Cipher UUID.
    #[must_use]
    pub const fn uuid_bytes(self) -> [u8; 16] {
        match self {
            Self::Aes256Cbc => [
                0x31, 0xc1, 0xf2, 0xe6, 0xbf, 0x71, 0x43, 0x50, 0xbe, 0x58, 0x05, 0x21, 0x6a, 0xfc,
                0x5a, 0xff,
            ],
            Self::ChaCha20 => [
                0xd6, 0x03, 0x8a, 0x2b, 0x8b, 0x6f, 0x4c, 0xb5, 0xa5, 0x24, 0x33, 0x9a, 0x31, 0xdb,
                0xb5, 0x9a,
            ],
        }
    }

    /// Parses a 16-byte KDBX Cipher UUID.
    pub fn from_uuid_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes == Self::Aes256Cbc.uuid_bytes() {
            Ok(Self::Aes256Cbc)
        } else if bytes == Self::ChaCha20.uuid_bytes() {
            Ok(Self::ChaCha20)
        } else {
            Err(RustPassError::UnsupportedFeature(format!(
                "Unsupported KDBX cipher UUID: {}",
                hex::encode(bytes)
            )))
        }
    }

    /// Required outer IV / nonce byte length.
    #[must_use]
    pub const fn iv_len(self) -> usize {
        match self {
            Self::Aes256Cbc => 16,
            Self::ChaCha20 => 12,
        }
    }

    /// Human-readable display name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChaCha20 => "ChaCha20 (256-bit)",
            Self::Aes256Cbc => "AES-256-CBC",
        }
    }
}

/// Inner random stream cipher used to XOR-mask `<Value Protected="True">` XML nodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum InnerStreamAlgorithm {
    /// No inner stream encryption (`0`).
    None,
    /// Salsa20 with 8-byte fixed KDBX nonce (`2`, KDBX 3.1 default).
    Salsa20,
    /// RFC 8439 ChaCha20 with SHA-512 key/nonce split (`3`, KDBX 4 default).
    #[default]
    ChaCha20,
}

impl InnerStreamAlgorithm {
    /// KDBX numeric stream identifier.
    #[must_use]
    pub const fn id(self) -> u32 {
        match self {
            Self::None => 0,
            Self::Salsa20 => 2,
            Self::ChaCha20 => 3,
        }
    }

    /// Parses KDBX numeric stream identifier.
    pub fn from_id(id: u32) -> Result<Self> {
        match id {
            0 => Ok(Self::None),
            2 => Ok(Self::Salsa20),
            3 => Ok(Self::ChaCha20),
            other => Err(RustPassError::UnsupportedFeature(format!(
                "Unsupported inner stream cipher ID: {other}"
            ))),
        }
    }
}

/// Argon2 variant for KDBX 4 key derivation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Argon2Variant {
    /// Argon2d (`ef636ddf-8c29-444b-91f7-a9a403e30a0c`).
    Argon2d,
    /// Argon2id (`9e298b19-56db-4773-b23d-fc3ec6f0a1e6`, recommended hybrid).
    #[default]
    Argon2id,
}

impl Argon2Variant {
    /// Canonical 16-byte KDF `$UUID`.
    #[must_use]
    pub const fn uuid_bytes(self) -> [u8; 16] {
        match self {
            Self::Argon2d => [
                0xef, 0x63, 0x6d, 0xdf, 0x8c, 0x29, 0x44, 0x4b, 0x91, 0xf7, 0xa9, 0xa4, 0x03, 0xe3,
                0x0a, 0x0c,
            ],
            Self::Argon2id => [
                0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73, 0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0,
                0xa1, 0xe6,
            ],
        }
    }
}

/// Key Derivation Function configuration stored in the KDBX header.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KdfConfig {
    /// Argon2d / Argon2id memory-hard KDF (KDBX 4).
    Argon2 {
        /// Argon2d vs Argon2id.
        variant: Argon2Variant,
        /// Memory cost in **bytes** (e.g. `67_108_864` = 64 MiB).
        memory_bytes: u64,
        /// Iteration count (time cost).
        iterations: u64,
        /// Parallelism (lanes).
        parallelism: u32,
        /// Argon2 version (`0x13` = v1.3, `0x10` = v1.0).
        version: u32,
        /// 32-byte salt (`S`).
        salt: [u8; 32],
    },
    /// Legacy AES-256-ECB iterated KDF (KDBX 3.1 & KDBX 4).
    AesKdf {
        /// Number of AES-256-ECB encryption rounds (`R`).
        rounds: u64,
        /// 32-byte transform seed (`S`).
        seed: [u8; 32],
    },
}

impl Default for KdfConfig {
    fn default() -> Self {
        Self::Argon2 {
            variant: Argon2Variant::Argon2id,
            memory_bytes: 64 * 1024 * 1024, // 64 MiB
            iterations: 3,
            parallelism: 4,
            version: 0x13,
            salt: [0u8; 32],
        }
    }
}

impl KdfConfig {
    /// Canonical AES-KDF `$UUID` in KDBX 4 VariantDictionary.
    pub const AES_KDF_UUID: [u8; 16] = [
        0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60, 0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f,
        0xea,
    ];

    /// Summary string for `db-info` and UI status bar.
    #[must_use]
    pub fn summary(&self) -> String {
        match self {
            Self::Argon2 {
                variant,
                memory_bytes,
                iterations,
                parallelism,
                ..
            } => {
                let name = match variant {
                    Argon2Variant::Argon2d => "Argon2d",
                    Argon2Variant::Argon2id => "Argon2id",
                };
                let mib = memory_bytes / (1024 * 1024);
                format!("{name} ({mib} MiB, {iterations} iterations, {parallelism} lanes)")
            }
            Self::AesKdf { rounds, .. } => format!("AES-KDF ({rounds} rounds)"),
        }
    }
}

/// Standard timestamps tracked on every KDBX `Group` and `Entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Times {
    /// Creation timestamp (UTC).
    pub creation_time: DateTime<Utc>,
    /// Last modification timestamp (UTC).
    pub last_modification_time: DateTime<Utc>,
    /// Last access timestamp (UTC).
    pub last_access_time: DateTime<Utc>,
    /// Optional expiration deadline (UTC).
    pub expiry_time: DateTime<Utc>,
    /// Whether `expiry_time` is active.
    pub expires: bool,
    /// Number of times this item was accessed.
    pub usage_count: u64,
    /// Last time the parent group changed.
    pub location_changed: DateTime<Utc>,
}

impl Default for Times {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            creation_time: now,
            last_modification_time: now,
            last_access_time: now,
            expiry_time: now,
            expires: false,
            usage_count: 0,
            location_changed: now,
        }
    }
}

impl Times {
    /// Returns `true` if `expires` is enabled and `expiry_time` is in the past.
    #[must_use]
    pub fn is_expired(&self) -> bool {
        self.expires && self.expiry_time <= Utc::now()
    }

    /// Updates `last_modification_time` and `last_access_time` to `Utc::now()`.
    pub fn touch_modified(&mut self) {
        let now = Utc::now();
        self.last_modification_time = now;
        self.last_access_time = now;
    }
}

/// Additional key/value string attribute on an `Entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomAttribute {
    /// Attribute name.
    pub key: String,
    /// Attribute value (zeroized on drop).
    pub value: ProtectedString,
    /// Whether `<Value Protected="True">` is set in KDBX.
    pub protected: bool,
}

/// Binary file attachment embedded on an `Entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attachment {
    /// File name as displayed on the entry (e.g. `"recovery-codes.txt"`).
    pub name: String,
    /// Uncompressed raw file bytes.
    pub data: Vec<u8>,
    /// Whether the binary payload is marked protected in memory (KDBX 4 Inner Header flag `0x01`).
    pub protected: bool,
}

/// Window title association rule for Auto-Type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoTypeAssociation {
    /// Wildcard window title pattern (e.g. `"*GitHub*"`).
    pub window: String,
    /// Keystroke sequence override (empty = inherit entry/group default).
    pub keystroke_sequence: String,
}

/// Auto-Type configuration on an `Entry`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoType {
    /// Whether Auto-Type is enabled for this entry.
    pub enabled: bool,
    /// Data transfer obfuscation mode (`0` = none, `1` = two-channel clipboard obfuscation).
    pub obfuscation: u32,
    /// Default keystroke sequence (empty = `{USERNAME}{TAB}{PASSWORD}{ENTER}`).
    pub default_sequence: String,
    /// Window associations.
    pub associations: Vec<AutoTypeAssociation>,
}

impl Default for AutoType {
    fn default() -> Self {
        Self {
            enabled: true,
            obfuscation: 0,
            default_sequence: String::new(),
            associations: Vec::new(),
        }
    }
}

/// A password vault entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    /// Globally unique 128-bit entry identifier.
    pub uuid: Uuid,
    /// Standard KeePass icon ID (`0..=68`, `0` = Key).
    pub icon_id: u32,
    /// Optional hex foreground color (e.g. `"#FF5500"`).
    pub foreground_color: String,
    /// Optional hex background color.
    pub background_color: String,
    /// Optional browser launcher override URL.
    pub override_url: String,
    /// Categorization tags.
    pub tags: Vec<String>,
    /// Lifecycle timestamps.
    pub times: Times,
    /// Entry title (`Title`).
    pub title: String,
    /// Account username (`UserName`).
    pub username: String,
    /// Account password (`Password`, protected in memory).
    pub password: ProtectedString,
    /// Login URL (`URL`).
    pub url: String,
    /// Multi-line notes (`Notes`).
    pub notes: String,
    /// Optional `otpauth://` TOTP/HOTP URI (`otp`, protected in memory).
    pub otp: Option<ProtectedString>,
    /// Additional user-defined string attributes.
    pub custom_attributes: Vec<CustomAttribute>,
    /// Attached binary files.
    pub attachments: Vec<Attachment>,
    /// Auto-Type settings.
    pub auto_type: AutoType,
    /// Previous versions of this entry (oldest to newest; snapshots carry an empty `history`).
    pub history: Vec<Entry>,
}

impl Entry {
    /// Creates a new entry with a fresh random v4 UUID and `Title`.
    #[must_use]
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            icon_id: 0,
            foreground_color: String::new(),
            background_color: String::new(),
            override_url: String::new(),
            tags: Vec::new(),
            times: Times::default(),
            title: title.into(),
            username: String::new(),
            password: ProtectedString::default(),
            url: String::new(),
            notes: String::new(),
            otp: None,
            custom_attributes: Vec::new(),
            attachments: Vec::new(),
            auto_type: AutoType::default(),
            history: Vec::new(),
        }
    }

    /// Captures a snapshot of the current entry state into `self.history` before mutation,
    /// enforcing `max_items`.
    pub fn push_history_snapshot(&mut self, max_items: usize) {
        if max_items == 0 {
            self.history.clear();
            return;
        }
        let mut snapshot = self.clone();
        snapshot.history.clear();
        self.history.push(snapshot);
        if self.history.len() > max_items {
            let excess = self.history.len() - max_items;
            self.history.drain(0..excess);
        }
    }

    /// Looks up a standard or custom attribute case-insensitively (`Title`, `UserName`, `Password`,
    /// `URL`, `Notes`, `otp`, or any custom attribute key).
    #[must_use]
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        if name.eq_ignore_ascii_case("title") {
            Some(&self.title)
        } else if name.eq_ignore_ascii_case("username") || name.eq_ignore_ascii_case("user") {
            Some(&self.username)
        } else if name.eq_ignore_ascii_case("password") {
            Some(self.password.as_str())
        } else if name.eq_ignore_ascii_case("url") {
            Some(&self.url)
        } else if name.eq_ignore_ascii_case("notes") {
            Some(&self.notes)
        } else if name.eq_ignore_ascii_case("otp") {
            self.otp.as_ref().map(ProtectedString::as_str)
        } else {
            self.custom_attributes
                .iter()
                .find(|a| a.key.eq_ignore_ascii_case(name))
                .map(|a| a.value.as_str())
        }
    }

    /// Sets or inserts a custom attribute.
    pub fn set_custom_attribute(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
        protected: bool,
    ) {
        let key_str = key.into();
        if let Some(existing) = self.custom_attributes.iter_mut().find(|a| a.key == key_str) {
            existing.value = ProtectedString::new(value);
            existing.protected = protected;
        } else {
            self.custom_attributes.push(CustomAttribute {
                key: key_str,
                value: ProtectedString::new(value),
                protected,
            });
        }
    }
}

/// Hierarchical folder containing sub-groups and entries.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    /// Globally unique 128-bit group identifier.
    pub uuid: Uuid,
    /// Group display name.
    pub name: String,
    /// Optional notes / description.
    pub notes: String,
    /// Standard KeePass icon ID (`48` = Folder, `43` = Recycle Bin).
    pub icon_id: u32,
    /// Lifecycle timestamps.
    pub times: Times,
    /// UI tree expansion state.
    pub is_expanded: bool,
    /// Optional default Auto-Type sequence inherited by child entries.
    pub default_autotype_sequence: String,
    /// Tri-state Auto-Type inheritance (`None` = null/inherit, `Some(true/false)`).
    pub enable_autotype: Option<bool>,
    /// Tri-state Search inclusion (`None` = null/inherit, `Some(true/false)`).
    pub enable_searching: Option<bool>,
    /// Direct child entries.
    pub entries: Vec<Entry>,
    /// Child sub-groups.
    pub children: Vec<Group>,
}

impl Group {
    /// Creates a new folder group (`icon_id = 48`).
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            uuid: Uuid::new_v4(),
            name: name.into(),
            notes: String::new(),
            icon_id: 48,
            times: Times::default(),
            is_expanded: true,
            default_autotype_sequence: String::new(),
            enable_autotype: None,
            enable_searching: None,
            entries: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Total number of entries recursively inside this group and its sub-groups.
    #[must_use]
    pub fn total_entry_count(&self) -> usize {
        self.entries.len()
            + self
                .children
                .iter()
                .map(Self::total_entry_count)
                .sum::<usize>()
    }

    /// Total number of groups (including `self` and all descendants).
    #[must_use]
    pub fn total_group_count(&self) -> usize {
        1 + self
            .children
            .iter()
            .map(Self::total_group_count)
            .sum::<usize>()
    }

    /// Collects `(group_path, &Entry)` across this subtree (`prefix` has no leading slash).
    pub fn collect_entries<'a>(&'a self, prefix: &str, out: &mut Vec<(String, &'a Entry)>) {
        for entry in &self.entries {
            out.push((prefix.to_string(), entry));
        }
        for child in &self.children {
            let child_prefix = if prefix.is_empty() {
                child.name.clone()
            } else {
                format!("{prefix}/{}", child.name)
            };
            child.collect_entries(&child_prefix, out);
        }
    }

    /// Finds an entry by `Uuid` anywhere in this subtree.
    #[must_use]
    pub fn find_entry_by_uuid(&self, uuid: Uuid) -> Option<&Entry> {
        if let Some(e) = self.entries.iter().find(|e| e.uuid == uuid) {
            return Some(e);
        }
        for child in &self.children {
            if let Some(e) = child.find_entry_by_uuid(uuid) {
                return Some(e);
            }
        }
        None
    }

    /// Finds a mutable entry by `Uuid` anywhere in this subtree.
    pub fn find_entry_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Entry> {
        if let Some(e) = self.entries.iter_mut().find(|e| e.uuid == uuid) {
            return Some(e);
        }
        for child in &mut self.children {
            if let Some(e) = child.find_entry_by_uuid_mut(uuid) {
                return Some(e);
            }
        }
        None
    }

    /// Finds a group by `Uuid` anywhere in this subtree.
    #[must_use]
    pub fn find_group_by_uuid(&self, uuid: Uuid) -> Option<&Group> {
        if self.uuid == uuid {
            return Some(self);
        }
        for child in &self.children {
            if let Some(g) = child.find_group_by_uuid(uuid) {
                return Some(g);
            }
        }
        None
    }

    /// Finds a mutable group by `Uuid` anywhere in this subtree.
    pub fn find_group_by_uuid_mut(&mut self, uuid: Uuid) -> Option<&mut Group> {
        if self.uuid == uuid {
            return Some(self);
        }
        for child in &mut self.children {
            if let Some(g) = child.find_group_by_uuid_mut(uuid) {
                return Some(g);
            }
        }
        None
    }
}

/// Tombstone recorded in `<DeletedObjects>` for synchronization / `merge`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeletedObject {
    /// Deleted group or entry UUID.
    pub uuid: Uuid,
    /// UTC timestamp of deletion.
    pub deletion_time: DateTime<Utc>,
}

/// Vault-level metadata (`<Meta>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Application that last wrote the file (`"RustPass"` or `"KeePassXC"`).
    pub generator: String,
    /// Human-readable vault name.
    pub database_name: String,
    /// Timestamp when `database_name` last changed.
    pub database_name_changed: DateTime<Utc>,
    /// Multi-line vault description.
    pub database_description: String,
    /// Timestamp when `database_description` last changed.
    pub database_description_changed: DateTime<Utc>,
    /// Default username pre-filled on new entries.
    pub default_username: String,
    /// Timestamp when `default_username` last changed.
    pub default_username_changed: DateTime<Utc>,
    /// Days to retain history items during maintenance.
    pub maintenance_history_days: u32,
    /// Optional vault accent color (`"#RRGGBB"`).
    pub color: String,
    /// Timestamp when master credentials last changed.
    pub master_key_changed: DateTime<Utc>,
    /// Whether `ProtectPassword` is enabled in `<MemoryProtection>`.
    pub protect_password: bool,
    /// Whether `ProtectTitle` is enabled.
    pub protect_title: bool,
    /// Whether `ProtectUserName` is enabled.
    pub protect_username: bool,
    /// Whether `ProtectURL` is enabled.
    pub protect_url: bool,
    /// Whether `ProtectNotes` is enabled.
    pub protect_notes: bool,
    /// Whether deleted items move to the Recycle Bin first.
    pub recycle_bin_enabled: bool,
    /// UUID of the Recycle Bin group (`Uuid::nil()` if not yet created).
    pub recycle_bin_uuid: Uuid,
    /// Timestamp when `recycle_bin_uuid` changed.
    pub recycle_bin_changed: DateTime<Utc>,
    /// Maximum history snapshots retained per entry.
    pub history_max_items: usize,
    /// Maximum history byte budget per entry (`6_291_456` = 6 MiB default).
    pub history_max_size: u64,
    /// Arbitrary key/value metadata (`<CustomData>`).
    pub custom_data: HashMap<String, String>,
}

impl Default for Meta {
    fn default() -> Self {
        let now = Utc::now();
        Self {
            generator: "RustPass".to_string(),
            database_name: String::new(),
            database_name_changed: now,
            database_description: String::new(),
            database_description_changed: now,
            default_username: String::new(),
            default_username_changed: now,
            maintenance_history_days: 365,
            color: String::new(),
            master_key_changed: now,
            protect_password: true,
            protect_title: false,
            protect_username: false,
            protect_url: false,
            protect_notes: false,
            recycle_bin_enabled: true,
            recycle_bin_uuid: Uuid::nil(),
            recycle_bin_changed: now,
            history_max_items: 10,
            history_max_size: 6_291_456,
            custom_data: HashMap::new(),
        }
    }
}

/// Summary of changes detected or applied during a `Database::merge_from` operation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MergeReport {
    /// Newly imported entries.
    pub entries_added: Vec<String>,
    /// Existing entries updated to a newer revision.
    pub entries_updated: Vec<String>,
    /// Newly created groups.
    pub groups_added: Vec<String>,
    /// Items removed due to newer tombstones in `<DeletedObjects>`.
    pub items_deleted: usize,
}

/// Complete in-memory KDBX password vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Database {
    /// Target binary container version (`V4_0` by default, or `V3_1` when opened from a 3.1 file).
    pub version: KdbxVersion,
    /// Outer payload cipher (`ChaCha20` or `Aes256Cbc`).
    pub cipher: CipherAlgorithm,
    /// Whether GZip payload compression is enabled (`true` by default).
    pub compression_gzip: bool,
    /// Key derivation parameters (`Argon2id`, `Argon2d`, or `AesKdf`).
    pub kdf: KdfConfig,
    /// Inner stream cipher protecting `<Value Protected="True">`.
    pub inner_stream: InnerStreamAlgorithm,
    /// Vault metadata (`<Meta>`).
    pub meta: Meta,
    /// Root group (`<Root><Group>`).
    pub root: Group,
    /// Tombstones of permanently deleted items (`<DeletedObjects>`).
    pub deleted_objects: Vec<DeletedObject>,
}

impl Database {
    /// Creates a brand-new KDBX 4.0 vault (ChaCha20 + Argon2id) with a root group.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        let name_str = name.into();
        let root_title = if name_str.is_empty() {
            "Passwords".to_string()
        } else {
            name_str.clone()
        };
        let meta = Meta {
            database_name: name_str,
            ..Meta::default()
        };

        Self {
            version: KdbxVersion::V4_0 { minor: 0 },
            cipher: CipherAlgorithm::ChaCha20,
            compression_gzip: true,
            kdf: KdfConfig::default(),
            inner_stream: InnerStreamAlgorithm::ChaCha20,
            meta,
            root: Group::new(root_title),
            deleted_objects: Vec::new(),
        }
    }

    /// Splits a `/` or `\` separated path into non-empty segments, stripping an optional leading
    /// root-group segment if it matches `self.root.name` and no child group shares that name.
    #[must_use]
    pub fn normalize_segments<'a>(&self, raw_path: &'a str) -> Vec<&'a str> {
        let mut segs: Vec<&'a str> = raw_path
            .split(['/', '\\'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if let Some(&first) = segs.first()
            && first.eq_ignore_ascii_case(&self.root.name)
            && !self
                .root
                .children
                .iter()
                .any(|c| c.name.eq_ignore_ascii_case(first))
        {
            segs.remove(0);
        }
        segs
    }

    /// Resolves a group path (`""` or `"/"` resolves to `&self.root`).
    pub fn resolve_group(&self, path: &str) -> Result<&Group> {
        let segs = self.normalize_segments(path);
        let mut current = &self.root;
        for seg in segs {
            current = current
                .children
                .iter()
                .find(|g| g.name.eq_ignore_ascii_case(seg))
                .ok_or_else(|| RustPassError::GroupNotFound(path.to_string()))?;
        }
        Ok(current)
    }

    /// Resolves a mutable group path (`""` or `"/"` resolves to `&mut self.root`).
    pub fn resolve_group_mut(&mut self, path: &str) -> Result<&mut Group> {
        let segs: Vec<String> = self
            .normalize_segments(path)
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut current = &mut self.root;
        for seg in segs {
            current = current
                .children
                .iter_mut()
                .find(|g| g.name.eq_ignore_ascii_case(&seg))
                .ok_or_else(|| RustPassError::GroupNotFound(path.to_string()))?;
        }
        Ok(current)
    }

    /// Ensures all intermediate groups along `path` exist, creating missing folders, and returns
    /// a mutable reference to the leaf group.
    pub fn mkdir_p(&mut self, path: &str) -> &mut Group {
        let segs: Vec<String> = self
            .normalize_segments(path)
            .into_iter()
            .map(str::to_string)
            .collect();
        let mut current = &mut self.root;
        for seg in segs {
            let idx = if let Some(pos) = current
                .children
                .iter()
                .position(|g| g.name.eq_ignore_ascii_case(&seg))
            {
                pos
            } else {
                current.children.push(Group::new(seg));
                current.children.len() - 1
            };
            current = &mut current.children[idx];
        }
        current
    }

    /// Resolves an entry by path (`"Group/SubGroup/EntryTitle"` or `"EntryTitle"`), or by `{uuid}`.
    pub fn resolve_entry(&self, entry_path: &str) -> Result<&Entry> {
        let trimmed = entry_path.trim().trim_matches(['{', '}']);
        if let Ok(uuid) = Uuid::parse_str(trimmed)
            && let Some(e) = self.root.find_entry_by_uuid(uuid)
        {
            return Ok(e);
        }

        let segs = self.normalize_segments(entry_path);
        let Some((&entry_title, group_segs)) = segs.split_last() else {
            return Err(RustPassError::EntryNotFound(entry_path.to_string()));
        };

        let mut group = &self.root;
        for seg in group_segs {
            group = group
                .children
                .iter()
                .find(|g| g.name.eq_ignore_ascii_case(seg))
                .ok_or_else(|| RustPassError::EntryNotFound(entry_path.to_string()))?;
        }

        group
            .entries
            .iter()
            .find(|e| e.title.eq_ignore_ascii_case(entry_title))
            .ok_or_else(|| RustPassError::EntryNotFound(entry_path.to_string()))
    }

    /// Resolves a mutable entry by path or UUID.
    pub fn resolve_entry_mut(&mut self, entry_path: &str) -> Result<&mut Entry> {
        let uuid = self.resolve_entry(entry_path)?.uuid;
        self.root
            .find_entry_by_uuid_mut(uuid)
            .ok_or_else(|| RustPassError::EntryNotFound(entry_path.to_string()))
    }

    /// Adds a new entry at `entry_path` (`"Group/SubGroup/Title"`), creating parent groups if needed.
    pub fn add_entry_at_path(&mut self, entry_path: &str, mut entry: Entry) -> Result<Uuid> {
        let segs: Vec<String> = self
            .normalize_segments(entry_path)
            .into_iter()
            .map(str::to_string)
            .collect();
        let Some((title, group_segs)) = segs.split_last() else {
            return Err(RustPassError::InvalidArgument(
                "Entry path cannot be empty".to_string(),
            ));
        };
        if entry.title.is_empty() {
            entry.title.clone_from(title);
        }
        let group_path = group_segs.join("/");
        let group = self.mkdir_p(&group_path);
        if group
            .entries
            .iter()
            .any(|e| e.title.eq_ignore_ascii_case(&entry.title))
        {
            return Err(RustPassError::InvalidArgument(format!(
                "An entry named '{}' already exists in group '{}'",
                entry.title, group.name
            )));
        }
        let uuid = entry.uuid;
        group.entries.push(entry);
        Ok(uuid)
    }

    /// Returns `true` if `uuid` lives inside the Recycle Bin subtree.
    #[must_use]
    pub fn is_in_recycle_bin(&self, entry_uuid: Uuid) -> bool {
        if !self.meta.recycle_bin_enabled || self.meta.recycle_bin_uuid.is_nil() {
            return false;
        }
        self.root
            .find_group_by_uuid(self.meta.recycle_bin_uuid)
            .is_some_and(|bin| bin.find_entry_by_uuid(entry_uuid).is_some())
    }

    /// Ensures the Recycle Bin group exists under `self.root` and returns its `Uuid`.
    pub fn ensure_recycle_bin(&mut self) -> Uuid {
        if !self.meta.recycle_bin_uuid.is_nil()
            && self
                .root
                .find_group_by_uuid(self.meta.recycle_bin_uuid)
                .is_some()
        {
            return self.meta.recycle_bin_uuid;
        }
        let mut bin = Group::new("Recycle Bin");
        bin.icon_id = 43;
        bin.enable_autotype = Some(false);
        bin.enable_searching = Some(false);
        let id = bin.uuid;
        self.root.children.push(bin);
        self.meta.recycle_bin_uuid = id;
        self.meta.recycle_bin_changed = Utc::now();
        id
    }

    /// Deletes an entry by `Uuid`: moves to Recycle Bin if enabled and not already inside it;
    /// otherwise permanently removes it and records a `DeletedObject` tombstone.
    pub fn delete_entry_by_uuid(&mut self, uuid: Uuid, permanent: bool) -> Result<()> {
        let already_in_bin = self.is_in_recycle_bin(uuid);
        let removed = Self::take_entry_from_group(&mut self.root, uuid)
            .ok_or_else(|| RustPassError::EntryNotFound(uuid.to_string()))?;

        if !permanent && self.meta.recycle_bin_enabled && !already_in_bin {
            let bin_id = self.ensure_recycle_bin();
            if let Some(bin) = self.root.find_group_by_uuid_mut(bin_id) {
                let mut moved = removed;
                moved.times.location_changed = Utc::now();
                bin.entries.push(moved);
                return Ok(());
            }
        }

        self.deleted_objects.push(DeletedObject {
            uuid,
            deletion_time: Utc::now(),
        });
        Ok(())
    }

    fn take_entry_from_group(group: &mut Group, uuid: Uuid) -> Option<Entry> {
        if let Some(pos) = group.entries.iter().position(|e| e.uuid == uuid) {
            return Some(group.entries.remove(pos));
        }
        for child in &mut group.children {
            if let Some(e) = Self::take_entry_from_group(child, uuid) {
                return Some(e);
            }
        }
        None
    }

    /// Moves an entry (`entry_path`) into `dest_group_path`.
    pub fn move_entry(&mut self, entry_path: &str, dest_group_path: &str) -> Result<()> {
        let uuid = self.resolve_entry(entry_path)?.uuid;
        // Validate destination exists before removing!
        let dest_uuid = self.resolve_group(dest_group_path)?.uuid;
        let mut entry = Self::take_entry_from_group(&mut self.root, uuid)
            .ok_or_else(|| RustPassError::EntryNotFound(entry_path.to_string()))?;
        entry.times.location_changed = Utc::now();
        let dest = self
            .root
            .find_group_by_uuid_mut(dest_uuid)
            .ok_or_else(|| RustPassError::GroupNotFound(dest_group_path.to_string()))?;
        dest.entries.push(entry);
        Ok(())
    }

    /// Removes a non-root group at `group_path` and records tombstones for it and its entries.
    pub fn remove_group(&mut self, group_path: &str) -> Result<()> {
        let segs = self.normalize_segments(group_path);
        let Some((&target_name, parent_segs)) = segs.split_last() else {
            return Err(RustPassError::InvalidArgument(
                "Cannot remove the root group".to_string(),
            ));
        };
        let parent_path = parent_segs.join("/");
        let target_name_owned = target_name.to_string();
        let parent = self.resolve_group_mut(&parent_path)?;
        let pos = parent
            .children
            .iter()
            .position(|g| g.name.eq_ignore_ascii_case(&target_name_owned))
            .ok_or_else(|| RustPassError::GroupNotFound(group_path.to_string()))?;
        let removed_group = parent.children.remove(pos);

        let now = Utc::now();
        let mut all = Vec::new();
        removed_group.collect_entries("", &mut all);
        for (_, e) in all {
            self.deleted_objects.push(DeletedObject {
                uuid: e.uuid,
                deletion_time: now,
            });
        }
        self.deleted_objects.push(DeletedObject {
            uuid: removed_group.uuid,
            deletion_time: now,
        });
        Ok(())
    }

    /// Collects all entries across the vault (optionally excluding the Recycle Bin).
    #[must_use]
    pub fn all_entries(&self, include_recycle_bin: bool) -> Vec<(String, &Entry)> {
        let mut out = Vec::new();
        for entry in &self.root.entries {
            out.push((String::new(), entry));
        }
        for child in &self.root.children {
            if !include_recycle_bin
                && self.meta.recycle_bin_enabled
                && !self.meta.recycle_bin_uuid.is_nil()
                && child.uuid == self.meta.recycle_bin_uuid
            {
                continue;
            }
            child.collect_entries(&child.name, &mut out);
        }
        out
    }

    /// Merges `other` into `self` by comparing UUIDs, modification timestamps, and `DeletedObjects`
    /// (matching KeePassXC's merge specification). When `dry_run` is `true`, `self` is left untouched.
    pub fn merge_from(&mut self, other: &Self, dry_run: bool) -> MergeReport {
        if dry_run {
            let mut clone = self.clone();
            return clone.merge_from(other, false);
        }

        let mut report = MergeReport::default();

        // 1. Reconcile DeletedObjects from `other`
        for del in &other.deleted_objects {
            if !self.deleted_objects.iter().any(|d| d.uuid == del.uuid) {
                if let Some(existing) = self.root.find_entry_by_uuid(del.uuid)
                    && existing.times.last_modification_time < del.deletion_time
                {
                    let _ = Self::take_entry_from_group(&mut self.root, del.uuid);
                    report.items_deleted += 1;
                }
                self.deleted_objects.push(del.clone());
            }
        }

        // 2. Recursively merge groups and entries from `other.root`
        let history_max = self.meta.history_max_items;
        let deleted_map: HashMap<Uuid, DateTime<Utc>> = self
            .deleted_objects
            .iter()
            .map(|d| (d.uuid, d.deletion_time))
            .collect();

        let mut other_entries = Vec::new();
        other.root.collect_entries("", &mut other_entries);

        // Ensure group paths exist
        Self::merge_group_skeleton(&mut self.root, &other.root, "", &deleted_map, &mut report);

        for (group_path, incoming) in other_entries {
            if let Some(&del_time) = deleted_map.get(&incoming.uuid)
                && incoming.times.last_modification_time <= del_time
            {
                continue;
            }

            if let Some(existing) = self.root.find_entry_by_uuid_mut(incoming.uuid) {
                if incoming.times.last_modification_time > existing.times.last_modification_time {
                    existing.push_history_snapshot(history_max);
                    let keep_history = existing.history.clone();
                    *existing = incoming.clone();
                    // Merge unique history entries by modification time
                    let mut combined = keep_history;
                    for h in &incoming.history {
                        if !combined.iter().any(|c| {
                            c.times.last_modification_time == h.times.last_modification_time
                        }) {
                            combined.push(h.clone());
                        }
                    }
                    combined.sort_by_key(|h| h.times.last_modification_time);
                    if combined.len() > history_max {
                        let excess = combined.len() - history_max;
                        combined.drain(0..excess);
                    }
                    existing.history = combined;
                    report.entries_updated.push(incoming.title.clone());
                }
            } else {
                let target_group = self.mkdir_p(&group_path);
                target_group.entries.push(incoming.clone());
                let label = if group_path.is_empty() {
                    incoming.title.clone()
                } else {
                    format!("{group_path}/{}", incoming.title)
                };
                report.entries_added.push(label);
            }
        }

        report
    }

    fn merge_group_skeleton(
        dst: &mut Group,
        src: &Group,
        prefix: &str,
        deleted: &HashMap<Uuid, DateTime<Utc>>,
        report: &mut MergeReport,
    ) {
        for src_child in &src.children {
            if deleted.contains_key(&src_child.uuid) {
                continue;
            }
            let child_path = if prefix.is_empty() {
                src_child.name.clone()
            } else {
                format!("{prefix}/{}", src_child.name)
            };
            let idx = if let Some(pos) = dst.children.iter().position(|g| {
                g.uuid == src_child.uuid || g.name.eq_ignore_ascii_case(&src_child.name)
            }) {
                pos
            } else {
                let mut g = Group::new(&src_child.name);
                g.uuid = src_child.uuid;
                g.icon_id = src_child.icon_id;
                g.notes.clone_from(&src_child.notes);
                dst.children.push(g);
                report.groups_added.push(child_path.clone());
                dst.children.len() - 1
            };
            Self::merge_group_skeleton(
                &mut dst.children[idx],
                src_child,
                &child_path,
                deleted,
                report,
            );
        }
    }
}
