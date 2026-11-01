//! Persistent user preferences (`settings.json`) for the `RustPass` desktop application.

use crate::generator::{DicewareOptions, PasswordGeneratorOptions};
use crate::i18n::Language;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Selectable visual themes in `RustPass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ThemeChoice {
    /// Follow OS light/dark preference dynamically.
    FollowSystem,
    /// KeePassXC-inspired Emerald Dark (deep slate + emerald accent).
    #[default]
    EmeraldDark,
    /// High-contrast Obsidian Dark (`#12151C` + warm amber-rust accent).
    ObsidianDark,
    /// Windows 11 Fluent Dark.
    FluentDark,
    /// Solarized Dark.
    SolarizedDark,
    /// Windows 11 Fluent Light.
    FluentLight,
    /// Crisp Classic Light with emerald accent.
    ClassicLight,
}

impl ThemeChoice {
    /// All selectable themes in menu order.
    pub const ALL: [Self; 7] = [
        Self::FollowSystem,
        Self::EmeraldDark,
        Self::ObsidianDark,
        Self::FluentDark,
        Self::SolarizedDark,
        Self::FluentLight,
        Self::ClassicLight,
    ];

    /// Display label in the View → Theme menu.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::FollowSystem => "Follow Windows Theme",
            Self::EmeraldDark => "Emerald Vault Dark (Default)",
            Self::ObsidianDark => "Obsidian Rust Dark",
            Self::FluentDark => "Fluent Dark",
            Self::SolarizedDark => "Solarized Dark",
            Self::FluentLight => "Fluent Light",
            Self::ClassicLight => "Classic Emerald Light",
        }
    }
}

/// Persistent desktop settings saved under `%APPDATA%\RustPass\settings.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    /// Selected visual theme.
    pub theme: ThemeChoice,
    /// Selected interface language.
    pub language: Language,
    /// Seconds before copied secrets are automatically wiped from the OS clipboard (`0` = disabled).
    pub clipboard_clear_seconds: u64,
    /// Seconds of UI inactivity before locking open vaults automatically (`0` = disabled).
    pub auto_lock_idle_seconds: u64,
    /// Automatically save the `.kdbx` vault immediately after creating/editing/deleting an entry.
    pub auto_save_on_change: bool,
    /// Hide passwords behind `••••••••` in the Entry Inspector by default.
    pub mask_passwords_by_default: bool,
    /// Recently opened `.kdbx` file paths (most recent first, max 10).
    pub recent_databases: Vec<PathBuf>,
    /// Saved character generator options.
    pub password_generator: PasswordGeneratorOptions,
    /// Saved Diceware passphrase options.
    pub diceware_generator: DicewareOptions,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            theme: ThemeChoice::EmeraldDark,
            language: Language::English,
            clipboard_clear_seconds: 12,
            auto_lock_idle_seconds: 300,
            auto_save_on_change: false,
            mask_passwords_by_default: true,
            recent_databases: Vec::new(),
            password_generator: PasswordGeneratorOptions::default(),
            diceware_generator: DicewareOptions {
                separator: "-".to_string(),
                capitalize: true,
                include_number: true,
                ..DicewareOptions::default()
            },
        }
    }
}

impl AppSettings {
    /// Path to `settings.json` inside the platform config directory.
    #[must_use]
    pub fn config_path() -> Option<PathBuf> {
        dirs::config_dir().map(|d| d.join("RustPass").join("settings.json"))
    }

    /// Loads `AppSettings` from disk. A corrupt file resets to defaults **with a
    /// stderr warning** (never silent), a missing file is the normal first run.
    #[must_use]
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };
        let Ok(raw) = std::fs::read_to_string(&path) else {
            return Self::default();
        };
        match serde_json::from_str(&raw) {
            Ok(settings) => settings,
            Err(e) => {
                eprintln!(
                    "warning: {} is corrupt ({e}); resetting preferences to defaults",
                    path.display()
                );
                Self::default()
            }
        }
    }

    /// Saves `AppSettings` atomically (sibling `.tmp` + rename) so a crash mid-write
    /// can never destroy the previous preferences.
    pub fn save(&self) {
        let Some(path) = Self::config_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let tmp = path.with_extension("json.tmp");
            if std::fs::write(&tmp, json).is_ok() {
                let _ = std::fs::rename(&tmp, &path);
            }
        }
    }

    /// Pushes `path` to the front of `recent_databases` (deduplicated, capped at 10).
    pub fn record_recent(&mut self, path: PathBuf) {
        self.recent_databases.retain(|p| p != &path);
        self.recent_databases.insert(0, path);
        self.recent_databases.truncate(10);
        self.save();
    }
}
