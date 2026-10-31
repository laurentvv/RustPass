//! Instant Command Palette (`Ctrl+Shift+P`) for keyboard-first vault workflows.

use crate::i18n::{Language, texts};
use eframe::egui::{self, Key, RichText};

/// Action dispatched when the user triggers an item in the Command Palette.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaletteAction {
    NewDatabase,
    OpenDatabase,
    SaveDatabase,
    LockVault,
    AddEntry,
    EditEntry,
    CloneEntry,
    DeleteEntry,
    CopyUsername,
    CopyPassword,
    CopyTotp,
    OpenUrl,
    PerformAutoType,
    OpenGenerator,
    OpenSecurityAudit,
    OpenDbSettings,
    ExportCsv,
    ExportXml,
    ExportHtml,
    ToggleLanguage,
    ShowShortcuts,
}

struct PaletteItem {
    action: PaletteAction,
    label_en: &'static str,
    label_fr: &'static str,
    shortcut: &'static str,
}

const ITEMS: &[PaletteItem] = &[
    PaletteItem {
        action: PaletteAction::AddEntry,
        label_en: "Entries: New Entry",
        label_fr: "Entrées : Nouvelle entrée",
        shortcut: "Ctrl+I",
    },
    PaletteItem {
        action: PaletteAction::EditEntry,
        label_en: "Entries: Edit Selected Entry",
        label_fr: "Entrées : Modifier l'entrée sélectionnée",
        shortcut: "Ctrl+E",
    },
    PaletteItem {
        action: PaletteAction::CopyPassword,
        label_en: "Entries: Copy Password (timed auto-clear)",
        label_fr: "Entrées : Copier le mot de passe (effacement auto)",
        shortcut: "Ctrl+C",
    },
    PaletteItem {
        action: PaletteAction::CopyUsername,
        label_en: "Entries: Copy Username",
        label_fr: "Entrées : Copier l'identifiant",
        shortcut: "Ctrl+B",
    },
    PaletteItem {
        action: PaletteAction::CopyTotp,
        label_en: "Entries: Copy 2FA / TOTP Code",
        label_fr: "Entrées : Copier le code TOTP",
        shortcut: "Ctrl+T",
    },
    PaletteItem {
        action: PaletteAction::PerformAutoType,
        label_en: "Entries: Perform Auto-Type into Previous Window",
        label_fr: "Entrées : Saisie automatique Auto-Type",
        shortcut: "Ctrl+V",
    },
    PaletteItem {
        action: PaletteAction::OpenUrl,
        label_en: "Entries: Open Login URL in Browser",
        label_fr: "Entrées : Ouvrir l'URL dans le navigateur",
        shortcut: "Ctrl+U",
    },
    PaletteItem {
        action: PaletteAction::CloneEntry,
        label_en: "Entries: Clone Selected Entry",
        label_fr: "Entrées : Dupliquer l'entrée",
        shortcut: "Ctrl+K",
    },
    PaletteItem {
        action: PaletteAction::DeleteEntry,
        label_en: "Entries: Delete Entry (Move to Recycle Bin)",
        label_fr: "Entrées : Supprimer l'entrée (Corbeille)",
        shortcut: "Del",
    },
    PaletteItem {
        action: PaletteAction::OpenGenerator,
        label_en: "Tools: Password & Diceware Generator",
        label_fr: "Outils : Générateur de mots de passe & Diceware",
        shortcut: "Ctrl+G",
    },
    PaletteItem {
        action: PaletteAction::OpenSecurityAudit,
        label_en: "Tools: Vault Security Health Audit",
        label_fr: "Outils : Audit de santé sécurité du coffre",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::OpenDbSettings,
        label_en: "Database: Encryption & Argon2id Settings",
        label_fr: "Base : Chiffrement & Paramètres Argon2id",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::NewDatabase,
        label_en: "Database: Create New KDBX Vault",
        label_fr: "Base : Créer un nouveau coffre KDBX",
        shortcut: "Ctrl+N",
    },
    PaletteItem {
        action: PaletteAction::OpenDatabase,
        label_en: "Database: Open Existing KDBX Vault",
        label_fr: "Base : Ouvrir un coffre KDBX existant",
        shortcut: "Ctrl+O",
    },
    PaletteItem {
        action: PaletteAction::SaveDatabase,
        label_en: "Database: Save Vault",
        label_fr: "Base : Enregistrer le coffre",
        shortcut: "Ctrl+S",
    },
    PaletteItem {
        action: PaletteAction::LockVault,
        label_en: "Database: Lock Active Vault",
        label_fr: "Base : Verrouiller le coffre actif",
        shortcut: "Ctrl+L",
    },
    PaletteItem {
        action: PaletteAction::ExportCsv,
        label_en: "Database: Export Vault to CSV",
        label_fr: "Base : Exporter le coffre en CSV",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::ExportXml,
        label_en: "Database: Export Vault to KeePass XML",
        label_fr: "Base : Exporter le coffre en XML KeePass",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::ExportHtml,
        label_en: "Database: Export Printable HTML Sheet",
        label_fr: "Base : Exporter une fiche HTML imprimable",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::ToggleLanguage,
        label_en: "View: Switch Language (English / Français)",
        label_fr: "Affichage : Changer de langue (Français / English)",
        shortcut: "",
    },
    PaletteItem {
        action: PaletteAction::ShowShortcuts,
        label_en: "Help: Keyboard Shortcuts Reference",
        label_fr: "Aide : Référence des raccourcis clavier",
        shortcut: "F1",
    },
];

/// Interactive state for the `Ctrl+Shift+P` Command Palette modal.
#[derive(Debug, Default)]
pub struct CommandPaletteState {
    pub open: bool,
    pub query: String,
    pub selected_index: usize,
    pub focus_requested: bool,
}

impl CommandPaletteState {
    /// Opens and resets the Command Palette.
    pub fn show(&mut self) {
        self.open = true;
        self.query.clear();
        self.selected_index = 0;
        self.focus_requested = true;
    }

    /// Renders the Command Palette window and returns a chosen `PaletteAction` if triggered.
    pub fn ui(&mut self, ctx: &egui::Context, lang: Language) -> Option<PaletteAction> {
        if !self.open {
            return None;
        }

        if ctx.input(|i| i.key_pressed(Key::Escape)) {
            self.open = false;
            return None;
        }

        let q_lower = self.query.trim().to_lowercase();
        let filtered: Vec<&PaletteItem> = ITEMS
            .iter()
            .filter(|item| {
                if q_lower.is_empty() {
                    return true;
                }
                let lbl = match lang {
                    Language::English => item.label_en,
                    Language::French => item.label_fr,
                };
                lbl.to_lowercase().contains(&q_lower)
                    || item.shortcut.to_lowercase().contains(&q_lower)
            })
            .collect();

        if self.selected_index >= filtered.len() {
            self.selected_index = 0;
        }

        if ctx.input(|i| i.key_pressed(Key::ArrowDown)) && !filtered.is_empty() {
            self.selected_index = (self.selected_index + 1) % filtered.len();
        }
        if ctx.input(|i| i.key_pressed(Key::ArrowUp)) && !filtered.is_empty() {
            self.selected_index = self
                .selected_index
                .checked_sub(1)
                .unwrap_or(filtered.len() - 1);
        }

        let mut chosen = None;
        let t = texts(lang);

        egui::Window::new(t.command_palette)
            .collapsible(false)
            .resizable(false)
            .fixed_size([520.0, 340.0])
            .anchor(egui::Align2::CENTER_TOP, [0.0, 64.0])
            .show(ctx, |ui| {
                let edit = ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .desired_width(f32::INFINITY)
                        .hint_text("Type a command…"),
                );
                if self.focus_requested {
                    edit.request_focus();
                    self.focus_requested = false;
                }

                if ctx.input(|i| i.key_pressed(Key::Enter))
                    && let Some(item) = filtered.get(self.selected_index)
                {
                    chosen = Some(item.action);
                }

                ui.add_space(6.0);
                ui.separator();
                egui::ScrollArea::vertical()
                    .max_height(265.0)
                    .show(ui, |ui| {
                        for (idx, item) in filtered.iter().enumerate() {
                            let is_sel = idx == self.selected_index;
                            let lbl = match lang {
                                Language::English => item.label_en,
                                Language::French => item.label_fr,
                            };
                            ui.horizontal(|ui| {
                                let resp =
                                    ui.selectable_label(is_sel, RichText::new(lbl).size(13.5));
                                if !item.shortcut.is_empty() {
                                    ui.with_layout(
                                        egui::Layout::right_to_left(egui::Align::Center),
                                        |ui| {
                                            ui.label(
                                                RichText::new(item.shortcut)
                                                    .monospace()
                                                    .size(11.5)
                                                    .weak(),
                                            );
                                        },
                                    );
                                }
                                if resp.clicked() {
                                    chosen = Some(item.action);
                                }
                            });
                        }
                    });
            });

        if chosen.is_some() {
            self.open = false;
        }
        chosen
    }
}
