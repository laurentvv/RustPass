//! Main `RustPassApp` desktop application state and 3-pane `egui`/`eframe` layout.

use crate::autotype::{compile_autotype_sequence, execute_autotype};
use crate::cli::GuiCliArgs;
use crate::crypto::kdf::MasterCredentials;
use crate::crypto::keyfile::write_new_keyfile;
use crate::generator::{StrengthLevel, estimate_password};
use crate::health::analyze_database;
use crate::i18n::{Language, texts};
use crate::io::{ExportFormat, export_database, import_csv_into, import_keepass_xml};
use crate::model::{Attachment, Database, Entry, Group, ProtectedString};
use crate::search::{SearchContext, SearchQuery};
use crate::settings::{AppSettings, ThemeChoice};
use crate::totp::TotpConfig;
use crate::ui::fonts::configure_fonts;
use crate::ui::modals::{
    DbSettingsModal, EntryEditorModal, GeneratorModal, SavedEntryPayload, SecurityAuditModal,
    build_qr_texture, show_about_window, show_shortcuts_window,
};
use crate::ui::palette::{CommandPaletteState, PaletteAction};
use crate::ui::themes::{VaultPalette, apply_theme, strength_color};
use eframe::egui::{self, Color32, Key, KeyboardShortcut, Modifiers, RichText, TextureHandle};
use std::path::PathBuf;
use std::time::{Duration, Instant};
use uuid::Uuid;
use zeroize::Zeroize;

/// Sidebar selection mode inside an unlocked vault tab.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SidebarFilter {
    AllEntries,
    Group(Uuid),
    TotpOnly,
    WeakOrReused,
    ExpiredOnly,
}

/// Sort column in the center entry list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortColumn {
    Title,
    Username,
    Url,
    Strength,
    Modified,
}

/// State of a single open (or locked) vault tab.
pub struct VaultSession {
    pub path: Option<PathBuf>,
    pub credentials: MasterCredentials,
    pub db: Option<Database>,
    pub dirty: bool,
    pub unlock_pw_buf: String,
    pub unlock_error: Option<String>,
    pub sidebar_filter: SidebarFilter,
    pub selected_entry: Option<Uuid>,
    pub search_query: String,
    pub sort_col: SortColumn,
    pub sort_asc: bool,
    pub reveal_inspector_pw: bool,
    pub show_inspector_qr: bool,
    pub inspector_qr_cache: Option<(String, TextureHandle)>,
    pub new_group_prompt: Option<String>,
}

impl VaultSession {
    fn from_unlocked(path: Option<PathBuf>, credentials: MasterCredentials, db: Database) -> Self {
        let first_entry = db.all_entries(false).first().map(|(_, e)| e.uuid);
        Self {
            path,
            credentials,
            db: Some(db),
            dirty: false,
            unlock_pw_buf: String::new(),
            unlock_error: None,
            sidebar_filter: SidebarFilter::AllEntries,
            selected_entry: first_entry,
            search_query: String::new(),
            sort_col: SortColumn::Title,
            sort_asc: true,
            reveal_inspector_pw: false,
            show_inspector_qr: false,
            inspector_qr_cache: None,
            new_group_prompt: None,
        }
    }

    fn tab_title(&self) -> String {
        let base = if let Some(ref db) = self.db {
            if !db.meta.database_name.is_empty() {
                db.meta.database_name.clone()
            } else {
                db.root.name.clone()
            }
        } else if let Some(ref p) = self.path {
            p.file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("Locked Vault")
                .to_string()
        } else {
            "Vault".to_string()
        };
        let lock_prefix = if self.db.is_none() { "[Locked] " } else { "" };
        let dirty_suffix = if self.dirty { " *" } else { "" };
        format!("{lock_prefix}{base}{dirty_suffix}")
    }

    fn lock(&mut self) {
        self.db = None;
        self.credentials.password = None;
        // The keyfile key is a composite-key component: drop it while locked too
        // (the path alone is kept so unlock stays convenient).
        self.credentials.keyfile_key = None;
        self.reveal_inspector_pw = false;
        self.inspector_qr_cache = None;
        self.unlock_pw_buf.zeroize();
    }
}

/// Welcome screen mode when opening or creating a `.kdbx` file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum WelcomeMode {
    #[default]
    UnlockExisting,
    CreateNew,
}

/// A vault mutation requested from a panel closure, applied once borrows release.
enum VaultDbAction {
    /// Restore one entry from the Recycle Bin to the vault root.
    RestoreEntry(uuid::Uuid),
    /// Permanently destroy one entry.
    DeleteEntryPermanent(uuid::Uuid),
    /// Restore every Recycle Bin entry to the vault root.
    RestoreAllTrash,
    /// Permanently destroy the whole Recycle Bin content.
    EmptyTrash,
    /// Rename a group.
    RenameGroup(uuid::Uuid, String),
    /// Remove a group and its whole subtree.
    DeleteGroup(uuid::Uuid),
}

/// A close/new/quit request that may be awaiting the unsaved-changes confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PendingClose {
    /// Close the tab at this index.
    Tab(usize),
    /// New vault: closes every session (Ctrl+N / Database -> New).
    NewVault,
    /// Quit the application (Ctrl+Q / Database -> Quit).
    Quit,
}

/// Timed clipboard wipe tracker.
struct PendingClipboardClear {
    copied_secret: ProtectedString,
    deadline: Instant,
}

/// Root `eframe::App` state for `RustPass`.
pub struct RustPassApp {
    settings: AppSettings,
    palette: VaultPalette,
    sessions: Vec<VaultSession>,
    active_tab: usize,
    welcome_mode: WelcomeMode,
    welcome_db_path: String,
    welcome_keyfile_path: String,
    welcome_vault_name: String,
    welcome_pw: String,
    welcome_pw_confirm: String,
    welcome_show_pw: bool,
    welcome_error: Option<String>,
    focus_search_next: bool,
    status_message: String,
    last_interaction: Instant,
    clipboard_guard: Option<PendingClipboardClear>,
    cmd_palette: CommandPaletteState,
    entry_editor: EntryEditorModal,
    generator_modal: GeneratorModal,
    audit_modal: SecurityAuditModal,
    db_settings_modal: DbSettingsModal,
    show_shortcuts: bool,
    show_about: bool,
    pending_close: Option<PendingClose>,
    pending_export: Option<(ExportFormat, &'static str)>,
    close_viewport_requested: bool,
    follow_system_last_poll: Instant,
    group_rename_buf: String,
    pending_group_delete: Option<uuid::Uuid>,
    pending_empty_trash: bool,
}

impl RustPassApp {
    /// Initializes `RustPassApp`, loading fonts, theme, user settings, and optional CLI startup vault.
    pub fn new(cc: &eframe::CreationContext<'_>, cli_args: GuiCliArgs) -> Self {
        configure_fonts(&cc.egui_ctx);
        let settings = AppSettings::load();
        let palette = apply_theme(&cc.egui_ctx, settings.theme);

        let gen_modal = GeneratorModal::new(
            settings.password_generator.clone(),
            settings.diceware_generator.clone(),
        );

        let mut app = Self {
            settings,
            palette,
            sessions: Vec::new(),
            active_tab: 0,
            welcome_mode: WelcomeMode::UnlockExisting,
            welcome_db_path: String::new(),
            welcome_keyfile_path: String::new(),
            welcome_vault_name: "Personal Vault".to_string(),
            welcome_pw: String::new(),
            welcome_pw_confirm: String::new(),
            welcome_show_pw: false,
            welcome_error: None,
            focus_search_next: false,
            status_message: "Ready — KDBX 4.0 & 3.1 Clean-Room Engine".to_string(),
            last_interaction: Instant::now(),
            clipboard_guard: None,
            cmd_palette: CommandPaletteState::default(),
            entry_editor: EntryEditorModal::default(),
            generator_modal: gen_modal,
            audit_modal: SecurityAuditModal::default(),
            db_settings_modal: DbSettingsModal::default(),
            show_shortcuts: false,
            show_about: false,
            pending_close: None,
            pending_export: None,
            close_viewport_requested: false,
            follow_system_last_poll: Instant::now(),
            group_rename_buf: String::new(),
            pending_group_delete: None,
            pending_empty_trash: false,
        };

        if let Some(kf) = cli_args.keyfile {
            app.welcome_keyfile_path = kf.display().to_string();
        }
        if let Some(db_path) = cli_args.database {
            app.welcome_db_path = db_path.display().to_string();
            if cli_args.pw_stdin {
                let mut line = String::new();
                if std::io::stdin().read_line(&mut line).is_ok() {
                    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                    line.zeroize();
                    let kf_opt = if app.welcome_keyfile_path.trim().is_empty() {
                        None
                    } else {
                        Some(PathBuf::from(app.welcome_keyfile_path.trim()))
                    };
                    if let Ok(creds) = MasterCredentials::new(Some(trimmed), kf_opt.as_deref())
                        && let Ok(db) = Database::open(&db_path, &creds)
                    {
                        app.settings.record_recent(db_path.clone());
                        app.sessions
                            .push(VaultSession::from_unlocked(Some(db_path), creds, db));
                    }
                }
            }
        }

        if let Some(ref l) = cli_args.lang {
            match l.to_lowercase().as_str() {
                "en" | "english" => app.settings.language = Language::English,
                "fr" | "french" | "francais" => app.settings.language = Language::French,
                _ => {}
            }
        }

        if cli_args.showcase {
            app.open_showcase_demo_vault();
            if let Some(sess) = app.sessions.first_mut() {
                sess.show_inspector_qr = true;
            }
        }

        if let Some(ref m) = cli_args.open_modal {
            match m.to_lowercase().as_str() {
                "generator" => app.generator_modal.open = true,
                "audit" => app.trigger_action(PaletteAction::OpenSecurityAudit),
                "editor" => app.trigger_action(PaletteAction::AddEntry),
                "shortcuts" => app.show_shortcuts = true,
                "settings" => app.trigger_action(PaletteAction::OpenDbSettings),
                "palette" => app.cmd_palette.show(),
                _ => {}
            }
        }

        app
    }

    /// Initializes `RustPassApp` for testing without an `eframe::CreationContext`.
    #[cfg(test)]
    pub fn new_for_test(ctx: &egui::Context, cli_args: GuiCliArgs) -> Self {
        configure_fonts(ctx);
        let settings = AppSettings::default();
        let palette = apply_theme(ctx, settings.theme);

        let gen_modal = GeneratorModal::new(
            settings.password_generator.clone(),
            settings.diceware_generator.clone(),
        );

        let mut app = Self {
            settings,
            palette,
            sessions: Vec::new(),
            active_tab: 0,
            welcome_mode: WelcomeMode::UnlockExisting,
            welcome_db_path: String::new(),
            welcome_keyfile_path: String::new(),
            welcome_vault_name: "Personal Vault".to_string(),
            welcome_pw: String::new(),
            welcome_pw_confirm: String::new(),
            welcome_show_pw: false,
            welcome_error: None,
            focus_search_next: false,
            status_message: "Ready — KDBX 4.0 & 3.1 Clean-Room Engine".to_string(),
            last_interaction: Instant::now(),
            clipboard_guard: None,
            cmd_palette: CommandPaletteState::default(),
            entry_editor: EntryEditorModal::default(),
            generator_modal: gen_modal,
            audit_modal: SecurityAuditModal::default(),
            db_settings_modal: DbSettingsModal::default(),
            show_shortcuts: false,
            show_about: false,
            pending_close: None,
            pending_export: None,
            close_viewport_requested: false,
            follow_system_last_poll: Instant::now(),
            group_rename_buf: String::new(),
            pending_group_delete: None,
            pending_empty_trash: false,
        };

        if let Some(kf) = cli_args.keyfile {
            app.welcome_keyfile_path = kf.display().to_string();
        }
        if let Some(db_path) = cli_args.database {
            app.welcome_db_path = db_path.display().to_string();
        }
        if let Some(ref l) = cli_args.lang {
            match l.to_lowercase().as_str() {
                "en" | "english" => app.settings.language = Language::English,
                "fr" | "french" | "francais" => app.settings.language = Language::French,
                _ => {}
            }
        }

        if cli_args.showcase {
            app.open_showcase_demo_vault();
            if let Some(sess) = app.sessions.first_mut() {
                sess.show_inspector_qr = true;
            }
        }
        if let Some(ref m) = cli_args.open_modal {
            match m.to_lowercase().as_str() {
                "generator" => app.generator_modal.open = true,
                "audit" => app.trigger_action(PaletteAction::OpenSecurityAudit),
                "editor" => app.trigger_action(PaletteAction::AddEntry),
                "shortcuts" => app.show_shortcuts = true,
                "settings" => app.trigger_action(PaletteAction::OpenDbSettings),
                "palette" => app.cmd_palette.show(),
                _ => {}
            }
        }
        app
    }

    fn active_session(&self) -> Option<&VaultSession> {
        self.sessions.get(self.active_tab)
    }

    fn active_session_mut(&mut self) -> Option<&mut VaultSession> {
        self.sessions.get_mut(self.active_tab)
    }

    fn copy_with_auto_clear(&mut self, label: &str, value: &str) {
        if value.is_empty() {
            return;
        }
        if let Ok(mut cb) = arboard::Clipboard::new()
            && cb.set_text(value).is_ok()
        {
            let secs = self.settings.clipboard_clear_seconds;
            if secs > 0 {
                self.clipboard_guard = Some(PendingClipboardClear {
                    copied_secret: ProtectedString::new(value),
                    deadline: Instant::now() + Duration::from_secs(secs),
                });
                self.status_message = format!("Copied {label} (auto-clears in {secs}s)");
            } else {
                self.status_message = format!("Copied {label} to clipboard");
            }
        }
    }

    fn poll_clipboard_and_autolock(&mut self, ctx: &egui::Context) {
        let now = Instant::now();

        if ctx.input(|i| {
            i.pointer.any_click()
                || i.pointer.is_moving()
                || !i.events.is_empty()
                || i.smooth_scroll_delta != egui::Vec2::ZERO
        }) {
            self.last_interaction = now;
        }

        if let Some(ref guard) = self.clipboard_guard {
            if now >= guard.deadline {
                if let Ok(mut cb) = arboard::Clipboard::new()
                    && let Ok(curr) = cb.get_text()
                    && curr == guard.copied_secret.as_str()
                {
                    let _ = cb.clear();
                }
                self.clipboard_guard = None;
                self.status_message = "Clipboard cleared automatically".to_string();
            } else {
                ctx.request_repaint_after(Duration::from_millis(250));
            }
        }

        let idle_limit = self.settings.auto_lock_idle_seconds;
        if idle_limit > 0 {
            let idle_for = now.duration_since(self.last_interaction);
            // Keep the UI loop running toward the lock deadline: without an explicit
            // repaint request egui sleeps until the next input event and the lock
            // would never fire while the user is away.
            ctx.request_repaint_after(
                Duration::from_secs(idle_limit)
                    .saturating_sub(idle_for)
                    .max(Duration::from_millis(250)),
            );
            if idle_for >= Duration::from_secs(idle_limit) {
                let mut locked_any = false;
                let mut kept_unsaved = 0usize;
                for sess in &mut self.sessions {
                    if sess.db.is_none() {
                        continue;
                    }
                    if sess.dirty {
                        match sess.path.clone() {
                            // Preserve edits: save before the idle lock rather than
                            // silently discarding or never locking at all.
                            Some(path) => {
                                let saved = sess.db.as_mut().is_some_and(|db| {
                                    db.save_atomic(&path, &sess.credentials).is_ok()
                                });
                                if saved {
                                    sess.dirty = false;
                                } else {
                                    kept_unsaved += 1;
                                    continue; // keep unlocked so the user can retry saving
                                }
                            }
                            None => {
                                // Path-less vault (showcase / brand-new): locking would
                                // silently destroy every unsaved edit.
                                kept_unsaved += 1;
                                continue;
                            }
                        }
                    }
                    sess.lock();
                    locked_any = true;
                }
                if locked_any {
                    self.status_message = "Vaults locked due to inactivity".to_string();
                }
                if kept_unsaved > 0 {
                    self.status_message =
                        format!("{kept_unsaved} vault(s) with unsaved changes kept unlocked");
                }
            }
        }
    }

    fn save_active_vault(&mut self, save_as: bool) {
        let Some(sess) = self.sessions.get_mut(self.active_tab) else {
            return;
        };
        if sess.db.is_none() {
            return;
        }

        let target_path = if save_as || sess.path.is_none() {
            rfd::FileDialog::new()
                .add_filter("KeePass KDBX Vault", &["kdbx"])
                .set_file_name("vault.kdbx")
                .save_file()
        } else {
            sess.path.clone()
        };

        let Some(path) = target_path else {
            return;
        };

        if let Some(ref mut db) = sess.db {
            match db.save_atomic(&path, &sess.credentials) {
                Ok(()) => {
                    sess.path = Some(path.clone());
                    sess.dirty = false;
                    self.settings.record_recent(path.clone());
                    self.status_message = format!("Saved vault to {}", path.display());
                }
                Err(e) => {
                    self.status_message = format!("Save failed: {e}");
                }
            }
        }
    }

    /// Requests a close action, routing through the unsaved-changes confirmation
    /// when any session is dirty.
    fn request_close(&mut self, close: PendingClose) {
        self.pending_close = Some(close);
        if !self.sessions.iter().any(|s| s.dirty) {
            let quit = self.execute_pending_close();
            if quit {
                self.close_viewport_requested = true;
            }
        }
    }

    /// Saves every dirty session that has a file path; returns how many remain dirty.
    fn save_all_dirty(&mut self) -> usize {
        let mut failed = 0usize;
        for sess in &mut self.sessions {
            if !sess.dirty {
                continue;
            }
            let Some(path) = sess.path.clone() else {
                failed += 1;
                continue;
            };
            let saved = sess
                .db
                .as_mut()
                .is_some_and(|db| db.save_atomic(&path, &sess.credentials).is_ok());
            if saved {
                sess.dirty = false;
            } else {
                failed += 1;
            }
        }
        failed
    }

    /// Executes the pending close; returns `true` when the app should now quit.
    fn execute_pending_close(&mut self) -> bool {
        match self.pending_close.take() {
            Some(PendingClose::Tab(idx)) => {
                if idx < self.sessions.len() {
                    self.sessions.remove(idx);
                }
                if self.active_tab >= self.sessions.len() && !self.sessions.is_empty() {
                    self.active_tab = self.sessions.len() - 1;
                }
                false
            }
            Some(PendingClose::NewVault) => {
                self.sessions.clear();
                self.active_tab = 0;
                self.welcome_mode = WelcomeMode::CreateNew;
                false
            }
            Some(PendingClose::Quit) => true,
            None => false,
        }
    }

    /// Confirmation modal shown whenever a close action meets dirty sessions.
    fn render_confirm_close_modal(&mut self, ctx: &egui::Context) {
        if self.pending_close.is_none() {
            return;
        }
        let t = texts(self.settings.language);
        let dirty_count = self.sessions.iter().filter(|s| s.dirty).count();
        let unsavable = self
            .sessions
            .iter()
            .filter(|s| s.dirty && s.path.is_none())
            .count();
        let palette = self.palette;
        egui::Window::new(t.unsaved_changes_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.label(format!("{dirty_count} {}", t.unsaved_changes_body));
                if unsavable > 0 {
                    ui.colored_label(
                        palette.warning,
                        format!("{unsavable} {}", t.unsaved_unsavable),
                    );
                }
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(unsavable == 0, egui::Button::new(t.save_and_close))
                        .clicked()
                    {
                        let remaining = self.save_all_dirty();
                        if remaining == 0 {
                            let quit = self.execute_pending_close();
                            if quit {
                                self.close_viewport_requested = true;
                            }
                        } else {
                            self.status_message =
                                format!("{remaining} vault(s) could not be saved");
                        }
                    }
                    if ui.button(t.discard_changes).clicked() {
                        let quit = self.execute_pending_close();
                        if quit {
                            self.close_viewport_requested = true;
                        }
                    }
                    if ui.button(t.cancel).clicked() {
                        self.pending_close = None;
                    }
                });
            });
    }

    /// Confirmation modal for plaintext exports (CSV / XML / HTML).
    fn render_confirm_export_modal(&mut self, ctx: &egui::Context) {
        let Some((fmt, ext)) = self.pending_export else {
            return;
        };
        let t = texts(self.settings.language);
        let palette = self.palette;
        egui::Window::new(t.export_warning_title)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.colored_label(palette.danger, t.export_warning_body);
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(t.export_anyway).clicked() {
                        self.pending_export = None;
                        self.export_dialog(fmt, ext);
                    }
                    if ui.button(t.cancel).clicked() {
                        self.pending_export = None;
                    }
                });
            });
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        if self.cmd_palette.open || self.entry_editor.open {
            return;
        }

        let consume = |ctx: &egui::Context, mods: Modifiers, key: Key| -> bool {
            ctx.input_mut(|i| i.consume_shortcut(&KeyboardShortcut::new(mods, key)))
        };

        let ctrl_shift = Modifiers::COMMAND | Modifiers::SHIFT;
        let ctrl = Modifiers::COMMAND;

        if consume(ctx, ctrl_shift, Key::P) {
            self.cmd_palette.show();
            return;
        }
        if consume(ctx, Modifiers::NONE, Key::F1) {
            self.show_shortcuts = true;
            return;
        }
        if consume(ctx, ctrl, Key::N) {
            self.request_close(PendingClose::NewVault);
            return;
        }
        if consume(ctx, ctrl, Key::O) {
            self.prompt_open_file_dialog();
            return;
        }
        if consume(ctx, ctrl, Key::S) {
            self.save_active_vault(false);
            return;
        }
        if consume(ctx, ctrl, Key::G) {
            self.generator_modal.open = true;
            return;
        }
        if consume(ctx, ctrl, Key::F) {
            self.focus_search_next = true;
            return;
        }
        if consume(ctx, ctrl, Key::L) {
            // Lock any session (unsaved ones are saved first when they have a path;
            // a failed save keeps the vault open instead of losing the edits).
            if let Some(sess) = self.active_session_mut()
                && sess.db.is_some()
            {
                if sess.dirty
                    && let Some(path) = sess.path.clone()
                {
                    let saved = sess
                        .db
                        .as_mut()
                        .is_some_and(|db| db.save_atomic(&path, &sess.credentials).is_ok());
                    if saved {
                        sess.dirty = false;
                    } else {
                        self.status_message =
                            "Save before lock failed; vault stays unlocked".to_string();
                        return;
                    }
                }
                sess.lock();
                self.status_message = "Vault locked".to_string();
            }
            return;
        }
        if consume(ctx, ctrl, Key::W) {
            self.request_close(PendingClose::Tab(self.active_tab));
            return;
        }
        if consume(ctx, ctrl, Key::Q) {
            self.request_close(PendingClose::Quit);
            return;
        }

        // Entry-level shortcuts when no text box currently holds keyboard focus
        if ctx.egui_wants_keyboard_input() {
            return;
        }

        if consume(ctx, ctrl, Key::I) {
            self.trigger_action(PaletteAction::AddEntry);
        } else if consume(ctx, ctrl, Key::E) {
            self.trigger_action(PaletteAction::EditEntry);
        } else if consume(ctx, ctrl, Key::K) {
            self.trigger_action(PaletteAction::CloneEntry);
        } else if consume(ctx, Modifiers::NONE, Key::Delete) {
            self.trigger_action(PaletteAction::DeleteEntry);
        } else if consume(ctx, ctrl, Key::B) {
            self.trigger_action(PaletteAction::CopyUsername);
        } else if consume(ctx, ctrl, Key::C) {
            self.trigger_action(PaletteAction::CopyPassword);
        } else if consume(ctx, ctrl, Key::T) {
            self.trigger_action(PaletteAction::CopyTotp);
        } else if consume(ctx, ctrl, Key::U) {
            self.trigger_action(PaletteAction::OpenUrl);
        } else if consume(ctx, ctrl, Key::V) {
            self.trigger_action(PaletteAction::PerformAutoType);
        }
    }

    fn prompt_open_file_dialog(&mut self) {
        if let Some(path) = rfd::FileDialog::new()
            .add_filter("KeePass Vault", &["kdbx"])
            .pick_file()
        {
            self.welcome_db_path = path.display().to_string();
            self.welcome_mode = WelcomeMode::UnlockExisting;
            // Create a locked tab ready for password entry if other vaults are already open
            if !self.sessions.is_empty() {
                self.sessions.push(VaultSession {
                    path: Some(path),
                    credentials: MasterCredentials::default(),
                    db: None,
                    dirty: false,
                    unlock_pw_buf: String::new(),
                    unlock_error: None,
                    sidebar_filter: SidebarFilter::AllEntries,
                    selected_entry: None,
                    search_query: String::new(),
                    sort_col: SortColumn::Title,
                    sort_asc: true,
                    reveal_inspector_pw: false,
                    show_inspector_qr: false,
                    inspector_qr_cache: None,
                    new_group_prompt: None,
                });
                self.active_tab = self.sessions.len() - 1;
            }
        }
    }

    fn trigger_action(&mut self, action: PaletteAction) {
        match action {
            PaletteAction::NewDatabase => {
                self.welcome_mode = WelcomeMode::CreateNew;
                if let Some(path) = rfd::FileDialog::new()
                    .add_filter("KeePass KDBX Vault", &["kdbx"])
                    .set_file_name("new-vault.kdbx")
                    .save_file()
                {
                    self.welcome_db_path = path.display().to_string();
                }
            }
            PaletteAction::OpenDatabase => self.prompt_open_file_dialog(),
            PaletteAction::SaveDatabase => self.save_active_vault(false),
            PaletteAction::LockVault => {
                if let Some(sess) = self.active_session_mut()
                    && sess.path.is_some()
                {
                    sess.lock();
                }
            }
            PaletteAction::AddEntry => {
                if let Some(sess) = self.sessions.get(self.active_tab)
                    && let Some(ref db) = sess.db
                {
                    let grp_uuid = match sess.sidebar_filter {
                        SidebarFilter::Group(id) => id,
                        _ => db.root.uuid,
                    };
                    self.entry_editor.open_new(
                        grp_uuid,
                        &db.meta.default_username,
                        &self.settings.password_generator,
                    );
                }
            }
            PaletteAction::EditEntry => {
                if let Some(sess) = self.sessions.get(self.active_tab)
                    && let Some(ref db) = sess.db
                    && let Some(sel) = sess.selected_entry
                    && let Some(entry) = db.root.find_entry_by_uuid(sel)
                {
                    self.entry_editor.open_edit(entry);
                }
            }
            PaletteAction::CloneEntry => {
                if let Some(sess) = self.active_session_mut()
                    && let Some(ref mut db) = sess.db
                    && let Some(sel) = sess.selected_entry
                    && let Some(orig) = db.root.find_entry_by_uuid(sel).cloned()
                {
                    let mut cloned = orig;
                    cloned.uuid = Uuid::new_v4();
                    cloned.title = format!("{} (Copy)", cloned.title);
                    cloned.history.clear();
                    let new_id = cloned.uuid;
                    db.root.entries.push(cloned);
                    sess.selected_entry = Some(new_id);
                    sess.dirty = true;
                    self.status_message = "Cloned entry".to_string();
                }
            }
            PaletteAction::DeleteEntry => {
                if let Some(sess) = self.active_session_mut()
                    && let Some(ref mut db) = sess.db
                    && let Some(sel) = sess.selected_entry
                    && db.delete_entry_by_uuid(sel, false).is_ok()
                {
                    sess.selected_entry = None;
                    sess.dirty = true;
                    self.status_message = "Entry moved to Recycle Bin".to_string();
                }
            }
            PaletteAction::CopyUsername => {
                let val = self
                    .active_session()
                    .and_then(|s| s.db.as_ref().zip(s.selected_entry))
                    .and_then(|(db, id)| db.root.find_entry_by_uuid(id))
                    .map(|e| e.username.clone());
                if let Some(u) = val {
                    self.copy_with_auto_clear("username", &u);
                }
            }
            PaletteAction::CopyPassword => {
                let val = self
                    .active_session()
                    .and_then(|s| s.db.as_ref().zip(s.selected_entry))
                    .and_then(|(db, id)| db.root.find_entry_by_uuid(id))
                    .map(|e| ProtectedString::new(e.password.as_str()));
                if let Some(pw) = val {
                    self.copy_with_auto_clear("password", pw.as_str());
                }
            }
            PaletteAction::CopyTotp => {
                let code_res = self
                    .active_session()
                    .and_then(|s| s.db.as_ref().zip(s.selected_entry))
                    .and_then(|(db, id)| db.root.find_entry_by_uuid(id))
                    .map(|e| TotpConfig::from_entry(e).and_then(|c| c.generate_now()));
                match code_res {
                    Some(Ok((code, _))) => self.copy_with_auto_clear("TOTP code", &code),
                    Some(Err(e)) => self.status_message = e.to_string(),
                    None => {}
                }
            }
            PaletteAction::OpenUrl => {
                if let Some(url) = self
                    .active_session()
                    .and_then(|s| s.db.as_ref().zip(s.selected_entry))
                    .and_then(|(db, id)| db.root.find_entry_by_uuid(id))
                    .map(|e| e.url.trim().to_string())
                    && (url.starts_with("https://") || url.starts_with("http://"))
                {
                    let _ = open::that(&url);
                    self.status_message = format!("Opened {url}");
                }
            }
            PaletteAction::PerformAutoType => {
                let compiled = self
                    .active_session()
                    .and_then(|s| s.db.as_ref().zip(s.selected_entry))
                    .and_then(|(db, id)| db.root.find_entry_by_uuid(id))
                    .map(|e| compile_autotype_sequence(e, None));
                if let Some(Ok(actions)) = compiled {
                    match execute_autotype(&actions, true) {
                        Ok(()) => self.status_message = "Auto-Type sequence dispatched".to_string(),
                        Err(e) => self.status_message = format!("Auto-Type error: {e}"),
                    }
                }
            }
            PaletteAction::OpenGenerator => {
                self.generator_modal.open = true;
            }
            PaletteAction::OpenSecurityAudit => {
                if let Some(sess) = self.active_session()
                    && let Some(ref db) = sess.db
                    && let Ok(rep) = analyze_database(db, None)
                {
                    self.audit_modal.report = Some(rep);
                    self.audit_modal.open = true;
                }
            }
            PaletteAction::OpenDbSettings => {
                if let Some(sess) = self.sessions.get(self.active_tab)
                    && let Some(ref db) = sess.db
                {
                    self.db_settings_modal.load_from(db);
                }
            }
            PaletteAction::ExportCsv => self.pending_export = Some((ExportFormat::Csv, "csv")),
            PaletteAction::ExportXml => self.pending_export = Some((ExportFormat::Xml, "xml")),
            PaletteAction::ExportHtml => {
                self.pending_export = Some((ExportFormat::Html, "html"));
            }
            PaletteAction::ToggleLanguage => {
                self.settings.language = match self.settings.language {
                    Language::English => Language::French,
                    Language::French => Language::English,
                };
                self.settings.save();
            }
            PaletteAction::ShowShortcuts => {
                self.show_shortcuts = true;
            }
        }
    }

    fn export_dialog(&mut self, fmt: ExportFormat, ext: &str) {
        let content = self
            .active_session()
            .and_then(|sess| sess.db.as_ref().map(|db| export_database(db, fmt)));
        let Some(content) = content else {
            self.status_message = "Export failed: no unlocked vault".to_string();
            return;
        };
        match content {
            Ok(content) => {
                if let Some(dest) = rfd::FileDialog::new()
                    .set_file_name(format!("vault-export.{ext}"))
                    .save_file()
                {
                    match std::fs::write(&dest, content) {
                        Ok(()) => {
                            self.status_message = format!("Exported {ext} to {}", dest.display());
                        }
                        Err(e) => self.status_message = format!("Export failed: {e}"),
                    }
                }
            }
            Err(e) => self.status_message = format!("Export failed: {e}"),
        }
    }

    fn open_showcase_demo_vault(&mut self) {
        let mut db = Database::new("RustPass Showcase Vault");
        db.meta.database_description =
            "Interactive clean-room KDBX 4.0 demonstration vault".to_string();
        db.meta.default_username = "laurent@acme-sec.io".to_string();

        let mut e1 = Entry::new("GitHub Enterprise");
        e1.username = "laurent-sec".to_string();
        e1.password = "K9#vM2$pL8@qR5!xZ4&nW7".into();
        e1.url = "https://github.com/login".to_string();
        e1.notes = "Primary engineering org account · Hardware SSH keys enrolled.".to_string();
        e1.tags = vec!["dev".to_string(), "critical".to_string(), "2fa".to_string()];
        e1.otp = Some(
            "otpauth://totp/GitHub:laurent-sec?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&period=30&digits=6&algorithm=SHA1"
                .into(),
        );
        e1.set_custom_attribute("Recovery Token", "ghr-9942-ABCD-EF01", true);
        e1.attachments.push(Attachment {
            name: "ssh_ed25519.pub".to_string(),
            data: b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIRustPassCleanRoomDemoKey laurent@workstation\n"
                .to_vec(),
            protected: false,
        });
        let _ = db.add_entry_at_path("Engineering/GitHub Enterprise", e1);

        let mut e2 = Entry::new("PostgreSQL Production Cluster");
        e2.username = "pg_superadmin".to_string();
        e2.password = "Aurora-Bastion-Cipher-Cobalt84-Citadel".into();
        e2.url = "https://db-console.internal.example".to_string();
        e2.notes = "Primary EU-West-3 RDS cluster · Rotated every 90 days.".to_string();
        e2.tags = vec!["database".to_string(), "prod".to_string()];
        e2.otp = Some(
            "otpauth://totp/AWS-RDS:pg_superadmin?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=AWS"
                .into(),
        );
        let _ = db.add_entry_at_path("Infrastructure/PostgreSQL Production Cluster", e2);

        let mut e3 = Entry::new("Cloudflare Zero Trust");
        e3.username = "secops@acme-sec.io".to_string();
        e3.password = "V7!zT3#bN9@mK6$wP2^yH8*cF5".into();
        e3.url = "https://dash.cloudflare.com".to_string();
        e3.tags = vec!["network".to_string(), "dns".to_string()];
        e3.otp = Some(
            "otpauth://totp/Cloudflare:secops?secret=MFRGGZDFMZTWQ2LK&issuer=Cloudflare".into(),
        );
        let _ = db.add_entry_at_path("Infrastructure/Cloudflare Zero Trust", e3);

        let mut e4 = Entry::new("Steam Guard Partner Account");
        e4.username = "studio_buildbot".to_string();
        e4.password = "Amber-Bonsai-Cascade-37-Falcon".into();
        e4.url = "https://store.steampowered.com".to_string();
        e4.otp = Some(
            "otpauth://totp/Steam:studio_buildbot?secret=JBSWY3DPEHPK3PXP&issuer=Steam&encoder=steam"
                .into(),
        );
        let _ = db.add_entry_at_path("Gaming & Media/Steam Guard Partner Account", e4);

        let mut e5 = Entry::new("Legacy Lab Switch (Audit Sample)");
        e5.username = "admin".to_string();
        e5.password = "admin123".into();
        e5.url = "http://192.168.10.254".to_string();
        e5.notes = "Intentionally weak HTTP entry to showcase Security Health Audit.".to_string();
        let _ = db.add_entry_at_path("Lab/Legacy Lab Switch (Audit Sample)", e5);

        let creds = MasterCredentials::with_password("demo-master-password");
        let sess = VaultSession::from_unlocked(None, creds, db);
        self.sessions.push(sess);
        self.active_tab = self.sessions.len() - 1;
        self.status_message =
            "Loaded interactive KDBX 4.0 Showcase Vault (Press Ctrl+S to save as .kdbx)"
                .to_string();
    }
}

impl RustPassApp {
    /// Renders the complete application layout (top bars, status bar, active view, and open modals).
    pub fn render_frame(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();

        self.render_top_bars(ui, &ctx);
        self.render_status_bar(ui);

        if self.sessions.is_empty() {
            self.render_welcome_screen(ui, &ctx);
        } else if self
            .sessions
            .get(self.active_tab)
            .is_some_and(|s| s.db.is_none())
        {
            self.render_locked_tab_screen(ui, &ctx);
        } else {
            self.render_unlocked_vault(ui, &ctx);
        }

        // Modals
        if let Some(act) = self.cmd_palette.ui(&ctx, self.settings.language) {
            self.trigger_action(act);
        }

        if let Some(saved) = self.entry_editor.ui(
            &ctx,
            &self.palette,
            texts(self.settings.language),
            &self.settings.password_generator,
        ) {
            let mut should_autosave = false;
            if let Some(sess) = self.sessions.get_mut(self.active_tab)
                && let Some(ref mut db) = sess.db
            {
                apply_saved_entry(db, saved, &mut sess.selected_entry);
                sess.dirty = true;
                sess.inspector_qr_cache = None;
                should_autosave = self.settings.auto_save_on_change && sess.path.is_some();
            }
            if should_autosave {
                self.save_active_vault(false);
            }
        }

        if let Some(secret) =
            self.generator_modal
                .ui(&ctx, &self.palette, texts(self.settings.language))
        {
            self.settings.password_generator = self.generator_modal.pw_opts.clone();
            self.settings.diceware_generator = self.generator_modal.dw_opts.clone();
            self.settings.save();
            self.copy_with_auto_clear("generated password", &secret);
        }

        if let Some(jump_id) = self
            .audit_modal
            .ui(&ctx, &self.palette, self.settings.language)
            && let Some(sess) = self.active_session_mut()
        {
            sess.sidebar_filter = SidebarFilter::AllEntries;
            sess.selected_entry = Some(jump_id);
        }

        if self.db_settings_modal.open {
            let palette = self.palette;
            if let Some(sess) = self.sessions.get_mut(self.active_tab)
                && let Some(ref mut db) = sess.db
                && self
                    .db_settings_modal
                    .ui(&ctx, db, &palette, texts(self.settings.language))
            {
                sess.dirty = true;
                self.status_message = "Updated database encryption settings".to_string();
            }
        }

        self.render_confirm_close_modal(&ctx);
        self.render_confirm_export_modal(&ctx);

        show_shortcuts_window(&ctx, &mut self.show_shortcuts);
        show_about_window(&ctx, &mut self.show_about, &self.palette);

        if self.close_viewport_requested {
            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
        }
    }
}

impl eframe::App for RustPassApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_clipboard_and_autolock(ctx);
        self.handle_shortcuts(ctx);

        if self.settings.theme == ThemeChoice::FollowSystem {
            // One registry read + restyle at most every 5 s, never per frame.
            let now = Instant::now();
            if now.duration_since(self.follow_system_last_poll) >= Duration::from_secs(5) {
                self.follow_system_last_poll = now;
                self.palette = apply_theme(ctx, ThemeChoice::FollowSystem);
            }
            ctx.request_repaint_after(Duration::from_secs(5));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.render_frame(ui);
    }
}

fn apply_saved_entry(
    db: &mut Database,
    payload: SavedEntryPayload,
    selected_entry: &mut Option<Uuid>,
) {
    if payload.is_new {
        let new_id = payload.entry.uuid;
        if let Some(grp) = db.root.find_group_by_uuid_mut(payload.target_group_uuid) {
            grp.entries.push(payload.entry);
        } else {
            db.root.entries.push(payload.entry);
        }
        *selected_entry = Some(new_id);
    } else {
        let history_max = db.meta.history_max_items;
        let id = payload.entry.uuid;
        if let Some(existing) = db.root.find_entry_by_uuid_mut(id) {
            existing.push_history_snapshot(history_max);
            let preserved_history = existing.history.clone();
            *existing = payload.entry;
            existing.history = preserved_history;
            existing.times.touch_modified();
        }
        *selected_entry = Some(id);
    }
}

impl RustPassApp {
    fn render_top_bars(&mut self, root_ui: &mut egui::Ui, ctx: &egui::Context) {
        let lang = self.settings.language;
        let t = texts(lang);
        let has_unlocked = self.active_session().is_some_and(|s| s.db.is_some());

        egui::Panel::top("rustpass_menubar").show(root_ui, |ui| {
            egui::MenuBar::new().ui(ui, |ui| {
                ui.menu_button(t.menu_database, |ui| {
                    if ui.button(t.new_database).clicked() {
                        ui.close();
                        self.request_close(PendingClose::NewVault);
                    }
                    if ui.button(t.open_database).clicked() {
                        ui.close();
                        self.prompt_open_file_dialog();
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.save_database))
                        .clicked()
                    {
                        ui.close();
                        self.save_active_vault(false);
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.save_as))
                        .clicked()
                    {
                        ui.close();
                        self.save_active_vault(true);
                    }
                    ui.separator();
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.db_settings))
                        .clicked()
                    {
                        ui.close();
                        self.trigger_action(PaletteAction::OpenDbSettings);
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.merge_kdbx))
                        .clicked()
                    {
                        ui.close();
                        let picked = rfd::FileDialog::new()
                            .add_filter("KeePass Vault", &["kdbx"])
                            .pick_file();
                        if let Some(src_path) = picked.as_ref()
                            && let Some(sess) = self.active_session_mut()
                            && sess.db.is_some()
                        {
                            if let Some(ref mut dst_db) = sess.db {
                                match Database::open(src_path, &sess.credentials) {
                                    Ok(src_db) => {
                                        let rep = dst_db.merge_from(&src_db, false);
                                        sess.dirty = true;
                                        self.status_message = format!(
                                            "Merged +{} added, ~{} updated",
                                            rep.entries_added.len(),
                                            rep.entries_updated.len()
                                        );
                                    }
                                    Err(e) => {
                                        self.status_message = format!(
                                            "Merge failed for {}: {e} (different master password?)",
                                            src_path.display()
                                        )
                                    }
                                }
                            }
                        } else if picked.is_some() {
                            self.status_message = "Merge cancelled: no unlocked vault".to_string();
                        }
                    }
                    ui.separator();
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.import_csv))
                        .clicked()
                    {
                        ui.close();
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("CSV", &["csv"])
                            .pick_file()
                        {
                            match std::fs::read_to_string(&p) {
                                Ok(raw) => {
                                    if let Some(sess) = self.active_session_mut()
                                        && let Some(ref mut db) = sess.db
                                    {
                                        match import_csv_into(db, &raw) {
                                            Ok(n) => {
                                                sess.dirty = true;
                                                self.status_message =
                                                    format!("Imported {n} CSV entries");
                                            }
                                            Err(e) => {
                                                self.status_message =
                                                    format!("CSV import failed: {e}")
                                            }
                                        }
                                    } else {
                                        self.status_message =
                                            "CSV import failed: no unlocked vault".to_string();
                                    }
                                }
                                Err(e) => {
                                    self.status_message =
                                        format!("CSV import failed reading {}: {e}", p.display())
                                }
                            }
                        }
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.import_xml))
                        .clicked()
                    {
                        ui.close();
                        if let Some(p) = rfd::FileDialog::new()
                            .add_filter("XML", &["xml"])
                            .pick_file()
                        {
                            match std::fs::read_to_string(&p)
                                .map_err(|e| e.to_string())
                                .and_then(|raw| import_keepass_xml(&raw).map_err(|e| e.to_string()))
                            {
                                Ok(src_db) => {
                                    if let Some(sess) = self.active_session_mut()
                                        && let Some(ref mut db) = sess.db
                                    {
                                        let rep = db.merge_from(&src_db, false);
                                        sess.dirty = true;
                                        self.status_message = format!(
                                            "Imported {} XML entries",
                                            rep.entries_added.len()
                                        );
                                    } else {
                                        self.status_message =
                                            "XML import failed: no unlocked vault".to_string();
                                    }
                                }
                                Err(e) => self.status_message = format!("XML import failed: {e}"),
                            }
                        }
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.export_csv))
                        .clicked()
                    {
                        ui.close();
                        self.pending_export = Some((ExportFormat::Csv, "csv"));
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.export_xml))
                        .clicked()
                    {
                        ui.close();
                        self.pending_export = Some((ExportFormat::Xml, "xml"));
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.export_html))
                        .clicked()
                    {
                        ui.close();
                        self.pending_export = Some((ExportFormat::Html, "html"));
                    }
                    ui.separator();
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.lock_vault))
                        .clicked()
                    {
                        ui.close();
                        self.trigger_action(PaletteAction::LockVault);
                    }
                    if ui
                        .add_enabled(!self.sessions.is_empty(), egui::Button::new(t.close_vault))
                        .clicked()
                    {
                        ui.close();
                        self.request_close(PendingClose::Tab(self.active_tab));
                    }
                    if ui.button(t.quit).clicked() {
                        ui.close();
                        self.request_close(PendingClose::Quit);
                    }
                });

                ui.menu_button(t.menu_entries, |ui| {
                    for (lbl, act) in [
                        (t.add_entry, PaletteAction::AddEntry),
                        (t.edit_entry, PaletteAction::EditEntry),
                        (t.clone_entry, PaletteAction::CloneEntry),
                        (t.delete_entry, PaletteAction::DeleteEntry),
                        (t.copy_username, PaletteAction::CopyUsername),
                        (t.copy_password, PaletteAction::CopyPassword),
                        (t.copy_totp, PaletteAction::CopyTotp),
                        (t.open_url, PaletteAction::OpenUrl),
                        (t.perform_autotype, PaletteAction::PerformAutoType),
                    ] {
                        if ui
                            .add_enabled(has_unlocked, egui::Button::new(lbl))
                            .clicked()
                        {
                            ui.close();
                            self.trigger_action(act);
                        }
                    }
                });

                ui.menu_button(t.menu_tools, |ui| {
                    if ui.button(t.password_generator).clicked() {
                        ui.close();
                        self.generator_modal.open = true;
                    }
                    if ui
                        .add_enabled(has_unlocked, egui::Button::new(t.security_audit))
                        .clicked()
                    {
                        ui.close();
                        self.trigger_action(PaletteAction::OpenSecurityAudit);
                    }
                    if ui.button(t.command_palette).clicked() {
                        ui.close();
                        self.cmd_palette.show();
                    }
                });

                ui.menu_button(t.menu_view, |ui| {
                    ui.menu_button(t.theme_menu, |ui| {
                        for choice in ThemeChoice::ALL {
                            if ui
                                .radio_value(&mut self.settings.theme, choice, choice.label())
                                .clicked()
                            {
                                self.palette = apply_theme(ctx, choice);
                                self.settings.save();
                                ui.close();
                            }
                        }
                    });
                    ui.menu_button(t.language_menu, |ui| {
                        for l in [Language::French, Language::English] {
                            if ui
                                .radio_value(&mut self.settings.language, l, l.label())
                                .clicked()
                            {
                                self.settings.save();
                                ui.close();
                            }
                        }
                    });
                });

                ui.menu_button(t.menu_help, |ui| {
                    if ui.button(t.shortcuts_help).clicked() {
                        ui.close();
                        self.show_shortcuts = true;
                    }
                    if ui.button(t.about).clicked() {
                        ui.close();
                        self.show_about = true;
                    }
                });
            });
        });

        if !self.sessions.is_empty() {
            egui::Panel::top("rustpass_tabs_and_toolbar").show(root_ui, |ui| {
                // Multi-vault tab strip
                ui.horizontal(|ui| {
                    let mut close_idx = None;
                    for i in 0..self.sessions.len() {
                        let title = self.sessions[i].tab_title();
                        let selected = i == self.active_tab;
                        if ui
                            .selectable_label(selected, RichText::new(title).strong())
                            .clicked()
                        {
                            self.active_tab = i;
                        }
                        if ui.small_button("×").clicked() {
                            close_idx = Some(i);
                        }
                        ui.separator();
                    }
                    if let Some(idx) = close_idx {
                        self.request_close(PendingClose::Tab(idx));
                    }
                    if ui.small_button(t.tb_open).clicked() {
                        self.prompt_open_file_dialog();
                    }
                });

                if self
                    .sessions
                    .get(self.active_tab)
                    .is_some_and(|s| s.db.is_some())
                {
                    ui.separator();
                    ui.horizontal(|ui| {
                        if ui
                            .button(
                                RichText::new(t.tb_add_entry)
                                    .color(self.palette.accent)
                                    .strong(),
                            )
                            .on_hover_text(t.add_entry)
                            .clicked()
                        {
                            self.trigger_action(PaletteAction::AddEntry);
                        }
                        if ui.button(t.btn_edit).on_hover_text(t.edit_entry).clicked() {
                            self.trigger_action(PaletteAction::EditEntry);
                        }
                        if ui
                            .button(t.tb_save)
                            .on_hover_text(t.save_database)
                            .clicked()
                        {
                            self.save_active_vault(false);
                        }
                        ui.separator();
                        if ui
                            .button(t.tb_copy_user)
                            .on_hover_text(t.copy_username)
                            .clicked()
                        {
                            self.trigger_action(PaletteAction::CopyUsername);
                        }
                        if ui
                            .button(t.tb_copy_pass)
                            .on_hover_text(t.copy_password)
                            .clicked()
                        {
                            self.trigger_action(PaletteAction::CopyPassword);
                        }
                        if ui
                            .button(t.tb_copy_2fa)
                            .on_hover_text(t.copy_totp)
                            .clicked()
                        {
                            self.trigger_action(PaletteAction::CopyTotp);
                        }
                        if ui
                            .button(t.tb_autotype)
                            .on_hover_text(t.perform_autotype)
                            .clicked()
                        {
                            self.trigger_action(PaletteAction::PerformAutoType);
                        }
                        ui.separator();
                        if ui.button(t.tb_generator).clicked() {
                            self.generator_modal.open = true;
                        }
                        if ui.button(t.tb_health).clicked() {
                            self.trigger_action(PaletteAction::OpenSecurityAudit);
                        }
                        if self.active_session().is_some_and(|s| s.path.is_some())
                            && ui.button(t.tb_lock).clicked()
                        {
                            self.trigger_action(PaletteAction::LockVault);
                        }

                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if let Some(sess) = self.sessions.get_mut(self.active_tab) {
                                if !sess.search_query.is_empty() && ui.small_button("×").clicked()
                                {
                                    sess.search_query.clear();
                                }
                                let search_resp = ui.add(
                                    egui::TextEdit::singleline(&mut sess.search_query)
                                        .desired_width(270.0)
                                        .hint_text(t.search_placeholder),
                                );
                                if self.focus_search_next {
                                    search_resp.request_focus();
                                    self.focus_search_next = false;
                                }
                            }
                        });
                    });
                }
            });
        }
    }

    fn render_status_bar(&self, root_ui: &mut egui::Ui) {
        let t = texts(self.settings.language);
        egui::Panel::bottom("rustpass_statusbar").show(root_ui, |ui| {
            ui.horizontal(|ui| {
                if let Some(sess) = self.active_session()
                    && let Some(ref db) = sess.db
                {
                    ui.colored_label(
                        self.palette.accent,
                        RichText::new(format!(
                            "{} · {} · {}",
                            db.version.label(),
                            db.cipher.name(),
                            db.kdf.summary()
                        ))
                        .size(11.5)
                        .strong(),
                    );
                    ui.separator();
                    ui.label(
                        RichText::new(format!("{} entries", db.all_entries(false).len()))
                            .size(11.5),
                    );
                    ui.separator();
                }

                ui.label(RichText::new(&self.status_message).size(11.5).weak());

                if let Some(ref guard) = self.clipboard_guard {
                    let rem = guard
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_secs_f32();
                    let total = self.settings.clipboard_clear_seconds.max(1) as f32;
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        ui.add(
                            egui::ProgressBar::new((rem / total).clamp(0.0, 1.0))
                                .desired_width(130.0)
                                .fill(self.palette.warning)
                                .text(format!("{} {:.0}s", t.clipboard_clearing_in, rem.ceil())),
                        );
                    });
                }
            });
        });
    }

    fn render_welcome_screen(&mut self, root_ui: &mut egui::Ui, ctx: &egui::Context) {
        let t = texts(self.settings.language);
        let palette = self.palette;

        egui::CentralPanel::default().show(root_ui, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(28.0);
                ui.label(
                    RichText::new("RustPass")
                        .size(34.0)
                        .strong()
                        .color(palette.accent),
                );
                ui.label(RichText::new(t.welcome_subtitle).size(13.5).weak());
                ui.add_space(18.0);
            });

            ui.columns(2, |cols| {
                // Left Card: Unlock or Create Vault
                egui::Frame::group(cols[0].style())
                    .fill(palette.bg_surface)
                    .inner_margin(20.0)
                    .show(&mut cols[0], |ui| {
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.welcome_mode,
                                WelcomeMode::UnlockExisting,
                                "Unlock Existing .kdbx",
                            );
                            ui.selectable_value(
                                &mut self.welcome_mode,
                                WelcomeMode::CreateNew,
                                "Create New .kdbx Vault",
                            );
                        });
                        ui.separator();
                        ui.add_space(6.0);

                        if self.welcome_mode == WelcomeMode::CreateNew {
                            ui.label("Vault Display Name");
                            ui.add(
                                egui::TextEdit::singleline(&mut self.welcome_vault_name)
                                    .desired_width(f32::INFINITY),
                            );
                            ui.add_space(6.0);
                        }

                        ui.label(t.wl_db_file);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.welcome_db_path)
                                    .hint_text(r"D:\Vaults\passwords.kdbx")
                                    .desired_width(300.0),
                            );
                            if ui.button(t.btn_browse).clicked() {
                                let picked = match self.welcome_mode {
                                    WelcomeMode::UnlockExisting => rfd::FileDialog::new()
                                        .add_filter("KeePass Vault", &["kdbx"])
                                        .pick_file(),
                                    WelcomeMode::CreateNew => rfd::FileDialog::new()
                                        .add_filter("KeePass Vault", &["kdbx"])
                                        .set_file_name("passwords.kdbx")
                                        .save_file(),
                                };
                                if let Some(p) = picked {
                                    self.welcome_db_path = p.display().to_string();
                                }
                            }
                        });

                        ui.add_space(6.0);
                        ui.label(t.master_password);
                        ui.horizontal(|ui| {
                            let resp = ui.add(
                                egui::TextEdit::singleline(&mut self.welcome_pw)
                                    .password(!self.welcome_show_pw)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(300.0),
                            );
                            if ui
                                .button(if self.welcome_show_pw {
                                    t.btn_hide
                                } else {
                                    t.btn_show
                                })
                                .clicked()
                            {
                                self.welcome_show_pw = !self.welcome_show_pw;
                            }
                            if resp.lost_focus()
                                && ctx.input(|i| i.key_pressed(Key::Enter))
                                && self.welcome_mode == WelcomeMode::UnlockExisting
                            {
                                self.submit_welcome_form();
                            }
                        });

                        if self.welcome_mode == WelcomeMode::CreateNew {
                            ui.add_space(6.0);
                            ui.label(t.confirm_password);
                            ui.add(
                                egui::TextEdit::singleline(&mut self.welcome_pw_confirm)
                                    .password(!self.welcome_show_pw)
                                    .font(egui::TextStyle::Monospace)
                                    .desired_width(300.0),
                            );
                        }

                        ui.add_space(6.0);
                        ui.label(t.key_file_optional);
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.welcome_keyfile_path)
                                    .hint_text(t.wl_keyfile_hint)
                                    .desired_width(240.0),
                            );
                            if ui.button(t.btn_select).clicked()
                                && let Some(kf) = rfd::FileDialog::new().pick_file()
                            {
                                self.welcome_keyfile_path = kf.display().to_string();
                            }
                            if self.welcome_mode == WelcomeMode::CreateNew
                                && ui.button(t.wl_new_keyx).clicked()
                                && let Some(kf) = rfd::FileDialog::new()
                                    .set_file_name("vault.keyx")
                                    .save_file()
                                && write_new_keyfile(&kf, true).is_ok()
                            {
                                self.welcome_keyfile_path = kf.display().to_string();
                            }
                        });

                        if let Some(ref err) = self.welcome_error {
                            ui.add_space(6.0);
                            ui.colored_label(palette.danger, err);
                        }

                        ui.add_space(12.0);
                        let btn_label = match self.welcome_mode {
                            WelcomeMode::UnlockExisting => t.unlock_button,
                            WelcomeMode::CreateNew => t.create_button,
                        };
                        if ui
                            .button(
                                RichText::new(btn_label)
                                    .size(15.0)
                                    .strong()
                                    .color(palette.accent),
                            )
                            .clicked()
                        {
                            self.submit_welcome_form();
                        }
                    });

                // Right Card: Recent Databases & Showcase Demo Vault
                egui::Frame::group(cols[1].style())
                    .fill(palette.bg_surface)
                    .inner_margin(20.0)
                    .show(&mut cols[1], |ui| {
                        ui.label(RichText::new(t.recent_databases).size(15.5).strong());
                        ui.separator();

                        let recents = self.settings.recent_databases.clone();
                        if recents.is_empty() {
                            ui.weak(t.wl_no_recents);
                        } else {
                            for p in recents {
                                let label = p.display().to_string();
                                if ui.link(&label).clicked() {
                                    self.welcome_db_path = label;
                                    self.welcome_mode = WelcomeMode::UnlockExisting;
                                }
                            }
                        }

                        ui.add_space(20.0);
                        ui.separator();
                        ui.label(RichText::new(t.wl_showcase_title).size(15.0).strong());
                        ui.weak(t.wl_showcase_blurb);
                        ui.add_space(8.0);
                        if ui
                            .button(
                                RichText::new(t.wl_showcase_open)
                                    .strong()
                                    .color(palette.accent),
                            )
                            .clicked()
                        {
                            self.open_showcase_demo_vault();
                        }
                    });
            });
        });
    }

    fn submit_welcome_form(&mut self) {
        let t = texts(self.settings.language);
        self.welcome_error = None;
        let db_path_str = self.welcome_db_path.trim();
        if db_path_str.is_empty() {
            self.welcome_error = Some("Please select or enter a .kdbx file path.".to_string());
            return;
        }
        let db_path = PathBuf::from(db_path_str);
        let kf_opt = if self.welcome_keyfile_path.trim().is_empty() {
            None
        } else {
            Some(PathBuf::from(self.welcome_keyfile_path.trim()))
        };
        let pw_opt = if self.welcome_pw.is_empty() && kf_opt.is_some() {
            None
        } else {
            Some(self.welcome_pw.clone())
        };

        match self.welcome_mode {
            WelcomeMode::UnlockExisting => {
                match MasterCredentials::new(pw_opt, kf_opt.as_deref())
                    .and_then(|creds| Database::open(&db_path, &creds).map(|db| (db, creds)))
                {
                    Ok((db, creds)) => {
                        self.welcome_pw.zeroize();
                        self.settings.record_recent(db_path.clone());
                        self.sessions
                            .push(VaultSession::from_unlocked(Some(db_path), creds, db));
                        self.active_tab = self.sessions.len() - 1;
                    }
                    Err(e) => {
                        self.welcome_error = Some(e.to_string());
                    }
                }
            }
            WelcomeMode::CreateNew => {
                if self.welcome_pw != self.welcome_pw_confirm {
                    self.welcome_error = Some(t.wl_pw_mismatch.to_string());
                    return;
                }
                let mut db = Database::new(self.welcome_vault_name.trim());
                for folder in ["General", "Internet", "Infrastructure", "Finance"] {
                    let _ = db.mkdir_p(folder);
                }
                match MasterCredentials::new(pw_opt, kf_opt.as_deref()).and_then(|creds| {
                    db.save_atomic(&db_path, &creds)?;
                    Ok(creds)
                }) {
                    Ok(creds) => {
                        self.welcome_pw.zeroize();
                        self.welcome_pw_confirm.zeroize();
                        self.settings.record_recent(db_path.clone());
                        self.sessions
                            .push(VaultSession::from_unlocked(Some(db_path), creds, db));
                        self.active_tab = self.sessions.len() - 1;
                    }
                    Err(e) => {
                        self.welcome_error = Some(e.to_string());
                    }
                }
            }
        }
    }

    fn render_locked_tab_screen(&mut self, root_ui: &mut egui::Ui, ctx: &egui::Context) {
        let t = texts(self.settings.language);
        let palette = self.palette;
        egui::CentralPanel::default().show(root_ui, |ui| {
            let Some(sess) = self.sessions.get_mut(self.active_tab) else {
                return;
            };
            let path_display = sess
                .path
                .as_ref()
                .map_or_else(|| "Vault".to_string(), |p| p.display().to_string());

            ui.vertical_centered(|ui| {
                ui.add_space(80.0);
                ui.label(
                    RichText::new(t.locked_title)
                        .size(26.0)
                        .strong()
                        .color(palette.accent),
                );
                ui.label(&path_display);
                ui.add_space(16.0);

                let resp = ui.add(
                    egui::TextEdit::singleline(&mut sess.unlock_pw_buf)
                        .password(true)
                        .hint_text(t.locked_hint)
                        .desired_width(300.0),
                );
                let enter = resp.lost_focus() && ctx.input(|i| i.key_pressed(Key::Enter));
                ui.add_space(8.0);
                if (ui
                    .button(
                        RichText::new(t.unlock_button)
                            .strong()
                            .color(palette.accent),
                    )
                    .clicked()
                    || enter)
                    && let Some(ref p) = sess.path
                {
                    let pw_opt = if sess.unlock_pw_buf.is_empty()
                        && sess.credentials.keyfile_path.is_some()
                    {
                        None
                    } else {
                        Some(sess.unlock_pw_buf.clone())
                    };
                    match MasterCredentials::new(pw_opt, sess.credentials.keyfile_path.as_deref())
                        .and_then(|c| Database::open(p, &c).map(|db| (db, c)))
                    {
                        Ok((db, creds)) => {
                            sess.unlock_pw_buf.zeroize();
                            sess.unlock_error = None;
                            sess.credentials = creds;
                            sess.db = Some(db);
                        }
                        Err(e) => {
                            sess.unlock_error = Some(e.to_string());
                        }
                    }
                }

                if let Some(ref err) = sess.unlock_error {
                    ui.add_space(6.0);
                    ui.colored_label(palette.danger, err);
                }
            });
        });
    }

    fn render_unlocked_vault(&mut self, root_ui: &mut egui::Ui, ctx: &egui::Context) {
        let lang = self.settings.language;
        let t = texts(lang);
        let palette = self.palette;
        // Vault mutations requested from panel closures, applied once borrows release.
        let mut db_action: Option<VaultDbAction> = None;

        // 1. Left Sidebar: Smart Filters + Group Hierarchy
        egui::Panel::left("rustpass_groups_sidebar")
            .resizable(true)
            .default_size(235.0)
            .min_size(180.0)
            .show(root_ui, |ui| {
                let Some(sess) = self.sessions.get_mut(self.active_tab) else {
                    return;
                };
                let Some(ref mut db) = sess.db else {
                    return;
                };

                ui.add_space(6.0);
                ui.label(
                    RichText::new(t.groups_header)
                        .size(11.0)
                        .strong()
                        .color(palette.text_muted),
                );
                ui.add_space(4.0);

                let total_active = db.all_entries(false).len();
                if ui
                    .selectable_label(
                        sess.sidebar_filter == SidebarFilter::AllEntries,
                        format!("{} ({total_active})", t.all_entries),
                    )
                    .clicked()
                {
                    sess.sidebar_filter = SidebarFilter::AllEntries;
                }
                if ui
                    .selectable_label(
                        sess.sidebar_filter == SidebarFilter::TotpOnly,
                        t.totp_entries,
                    )
                    .clicked()
                {
                    sess.sidebar_filter = SidebarFilter::TotpOnly;
                }
                if ui
                    .selectable_label(
                        sess.sidebar_filter == SidebarFilter::WeakOrReused,
                        t.weak_entries,
                    )
                    .clicked()
                {
                    sess.sidebar_filter = SidebarFilter::WeakOrReused;
                }
                if ui
                    .selectable_label(
                        sess.sidebar_filter == SidebarFilter::ExpiredOnly,
                        t.expired_entries,
                    )
                    .clicked()
                {
                    sess.sidebar_filter = SidebarFilter::ExpiredOnly;
                }

                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    render_group_tree_node(
                        ui,
                        &db.root,
                        db.meta.recycle_bin_uuid,
                        0,
                        &mut sess.sidebar_filter,
                    );
                });

                // Trash / group management row for the selected group.
                if let SidebarFilter::Group(gid) = sess.sidebar_filter {
                    ui.separator();
                    if !db.meta.recycle_bin_uuid.is_nil() && gid == db.meta.recycle_bin_uuid {
                        ui.horizontal(|ui| {
                            if ui.small_button(t.trash_restore_all).clicked() {
                                db_action = Some(VaultDbAction::RestoreAllTrash);
                            }
                            if self.pending_empty_trash {
                                if ui
                                    .small_button(
                                        RichText::new(t.trash_empty_confirm).color(palette.danger),
                                    )
                                    .clicked()
                                {
                                    db_action = Some(VaultDbAction::EmptyTrash);
                                    self.pending_empty_trash = false;
                                }
                            } else if ui.small_button(t.trash_empty).clicked() {
                                self.pending_empty_trash = true;
                            }
                        });
                    } else {
                        ui.horizontal(|ui| {
                            let hint = db
                                .root
                                .find_group_by_uuid(gid)
                                .map_or_else(String::new, |g| g.name.clone());
                            ui.add(
                                egui::TextEdit::singleline(&mut self.group_rename_buf)
                                    .hint_text(hint)
                                    .desired_width(110.0),
                            );
                            if ui.small_button(t.grp_rename).clicked()
                                && !self.group_rename_buf.trim().is_empty()
                            {
                                db_action = Some(VaultDbAction::RenameGroup(
                                    gid,
                                    self.group_rename_buf.trim().to_string(),
                                ));
                                self.group_rename_buf.clear();
                            }
                            if self.pending_group_delete == Some(gid) {
                                if ui
                                    .small_button(
                                        RichText::new(t.grp_delete_confirm).color(palette.danger),
                                    )
                                    .clicked()
                                {
                                    db_action = Some(VaultDbAction::DeleteGroup(gid));
                                    self.pending_group_delete = None;
                                    sess.sidebar_filter = SidebarFilter::AllEntries;
                                }
                            } else if ui.small_button(t.grp_delete).clicked() {
                                self.pending_group_delete = Some(gid);
                            }
                        });
                    }
                }

                ui.separator();
                let mut clear_prompt = false;
                if let Some(ref mut folder_name) = sess.new_group_prompt {
                    ui.horizontal(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(folder_name)
                                .hint_text(t.sidebar_group_hint)
                                .desired_width(120.0),
                        );
                        if ui.small_button(t.btn_add).clicked() && !folder_name.trim().is_empty() {
                            let name = folder_name.trim().to_string();
                            let parent_id = match sess.sidebar_filter {
                                SidebarFilter::Group(id) => id,
                                _ => db.root.uuid,
                            };
                            if let Some(parent) = db.root.find_group_by_uuid_mut(parent_id) {
                                parent.children.push(Group::new(name));
                                sess.dirty = true;
                            }
                            clear_prompt = true;
                        } else if ui.small_button("×").clicked() {
                            clear_prompt = true;
                        }
                    });
                } else if ui.small_button(t.add_group).clicked() {
                    sess.new_group_prompt = Some(String::new());
                }
                if clear_prompt {
                    sess.new_group_prompt = None;
                }
            });

        // 2. Right Inspector Panel
        let mut copy_action: Option<(&'static str, String)> = None;
        let mut att_save_error: Option<String> = None;
        let mut edit_selected = false;
        let mut autotype_selected = false;

        egui::Panel::right("rustpass_entry_inspector")
            .resizable(true)
            .default_size(340.0)
            .min_size(270.0)
            .show(root_ui, |ui| {
                let Some(sess) = self.sessions.get_mut(self.active_tab) else {
                    return;
                };
                let Some(ref db) = sess.db else {
                    return;
                };
                let Some(sel_id) = sess.selected_entry else {
                    ui.centered_and_justified(|ui| {
                        ui.weak(t.inspector_empty);
                    });
                    return;
                };
                let Some(entry) = db.root.find_entry_by_uuid(sel_id) else {
                    ui.weak(t.inspector_empty);
                    return;
                };

                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_space(6.0);
                    ui.horizontal(|ui| {
                        ui.label(
                            RichText::new(&entry.title)
                                .size(19.0)
                                .strong()
                                .color(palette.accent),
                        );
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if ui.small_button(t.btn_edit).clicked() {
                                edit_selected = true;
                            }
                            if ui.small_button("Auto-Type").clicked() {
                                autotype_selected = true;
                            }
                        });
                    });

                    if db.is_in_recycle_bin(entry.uuid) {
                        ui.colored_label(palette.warning, t.ins_in_trash);
                        ui.horizontal(|ui| {
                            if ui.small_button(t.ins_restore).clicked() {
                                db_action = Some(VaultDbAction::RestoreEntry(entry.uuid));
                            }
                            if ui
                                .small_button(
                                    RichText::new(t.ins_delete_perm).color(palette.danger),
                                )
                                .clicked()
                            {
                                db_action = Some(VaultDbAction::DeleteEntryPermanent(entry.uuid));
                            }
                        });
                        ui.add_space(4.0);
                    }

                    if !entry.tags.is_empty() {
                        ui.horizontal_wrapped(|ui| {
                            for tag in &entry.tags {
                                ui.label(
                                    RichText::new(format!("#{tag}"))
                                        .monospace()
                                        .size(11.5)
                                        .color(palette.accent),
                                );
                            }
                        });
                    }
                    ui.separator();

                    // Username
                    ui.weak(t.ins_username);
                    ui.horizontal(|ui| {
                        ui.label(RichText::new(&entry.username).monospace().size(13.5));
                        if !entry.username.is_empty() && ui.small_button("Copy").clicked() {
                            copy_action = Some(("username", entry.username.clone()));
                        }
                    });
                    ui.add_space(6.0);

                    // Password + Entropy
                    ui.weak(t.ins_password);
                    ui.horizontal(|ui| {
                        let shown = if sess.reveal_inspector_pw {
                            entry.password.as_str().to_string()
                        } else {
                            "••••••••••••••".to_string()
                        };
                        ui.label(RichText::new(shown).monospace().size(13.5));
                        if ui
                            .small_button(if sess.reveal_inspector_pw {
                                "Hide"
                            } else {
                                "Show"
                            })
                            .clicked()
                        {
                            sess.reveal_inspector_pw = !sess.reveal_inspector_pw;
                        }
                        if !entry.password.is_empty() && ui.small_button("Copy").clicked() {
                            copy_action = Some(("password", entry.password.as_str().to_string()));
                        }
                    });

                    let est = estimate_password(entry.password.as_str());
                    let s_col = strength_color(est.level, &palette);
                    ui.horizontal(|ui| {
                        let frac = (est.entropy_bits / 110.0).clamp(0.0, 1.0) as f32;
                        ui.add(
                            egui::ProgressBar::new(frac)
                                .desired_width(150.0)
                                .fill(s_col),
                        );
                        ui.colored_label(
                            s_col,
                            RichText::new(format!(
                                "{:.0} bits ({})",
                                est.entropy_bits,
                                est.level.label_en()
                            ))
                            .size(11.5),
                        );
                    });

                    // URL
                    if !entry.url.is_empty() {
                        ui.add_space(6.0);
                        ui.weak(t.ins_url);
                        ui.horizontal(|ui| {
                            if ui.link(&entry.url).clicked()
                                && (entry.url.starts_with("https://")
                                    || entry.url.starts_with("http://"))
                            {
                                let _ = open::that(&entry.url);
                            }
                        });
                    }

                    // Live TOTP + QR
                    if let Ok(cfg) = TotpConfig::from_entry(entry)
                        && let Ok((code, rem)) = cfg.generate_now()
                    {
                        ctx.request_repaint_after(Duration::from_secs(1));
                        ui.add_space(8.0);
                        ui.separator();
                        ui.weak(t.ins_2fa);
                        ui.horizontal(|ui| {
                            let formatted = if code.len() == 6 {
                                format!("{} {}", &code[0..3], &code[3..6])
                            } else {
                                code.clone()
                            };
                            ui.label(
                                RichText::new(formatted)
                                    .monospace()
                                    .size(22.0)
                                    .strong()
                                    .color(palette.accent),
                            );
                            if ui.small_button("Copy 2FA").clicked() {
                                copy_action = Some(("TOTP code", code));
                            }
                            if ui
                                .small_button(if sess.show_inspector_qr {
                                    "Hide QR"
                                } else {
                                    "QR Code"
                                })
                                .clicked()
                            {
                                sess.show_inspector_qr = !sess.show_inspector_qr;
                            }
                        });
                        let progress = (rem as f32) / (cfg.period.max(1) as f32);
                        ui.add(
                            egui::ProgressBar::new(progress)
                                .desired_width(220.0)
                                .fill(if rem <= 5 {
                                    palette.danger
                                } else {
                                    palette.accent
                                })
                                .text(format!("{rem}s")),
                        );

                        if sess.show_inspector_qr {
                            let uri = cfg.to_otpauth_uri();
                            let rebuild = sess
                                .inspector_qr_cache
                                .as_ref()
                                .is_none_or(|(u, _)| u != &uri);
                            // Texture names are global in egui: keying by entry UUID
                            // prevents one tab's QR from overwriting another's.
                            let tex_name = format!("inspector_qr_{}", entry.uuid.simple());
                            if rebuild && let Ok(tex) = build_qr_texture(ctx, &tex_name, &uri) {
                                sess.inspector_qr_cache = Some((uri, tex));
                            }
                            if let Some((_, ref tex)) = sess.inspector_qr_cache {
                                ui.add_space(6.0);
                                ui.image((tex.id(), egui::vec2(164.0, 164.0)));
                            }
                        }
                    }

                    // Custom Attributes
                    if !entry.custom_attributes.is_empty() {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.weak(t.ins_attrs);
                        for attr in &entry.custom_attributes {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(format!("{}:", attr.key)).strong());
                                let val_disp = if attr.protected && !sess.reveal_inspector_pw {
                                    "••••••••"
                                } else {
                                    attr.value.as_str()
                                };
                                ui.label(RichText::new(val_disp).monospace());
                                if ui.small_button("Copy").clicked() {
                                    copy_action =
                                        Some(("attribute", attr.value.as_str().to_string()));
                                }
                            });
                        }
                    }

                    // Attachments
                    if !entry.attachments.is_empty() {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.weak(t.ins_attachments);
                        for att in &entry.attachments {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(&att.name).monospace());
                                ui.weak(format!("({} B)", att.data.len()));
                                if ui.small_button("Save…").clicked() {
                                    let safe_name = std::path::Path::new(&att.name)
                                        .file_name()
                                        .and_then(|s| s.to_str())
                                        .unwrap_or("attachment.bin");
                                    if let Some(dest) =
                                        rfd::FileDialog::new().set_file_name(safe_name).save_file()
                                        && let Err(e) = std::fs::write(dest, &att.data)
                                    {
                                        att_save_error =
                                            Some(format!("Attachment save failed: {e}"));
                                    }
                                }
                            });
                        }
                    }

                    // Notes
                    if !entry.notes.is_empty() {
                        ui.add_space(8.0);
                        ui.separator();
                        ui.weak(t.ins_notes);
                        ui.label(&entry.notes);
                    }

                    ui.add_space(10.0);
                    ui.separator();
                    let modified = entry
                        .times
                        .last_modification_time
                        .format("%Y-%m-%d %H:%M")
                        .to_string();
                    let revisions = entry.history.len();
                    ui.weak(crate::i18n::fill(
                        t.ins_modified_history,
                        &[&modified, &revisions],
                    ));
                });
            });

        if let Some((lbl, secret)) = copy_action {
            self.copy_with_auto_clear(lbl, &secret);
        }
        if let Some(err) = att_save_error {
            self.status_message = err;
        }
        if let Some(action) = db_action
            && let Some(sess) = self.active_session_mut()
            && let Some(ref mut db) = sess.db
        {
            let outcome = match action {
                VaultDbAction::RestoreEntry(id) => db
                    .restore_entry_from_recycle_bin(id)
                    .map(|()| "Entry restored to the vault root".to_string()),
                VaultDbAction::DeleteEntryPermanent(id) => db
                    .delete_entry_by_uuid(id, true)
                    .map(|()| "Entry permanently deleted".to_string()),
                VaultDbAction::RestoreAllTrash => {
                    let bin_id = db.meta.recycle_bin_uuid;
                    let ids: Vec<uuid::Uuid> = db
                        .root
                        .find_group_by_uuid(bin_id)
                        .map_or_else(Vec::new, |b| b.entries.iter().map(|e| e.uuid).collect());
                    let mut restored = 0usize;
                    let mut first_err = None;
                    for id in ids {
                        match db.restore_entry_from_recycle_bin(id) {
                            Ok(()) => restored += 1,
                            Err(e) => {
                                first_err.get_or_insert(e);
                            }
                        }
                    }
                    match first_err {
                        Some(e) => Err(e),
                        None => Ok(format!("Restored {restored} entries to the vault root")),
                    }
                }
                VaultDbAction::EmptyTrash => db
                    .empty_recycle_bin()
                    .map(|n| format!("Trash emptied ({n} entries destroyed)")),
                VaultDbAction::RenameGroup(id, name) => db
                    .rename_group_by_uuid(id, &name)
                    .map(|()| "Group renamed".to_string()),
                VaultDbAction::DeleteGroup(id) => db
                    .remove_group_by_uuid(id)
                    .map(|()| "Group deleted (entries tombstoned)".to_string()),
            };
            match outcome {
                Ok(msg) => {
                    sess.dirty = true;
                    self.status_message = msg;
                }
                Err(e) => self.status_message = format!("Action failed: {e}"),
            }
        }
        if edit_selected {
            self.trigger_action(PaletteAction::EditEntry);
        }
        if autotype_selected {
            self.trigger_action(PaletteAction::PerformAutoType);
        }

        // 3. Center Entry Table
        let mut ctx_action: Option<PaletteAction> = None;
        egui::CentralPanel::default().show(root_ui, |ui| {
            let Some(sess) = self.sessions.get_mut(self.active_tab) else {
                return;
            };
            let Some(ref db) = sess.db else {
                return;
            };

            let parsed_q = SearchQuery::parse(&sess.search_query);
            let search_ctx = SearchContext::from_database(db);

            // Collect entries matching sidebar filter + search query
            let candidates: Vec<(String, &Entry)> = match sess.sidebar_filter {
                SidebarFilter::Group(gid) => {
                    let mut out = Vec::new();
                    if let Some(grp) = db.root.find_group_by_uuid(gid) {
                        grp.collect_entries(&grp.name, &mut out);
                    }
                    out
                }
                SidebarFilter::AllEntries
                | SidebarFilter::TotpOnly
                | SidebarFilter::WeakOrReused
                | SidebarFilter::ExpiredOnly => db.all_entries(false),
            };

            // Constant query: parse once per process instead of once per frame.
            static WEAK_OR_REUSED_Q: std::sync::OnceLock<SearchQuery> = std::sync::OnceLock::new();
            let weak_q = WEAK_OR_REUSED_Q.get_or_init(|| SearchQuery::parse("is:weak | is:reused"));
            let mut rows: Vec<(String, &Entry, f64, StrengthLevel)> = candidates
                .into_iter()
                .filter(|(g_path, entry)| {
                    let sidebar_ok = match sess.sidebar_filter {
                        SidebarFilter::TotpOnly => {
                            entry.otp.as_ref().is_some_and(|o| !o.is_empty())
                                || entry.get_attribute("TOTP Seed").is_some()
                        }
                        SidebarFilter::WeakOrReused => weak_q.matches(g_path, entry, &search_ctx),
                        SidebarFilter::ExpiredOnly => entry.times.is_expired(),
                        _ => true,
                    };
                    sidebar_ok && parsed_q.matches(g_path, entry, &search_ctx)
                })
                .map(|(g, e)| {
                    // One estimate per row: reuse it for both the cell text and color.
                    let est = estimate_password(e.password.as_str());
                    (g, e, est.entropy_bits, est.level)
                })
                .collect();

            rows.sort_by(|a, b| {
                let cmp = match sess.sort_col {
                    SortColumn::Title => a.1.title.to_lowercase().cmp(&b.1.title.to_lowercase()),
                    SortColumn::Username => {
                        a.1.username
                            .to_lowercase()
                            .cmp(&b.1.username.to_lowercase())
                    }
                    SortColumn::Url => a.1.url.to_lowercase().cmp(&b.1.url.to_lowercase()),
                    SortColumn::Strength => a.2.total_cmp(&b.2),
                    SortColumn::Modified => {
                        a.1.times
                            .last_modification_time
                            .cmp(&b.1.times.last_modification_time)
                    }
                };
                if sess.sort_asc { cmp } else { cmp.reverse() }
            });

            // Responsive Sortable Column Widths (`break-ui`: zero horizontal clipping across viewport sizes)
            let avail = (ui.available_width() - 48.0).max(360.0);
            let w_strength = 68.0_f32;
            let w_modified = 84.0_f32;
            let flex = (avail - w_strength - w_modified).max(200.0);
            let w_title = flex * 0.38;
            let w_user = flex * 0.28;
            let w_url = flex * 0.34;

            // Sortable Column Header Row
            ui.horizontal(|ui| {
                ui.add_space(6.0);
                for (col, label, width) in [
                    (SortColumn::Title, t.col_title, w_title),
                    (SortColumn::Username, t.col_username, w_user),
                    (SortColumn::Url, t.col_url, w_url),
                    (SortColumn::Strength, t.col_strength, w_strength),
                    (SortColumn::Modified, t.col_modified, w_modified),
                ] {
                    let arrow = if sess.sort_col == col {
                        if sess.sort_asc { " ▲" } else { " ▼" }
                    } else {
                        ""
                    };
                    let btn = ui.add_sized(
                        [width, 22.0],
                        egui::Button::new(RichText::new(format!("{label}{arrow}")).strong()),
                    );
                    if btn.clicked() {
                        if sess.sort_col == col {
                            sess.sort_asc = !sess.sort_asc;
                        } else {
                            sess.sort_col = col;
                            sess.sort_asc = true;
                        }
                    }
                }
            });
            ui.separator();

            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (_g_path, entry, bits, level) in rows {
                        let is_selected = sess.selected_entry == Some(entry.uuid);
                        let has_2fa = entry.otp.is_some();
                        let bg = if is_selected {
                            palette.selection_bg
                        } else {
                            Color32::TRANSPARENT
                        };

                        let frame_resp = egui::Frame::NONE
                            .fill(bg)
                            .inner_margin(egui::Margin::symmetric(6, 4))
                            .corner_radius(4.0)
                            .show(ui, |ui| {
                                ui.horizontal(|ui| {
                                    let title_badge = if has_2fa {
                                        format!("{} [2FA]", entry.title)
                                    } else {
                                        entry.title.clone()
                                    };
                                    ui.add_sized(
                                        [w_title, 20.0],
                                        egui::Label::new(RichText::new(title_badge).strong())
                                            .truncate(),
                                    );
                                    ui.add_sized(
                                        [w_user, 20.0],
                                        egui::Label::new(
                                            RichText::new(&entry.username).monospace().size(12.5),
                                        )
                                        .truncate(),
                                    );
                                    ui.add_sized(
                                        [w_url, 20.0],
                                        egui::Label::new(
                                            RichText::new(&entry.url)
                                                .size(12.0)
                                                .color(palette.text_muted),
                                        )
                                        .truncate(),
                                    );
                                    ui.add_sized(
                                        [w_strength, 20.0],
                                        egui::Label::new(
                                            RichText::new(format!("{bits:.0} b"))
                                                .monospace()
                                                .color(strength_color(level, &palette)),
                                        ),
                                    );
                                    ui.add_sized(
                                        [w_modified, 20.0],
                                        egui::Label::new(
                                            RichText::new(
                                                entry
                                                    .times
                                                    .last_modification_time
                                                    .format("%Y-%m-%d")
                                                    .to_string(),
                                            )
                                            .size(12.0)
                                            .weak(),
                                        ),
                                    );
                                });
                            });

                        let interact = ui.interact(
                            frame_resp.response.rect,
                            ui.scope_id().with(entry.uuid),
                            egui::Sense::click(),
                        );
                        if interact.clicked() && sess.selected_entry != Some(entry.uuid) {
                            sess.selected_entry = Some(entry.uuid);
                            sess.reveal_inspector_pw = !self.settings.mask_passwords_by_default;
                            sess.inspector_qr_cache = None;
                        }
                        if interact.double_clicked() {
                            sess.selected_entry = Some(entry.uuid);
                            ctx_action = Some(PaletteAction::EditEntry);
                        }
                        interact.context_menu(|ui| {
                            sess.selected_entry = Some(entry.uuid);
                            if ui.button(t.copy_password).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::CopyPassword);
                            }
                            if ui.button(t.copy_username).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::CopyUsername);
                            }
                            if ui.button(t.copy_totp).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::CopyTotp);
                            }
                            if ui.button(t.perform_autotype).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::PerformAutoType);
                            }
                            ui.separator();
                            if ui.button(t.edit_entry).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::EditEntry);
                            }
                            if ui.button(t.clone_entry).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::CloneEntry);
                            }
                            if ui.button(t.delete_entry).clicked() {
                                ui.close();
                                ctx_action = Some(PaletteAction::DeleteEntry);
                            }
                        });
                    }
                });
        });

        if let Some(act) = ctx_action {
            self.trigger_action(act);
        }
    }
}

fn render_group_tree_node(
    ui: &mut egui::Ui,
    group: &Group,
    recycle_bin_uuid: Uuid,
    depth: usize,
    filter: &mut SidebarFilter,
) {
    let is_trash = !recycle_bin_uuid.is_nil() && group.uuid == recycle_bin_uuid;
    let prefix = if is_trash { "[Trash] " } else { "" };
    let count = group.total_entry_count();
    let label = format!("{prefix}{} ({count})", group.name);
    let selected = *filter == SidebarFilter::Group(group.uuid);

    ui.horizontal(|ui| {
        ui.add_space((depth as f32) * 12.0);
        if ui.selectable_label(selected, label).clicked() {
            *filter = SidebarFilter::Group(group.uuid);
        }
    });

    for child in &group.children {
        render_group_tree_node(ui, child, recycle_bin_uuid, depth + 1, filter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keyfile::write_new_keyfile;
    use crate::model::{CipherAlgorithm, CustomAttribute};

    fn temp_test_file(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "rustpass_gui_{}_{}_{name}",
            std::process::id(),
            Uuid::new_v4().simple()
        ))
    }

    #[test]
    fn test_gui_welcome_screen_and_database_creation() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(&ctx, GuiCliArgs::default());

        assert!(app.sessions.is_empty());
        assert_eq!(app.welcome_mode, WelcomeMode::UnlockExisting);

        // Switch to create mode
        app.welcome_mode = WelcomeMode::CreateNew;
        app.welcome_vault_name = "My Personal Vault".to_string();

        let db_file = temp_test_file("create_test.kdbx");
        app.welcome_db_path = db_file.display().to_string();

        // 1. Password mismatch validation
        app.welcome_pw = "Secret#12345".to_string();
        app.welcome_pw_confirm = "Secret#Different".to_string();
        app.submit_welcome_form();

        assert_eq!(
            app.welcome_error.as_deref(),
            Some("Master passwords do not match.")
        );
        assert!(app.sessions.is_empty());

        // 2. Successful creation with keyfile
        let key_file = temp_test_file("vault.keyx");
        write_new_keyfile(&key_file, true).expect("write keyfile");
        app.welcome_keyfile_path = key_file.display().to_string();

        app.welcome_pw = "Secret#12345".to_string();
        app.welcome_pw_confirm = "Secret#12345".to_string();
        app.submit_welcome_form();

        assert!(app.welcome_error.is_none());
        assert_eq!(app.sessions.len(), 1);
        assert!(db_file.is_file());

        let sess = app.active_session().expect("active session");
        assert_eq!(sess.path, Some(db_file.clone()));
        assert!(!sess.dirty);

        let db = sess.db.as_ref().expect("opened database");
        assert_eq!(db.meta.database_name, "My Personal Vault");
        assert_eq!(db.root.name, "My Personal Vault");

        // Verify default folders were created
        let group_names: Vec<&str> = db.root.children.iter().map(|g| g.name.as_str()).collect();
        assert!(group_names.contains(&"General"));
        assert!(group_names.contains(&"Internet"));
        assert!(group_names.contains(&"Infrastructure"));
        assert!(group_names.contains(&"Finance"));

        let _ = std::fs::remove_file(&db_file);
        let _ = std::fs::remove_file(&key_file);
    }

    #[test]
    fn test_gui_group_creation_and_nested_hierarchy() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );
        assert_eq!(app.sessions.len(), 1);

        let sess = app.active_session_mut().expect("active session");
        let db = sess.db.as_mut().expect("db");

        // 1. Add group under root
        let root_id = db.root.uuid;
        sess.sidebar_filter = SidebarFilter::Group(root_id);
        sess.new_group_prompt = Some("SecOps".to_string());

        // Simulate Add button click
        let name = sess.new_group_prompt.take().unwrap();
        let parent = db.root.find_group_by_uuid_mut(root_id).expect("root");
        parent.children.push(Group::new(name));
        sess.dirty = true;

        let secops_grp = db
            .root
            .children
            .iter()
            .find(|g| g.name == "SecOps")
            .expect("SecOps");
        let secops_id = secops_grp.uuid;

        // 2. Add nested group under SecOps
        sess.sidebar_filter = SidebarFilter::Group(secops_id);
        sess.new_group_prompt = Some("Kubernetes".to_string());

        let nested_name = sess.new_group_prompt.take().unwrap();
        let parent = db.root.find_group_by_uuid_mut(secops_id).expect("secops");
        parent.children.push(Group::new(nested_name));

        let k8s_grp = db
            .root
            .find_group_by_uuid(secops_id)
            .unwrap()
            .children
            .iter()
            .find(|g| g.name == "Kubernetes")
            .expect("k8s");
        assert_eq!(k8s_grp.name, "Kubernetes");
        assert!(sess.dirty);
    }

    #[test]
    fn test_gui_entry_editor_modal_and_apply_saved_entry() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );

        let target_group = app
            .active_session()
            .unwrap()
            .db
            .as_ref()
            .unwrap()
            .root
            .children[0]
            .uuid;
        let gen_opts = app.settings.password_generator.clone();

        // 1. Open new entry editor
        app.entry_editor
            .open_new(target_group, "admin@corp", &gen_opts);
        assert!(app.entry_editor.open);
        assert!(app.entry_editor.is_new);
        assert_eq!(app.entry_editor.draft.username, "admin@corp");

        // 2. Populate entry details
        app.entry_editor.draft.title = "Production Ingress".to_string();
        app.entry_editor.password_plain = "ClusterSecret#2026!".to_string();
        app.entry_editor.draft.url = "https://ingress.corp.internal".to_string();
        app.entry_editor.draft.notes = "Primary Gateway".to_string();
        app.entry_editor.tags_csv = "k8s, prod, network".to_string();
        app.entry_editor.otp_raw = "JBSWY3DPEHPK3PXP".to_string();

        // 3. Add custom attribute
        app.entry_editor
            .draft
            .custom_attributes
            .push(CustomAttribute {
                key: "AccessTier".to_string(),
                value: ProtectedString::new("Level-4"),
                protected: true,
            });

        // 4. Add attachment
        app.entry_editor.draft.attachments.push(Attachment {
            name: "ingress_cert.pem".to_string(),
            data: b"CERT_DATA_BYTES".to_vec(),
            protected: false,
        });

        // 5. Submit modal
        app.entry_editor.draft.password = ProtectedString::new(&app.entry_editor.password_plain);
        app.entry_editor.draft.otp = Some(ProtectedString::new(&app.entry_editor.otp_raw));
        app.entry_editor.draft.tags = app
            .entry_editor
            .tags_csv
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let payload = SavedEntryPayload {
            is_new: true,
            target_group_uuid: target_group,
            entry: app.entry_editor.draft.clone(),
        };
        app.entry_editor.open = false;

        let entry_uuid = payload.entry.uuid;
        let sess = app.active_session_mut().unwrap();
        let db = sess.db.as_mut().unwrap();
        apply_saved_entry(db, payload, &mut sess.selected_entry);

        assert_eq!(sess.selected_entry, Some(entry_uuid));
        let created = db
            .root
            .find_entry_by_uuid(entry_uuid)
            .expect("created entry");
        assert_eq!(created.title, "Production Ingress");
        assert_eq!(created.username, "admin@corp");
        assert_eq!(created.password.as_str(), "ClusterSecret#2026!");
        assert_eq!(created.tags, vec!["k8s", "prod", "network"]);
        assert_eq!(created.attachments.len(), 1);
        assert_eq!(created.attachments[0].name, "ingress_cert.pem");

        // Verify live TOTP generation works for this created entry
        let totp = TotpConfig::from_entry(created).expect("valid totp config");
        let (code, remaining) = totp.generate_now().expect("totp token");
        assert_eq!(code.len(), 6);
        assert!(remaining <= 30);
    }

    #[test]
    fn test_gui_entry_edit_version_history_and_cloning() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );

        let sess = app.active_session_mut().expect("active session");
        let db = sess.db.as_mut().expect("db");
        let orig_entry_id = sess.selected_entry.expect("selected entry");
        let orig_entry = db
            .root
            .find_entry_by_uuid(orig_entry_id)
            .expect("entry")
            .clone();

        assert_eq!(orig_entry.history.len(), 0);

        // 1. Edit entry (change password)
        let mut edited = orig_entry.clone();
        edited.password = ProtectedString::new("NewUpdatedPassword#2026!");

        let payload = SavedEntryPayload {
            is_new: false,
            target_group_uuid: db.root.uuid,
            entry: edited,
        };
        apply_saved_entry(db, payload, &mut sess.selected_entry);

        let updated = db
            .root
            .find_entry_by_uuid(orig_entry_id)
            .expect("updated entry");
        assert_eq!(updated.password.as_str(), "NewUpdatedPassword#2026!");
        assert_eq!(updated.history.len(), 1);
        assert_eq!(
            updated.history[0].password.as_str(),
            orig_entry.password.as_str()
        );

        // 2. Clone entry
        app.trigger_action(PaletteAction::CloneEntry);
        let cloned_id = app
            .active_session()
            .unwrap()
            .selected_entry
            .expect("cloned entry");
        assert_ne!(cloned_id, orig_entry_id);

        let db = app.active_session().unwrap().db.as_ref().unwrap();
        let cloned = db.root.find_entry_by_uuid(cloned_id).expect("cloned");
        assert!(cloned.title.ends_with("(Copy)"));
        assert_eq!(cloned.history.len(), 0);

        // 3. Delete original entry (moves to recycle bin)
        let sess = app.active_session_mut().unwrap();
        sess.selected_entry = Some(orig_entry_id);
        app.trigger_action(PaletteAction::DeleteEntry);

        let db = app.active_session().unwrap().db.as_ref().unwrap();
        // Entry is no longer in active engineering group
        let bin_uuid = db.meta.recycle_bin_uuid;
        assert!(!bin_uuid.is_nil());
        let bin = db.root.find_group_by_uuid(bin_uuid).expect("recycle bin");
        assert!(bin.find_entry_by_uuid(orig_entry_id).is_some());
    }

    #[test]
    fn test_gui_generator_audit_settings_modals() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );

        // 1. Password Generator modal
        app.generator_modal.open = true;
        app.generator_modal.pw_opts.length = 32;
        app.generator_modal.pw_opts.lowercase = true;
        app.generator_modal.pw_opts.uppercase = true;
        app.generator_modal.pw_opts.numbers = true;
        app.generator_modal.pw_opts.special = true;
        app.generator_modal.pw_opts.ensure_every_group = true;
        app.generator_modal.regenerate();

        assert_eq!(app.generator_modal.current_output.len(), 32);
        let est = estimate_password(&app.generator_modal.current_output);
        assert!(est.entropy_bits >= 160.0);

        // 2. Security Audit modal
        app.trigger_action(PaletteAction::OpenSecurityAudit);
        assert!(app.audit_modal.open);
        assert!(app.audit_modal.report.is_some());
        let rep = app.audit_modal.report.as_ref().unwrap();
        assert!(rep.total_entries >= 5);
        assert!(rep.weak_count >= 1);
        assert!(rep.http_count >= 1);

        // 3. Database Settings modal
        app.trigger_action(PaletteAction::OpenDbSettings);
        assert!(app.db_settings_modal.open);
        assert_eq!(app.db_settings_modal.cipher, CipherAlgorithm::ChaCha20);
        app.db_settings_modal.cipher = CipherAlgorithm::Aes256Cbc;
        app.db_settings_modal.argon2_mib = 128;
        app.db_settings_modal.argon2_iterations = 4;

        let new_cipher = app.db_settings_modal.cipher;
        let sess = app.active_session_mut().unwrap();
        let db = sess.db.as_mut().unwrap();
        db.cipher = new_cipher;
        assert_eq!(db.cipher, CipherAlgorithm::Aes256Cbc);
    }

    #[test]
    fn test_gui_lock_and_unlock_flow() {
        let ctx = egui::Context::default();
        let db_file = temp_test_file("lock_test.kdbx");

        let mut app = RustPassApp::new_for_test(&ctx, GuiCliArgs::default());
        app.welcome_mode = WelcomeMode::CreateNew;
        app.welcome_vault_name = "Lockable Vault".to_string();
        app.welcome_db_path = db_file.display().to_string();
        app.welcome_pw = "LockMaster#2026!".to_string();
        app.welcome_pw_confirm = "LockMaster#2026!".to_string();
        app.submit_welcome_form();

        assert_eq!(app.sessions.len(), 1);
        assert!(app.active_session().unwrap().db.is_some());

        // 1. Lock vault
        app.trigger_action(PaletteAction::LockVault);
        assert!(app.active_session().unwrap().db.is_none());

        // 2. Unlock with wrong password
        let sess = app.active_session_mut().unwrap();
        sess.unlock_pw_buf = "WrongPassword".to_string();
        let creds_fail = MasterCredentials::with_password(&sess.unlock_pw_buf);
        let open_res = Database::open(&db_file, &creds_fail);
        assert!(open_res.is_err());

        // 3. Unlock with correct password
        sess.unlock_pw_buf = "LockMaster#2026!".to_string();
        let creds_ok = MasterCredentials::with_password(&sess.unlock_pw_buf);
        let db = Database::open(&db_file, &creds_ok).expect("unlock ok");
        sess.db = Some(db);
        sess.credentials = creds_ok;
        sess.unlock_pw_buf.clear();

        assert!(app.active_session().unwrap().db.is_some());

        let _ = std::fs::remove_file(&db_file);
    }

    #[test]
    fn test_gui_render_frame_simulation_without_panics() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );

        let render_pass = |app: &mut RustPassApp| {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render_frame(ui);
            });
            output.textures_delta.clear();
        };

        // Simulate frame render 1: Unlocked 3-pane layout
        render_pass(&mut app);

        // Simulate frame render 2: Generator Modal open
        app.generator_modal.open = true;
        render_pass(&mut app);
        app.generator_modal.open = false;

        // Simulate frame render 3: Entry Editor open
        app.entry_editor.open = true;
        render_pass(&mut app);
        app.entry_editor.open = false;

        // Simulate frame render 4: Security Audit open
        app.audit_modal.open = true;
        render_pass(&mut app);
        app.audit_modal.open = false;

        // Simulate frame render 5: DB Settings open
        app.db_settings_modal.open = true;
        render_pass(&mut app);
        app.db_settings_modal.open = false;

        // Simulate frame render 6: Welcome Screen
        app.sessions.clear();
        render_pass(&mut app);
    }

    #[test]
    fn test_gui_trash_and_group_management_render_and_act() {
        let ctx = egui::Context::default();
        let db_file = temp_test_file("trash_test.kdbx");

        let mut app = RustPassApp::new_for_test(&ctx, GuiCliArgs::default());
        app.welcome_mode = WelcomeMode::CreateNew;
        app.welcome_vault_name = "Trash Vault".to_string();
        app.welcome_db_path = db_file.display().to_string();
        app.welcome_pw = "TrashMaster#2026!".to_string();
        app.welcome_pw_confirm = "TrashMaster#2026!".to_string();
        app.submit_welcome_form();

        // Trash one entry, then select the Recycle Bin group in the sidebar.
        let entry_uuid = {
            let sess = app.active_session_mut().unwrap();
            let db = sess.db.as_mut().unwrap();
            let id = db
                .add_entry_at_path("T/DeleteMe", Entry::new("DeleteMe"))
                .expect("add");
            db.delete_entry_by_uuid(id, false).expect("to bin");
            sess.sidebar_filter = SidebarFilter::Group(db.meta.recycle_bin_uuid);
            sess.selected_entry = Some(id);
            id
        };

        // Rendering with the bin selected (management row) and a trashed entry
        // selected (inspector banner) must not panic.
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render_frame(ui);
        });
        output.textures_delta.clear();

        // Inspector restore action path.
        {
            let sess = app.active_session_mut().unwrap();
            let db = sess.db.as_mut().unwrap();
            db.restore_entry_from_recycle_bin(entry_uuid)
                .expect("restore");
            assert!(db.root.entries.iter().any(|e| e.uuid == entry_uuid));
        }

        // Group rename + delete path.
        let group_uuid = {
            let sess = app.active_session_mut().unwrap();
            let db = sess.db.as_mut().unwrap();
            let _ = db.mkdir_p("ToManage");
            let id = db.resolve_group("ToManage").expect("group").uuid;
            db.rename_group_by_uuid(id, "Managed").expect("rename");
            db.remove_group_by_uuid(id).expect("delete group");
            id
        };
        {
            let sess = app.active_session_mut().unwrap();
            let db = sess.db.as_ref().unwrap();
            assert!(db.root.find_group_by_uuid(group_uuid).is_none());
        }

        let _ = std::fs::remove_file(&db_file);
    }

    #[test]
    fn test_gui_renders_fully_in_french_without_panics() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );
        app.settings.language = crate::i18n::Language::French;

        // Full FR render of the unlocked layout + every modal.
        let render_pass = |app: &mut RustPassApp| {
            let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
                app.render_frame(ui);
            });
            output.textures_delta.clear();
        };
        render_pass(&mut app);
        app.entry_editor.open = true;
        render_pass(&mut app);
        app.entry_editor.open = false;
        app.generator_modal.open = true;
        render_pass(&mut app);
        app.generator_modal.open = false;
        app.audit_modal.open = true;
        render_pass(&mut app);
        app.audit_modal.open = false;
        app.db_settings_modal.open = true;
        render_pass(&mut app);
        app.db_settings_modal.open = false;

        // The localized bundle must be complete enough for the toolbar keys.
        let t = crate::i18n::texts(crate::i18n::Language::French);
        assert!(!t.tb_add_entry.is_empty() && t.tb_add_entry.contains('E'));
        assert!(t.ins_password.contains("PASSE"));
    }

    #[test]
    fn test_gui_close_confirm_modal_protects_dirty_sessions() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );
        assert_eq!(app.sessions.len(), 1);
        app.active_session_mut().unwrap().dirty = true;

        // Ctrl+W / tab-x path on a dirty session must NOT discard it directly.
        app.request_close(PendingClose::Tab(0));
        assert!(app.pending_close.is_some(), "confirm modal must be pending");
        assert_eq!(
            app.sessions.len(),
            1,
            "session must survive until confirmed"
        );

        // Rendering with the confirm modal open must not panic.
        let mut output = ctx.run_ui(egui::RawInput::default(), |ui| {
            app.render_frame(ui);
        });
        output.textures_delta.clear();

        // A path-less dirty vault cannot be saved: save_all_dirty reports it.
        assert_eq!(app.save_all_dirty(), 1);
        assert_eq!(app.sessions.len(), 1);

        // Explicit discard executes the close.
        let quit = app.execute_pending_close();
        assert!(!quit);
        assert!(app.sessions.is_empty());
        assert!(app.pending_close.is_none());
    }

    #[test]
    fn test_gui_clean_close_executes_without_modal() {
        let ctx = egui::Context::default();
        let mut app = RustPassApp::new_for_test(
            &ctx,
            GuiCliArgs {
                showcase: true,
                ..Default::default()
            },
        );
        app.request_close(PendingClose::Tab(0));
        assert!(app.sessions.is_empty(), "clean session closes immediately");
        assert!(app.pending_close.is_none());
    }

    #[test]
    fn test_gui_idle_autolock_fires_after_deadline_and_saves_dirty() {
        let ctx = egui::Context::default();
        let db_file = temp_test_file("idle_lock_test.kdbx");

        let mut app = RustPassApp::new_for_test(&ctx, GuiCliArgs::default());
        app.welcome_mode = WelcomeMode::CreateNew;
        app.welcome_vault_name = "Idle Vault".to_string();
        app.welcome_db_path = db_file.display().to_string();
        app.welcome_pw = "IdleMaster#2026!".to_string();
        app.welcome_pw_confirm = "IdleMaster#2026!".to_string();
        app.submit_welcome_form();
        assert!(app.active_session().unwrap().db.is_some());

        // Simulate an edit after the save (dirty) …
        {
            let sess = app.active_session_mut().unwrap();
            sess.dirty = true;
            let db = sess.db.as_mut().unwrap();
            let mut e = Entry::new("IdleCreated");
            e.username = "idle-user".to_string();
            let _ = db.add_entry_at_path("IdleGroup/IdleCreated", e);
        }
        // … then idle far past auto_lock_idle_seconds.
        app.last_interaction =
            Instant::now() - Duration::from_secs(app.settings.auto_lock_idle_seconds + 5);
        app.poll_clipboard_and_autolock(&ctx);

        let sess = app.active_session().unwrap();
        assert!(sess.db.is_none(), "vault must have locked while idle");
        assert!(!sess.dirty, "edits must have been saved before locking");

        // The pre-lock save preserved the edit on disk.
        let creds = MasterCredentials::with_password("IdleMaster#2026!");
        let reopened = Database::open(&db_file, &creds).expect("reopen after idle lock");
        assert!(reopened.resolve_entry("IdleGroup/IdleCreated").is_ok());

        let _ = std::fs::remove_file(&db_file);
    }
}
