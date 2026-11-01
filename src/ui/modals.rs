//! Modal dialogs for `RustPass`: Entry Editor (with TOTP + QR, Custom Attributes, Attachments,
//! Auto-Type, History), Password/Diceware Generator, Security Health Audit, Database Settings,
//! Keyboard Shortcuts (`F1`), and About.

use crate::crypto::kdf::calibrate_argon2id;
use crate::generator::{DicewareOptions, PasswordGeneratorOptions, estimate_password};
use crate::health::{AuditReport, FindingKind};
use crate::i18n::Language;
use crate::i18n::Texts;
use crate::model::{
    Argon2Variant, Attachment, CipherAlgorithm, CustomAttribute, Database, Entry, KdbxVersion,
    KdfConfig, ProtectedString,
};
use crate::totp::TotpConfig;
use crate::totp::qr::QrMatrix;
use crate::ui::themes::{VaultPalette, strength_color};
use eframe::egui::{self, Color32, ColorImage, RichText, TextureHandle, TextureOptions};
use uuid::Uuid;

/// Active tab inside the Entry Editor modal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EditorTab {
    #[default]
    General,
    Totp,
    Attributes,
    Attachments,
    AutoType,
    History,
}

/// Editable draft state for creating or modifying a vault `Entry`.
pub struct EntryEditorModal {
    pub open: bool,
    pub is_new: bool,
    pub target_group_uuid: Uuid,
    pub draft: Entry,
    pub password_plain: String,
    pub show_password: bool,
    pub otp_raw: String,
    pub tags_csv: String,
    pub active_tab: EditorTab,
    pub new_attr_key: String,
    pub new_attr_val: String,
    pub new_attr_protected: bool,
    pub qr_cache: Option<(String, TextureHandle)>,
    pub error_msg: Option<String>,
}

impl Default for EntryEditorModal {
    fn default() -> Self {
        Self {
            open: false,
            is_new: true,
            target_group_uuid: Uuid::nil(),
            draft: Entry::new(""),
            password_plain: String::new(),
            show_password: false,
            otp_raw: String::new(),
            tags_csv: String::new(),
            active_tab: EditorTab::General,
            new_attr_key: String::new(),
            new_attr_val: String::new(),
            new_attr_protected: true,
            qr_cache: None,
            error_msg: None,
        }
    }
}

/// Outcome returned when the user submits the Entry Editor modal.
pub struct SavedEntryPayload {
    pub is_new: bool,
    pub target_group_uuid: Uuid,
    pub entry: Entry,
}

impl EntryEditorModal {
    /// Opens the modal to create a brand-new entry inside `group_uuid`.
    pub fn open_new(
        &mut self,
        group_uuid: Uuid,
        default_username: &str,
        gen_opts: &PasswordGeneratorOptions,
    ) {
        let mut entry = Entry::new("");
        entry.username = default_username.to_string();
        let initial_pw = gen_opts
            .generate()
            .map_or_else(|_| String::new(), |p| p.as_str().to_string());
        self.open = true;
        self.is_new = true;
        self.target_group_uuid = group_uuid;
        self.draft = entry;
        self.password_plain = initial_pw;
        self.show_password = false;
        self.otp_raw.clear();
        self.tags_csv.clear();
        self.active_tab = EditorTab::General;
        self.qr_cache = None;
        self.error_msg = None;
    }

    /// Opens the modal to edit an existing `entry`.
    pub fn open_edit(&mut self, entry: &Entry) {
        self.open = true;
        self.is_new = false;
        self.target_group_uuid = Uuid::nil();
        self.draft = entry.clone();
        self.password_plain = entry.password.as_str().to_string();
        self.show_password = false;
        self.otp_raw = entry
            .otp
            .as_ref()
            .map_or_else(String::new, |o| o.as_str().to_string());
        self.tags_csv = entry.tags.join(", ");
        self.active_tab = EditorTab::General;
        self.qr_cache = None;
        self.error_msg = None;
    }

    /// Renders the Entry Editor window and returns `Some(SavedEntryPayload)` when saved.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        palette: &VaultPalette,
        t: &'static Texts,
        gen_opts: &PasswordGeneratorOptions,
    ) -> Option<SavedEntryPayload> {
        if !self.open {
            return None;
        }

        let win_title = if self.is_new {
            t.ed_new_title
        } else {
            t.ed_edit_title
        };
        let mut committed = None;
        let mut cancel_clicked = false;

        egui::Window::new(win_title)
            .collapsible(false)
            .resizable(true)
            .default_size([590.0, 480.0])
            .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.selectable_value(&mut self.active_tab, EditorTab::General, t.ed_tab_general);
                    ui.selectable_value(&mut self.active_tab, EditorTab::Totp, t.ed_tab_totp);
                    ui.selectable_value(
                        &mut self.active_tab,
                        EditorTab::Attributes,
                        format!(
                            "{} ({})",
                            t.ed_tab_attributes,
                            self.draft.custom_attributes.len()
                        ),
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        EditorTab::Attachments,
                        format!(
                            "{} ({})",
                            t.ed_tab_attachments,
                            self.draft.attachments.len()
                        ),
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        EditorTab::AutoType,
                        t.ed_tab_autotype,
                    );
                    ui.selectable_value(
                        &mut self.active_tab,
                        EditorTab::History,
                        format!("{} ({})", t.ed_tab_history, self.draft.history.len()),
                    );
                });
                ui.separator();

                egui::ScrollArea::vertical()
                    .max_height(360.0)
                    .show(ui, |ui| match self.active_tab {
                        EditorTab::General => self.ui_general(ui, palette, t, gen_opts),
                        EditorTab::Totp => self.ui_totp(ctx, ui, palette, t),
                        EditorTab::Attributes => self.ui_attributes(ui, t),
                        EditorTab::Attachments => self.ui_attachments(ui, t),
                        EditorTab::AutoType => self.ui_autotype(ui, t),
                        EditorTab::History => self.ui_history(ui, t),
                    });

                if let Some(ref err) = self.error_msg {
                    ui.add_space(4.0);
                    ui.colored_label(palette.danger, err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui
                        .button(
                            RichText::new(t.ed_save_entry)
                                .strong()
                                .color(palette.accent),
                        )
                        .clicked()
                    {
                        if self.draft.title.trim().is_empty() {
                            self.error_msg = Some(t.ed_title_required.to_string());
                        } else {
                            let mut saved = self.draft.clone();
                            saved.title = saved.title.trim().to_string();
                            saved.password = ProtectedString::new(self.password_plain.clone());
                            saved.tags = self
                                .tags_csv
                                .split(',')
                                .map(str::trim)
                                .filter(|s| !s.is_empty())
                                .map(str::to_string)
                                .collect();
                            let trimmed_otp = self.otp_raw.trim();
                            if trimmed_otp.is_empty() {
                                saved.otp = None;
                                committed = Some(SavedEntryPayload {
                                    is_new: self.is_new,
                                    target_group_uuid: self.target_group_uuid,
                                    entry: saved,
                                });
                            } else {
                                match TotpConfig::parse(trimmed_otp) {
                                    Ok(mut cfg) => {
                                        if cfg.issuer.is_empty() {
                                            cfg.issuer.clone_from(&saved.title);
                                        }
                                        if cfg.account.is_empty() {
                                            cfg.account.clone_from(&saved.username);
                                        }
                                        saved.otp =
                                            Some(ProtectedString::new(cfg.to_otpauth_uri()));
                                        committed = Some(SavedEntryPayload {
                                            is_new: self.is_new,
                                            target_group_uuid: self.target_group_uuid,
                                            entry: saved,
                                        });
                                    }
                                    Err(e) => {
                                        self.error_msg = Some(e.to_string());
                                    }
                                }
                            }
                        }
                    }
                    if ui.button(t.cancel).clicked() {
                        cancel_clicked = true;
                    }
                });
            });

        if committed.is_some() || cancel_clicked {
            zeroize::Zeroize::zeroize(&mut self.password_plain);
            zeroize::Zeroize::zeroize(&mut self.otp_raw);
            self.open = false;
        }
        committed
    }

    fn ui_general(
        &mut self,
        ui: &mut egui::Ui,
        palette: &VaultPalette,
        t: &'static Texts,
        gen_opts: &PasswordGeneratorOptions,
    ) {
        egui::Grid::new("entry_general_grid")
            .num_columns(2)
            .spacing([12.0, 8.0])
            .striped(false)
            .show(ui, |ui| {
                ui.label(t.lbl_title_req);
                ui.add(egui::TextEdit::singleline(&mut self.draft.title).desired_width(410.0));
                ui.end_row();

                ui.label(t.lbl_username);
                ui.add(egui::TextEdit::singleline(&mut self.draft.username).desired_width(410.0));
                ui.end_row();

                ui.label(t.lbl_password);
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password_plain)
                            .password(!self.show_password)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(275.0),
                    );
                    let eye = if self.show_password {
                        t.btn_hide
                    } else {
                        t.btn_show
                    };
                    if ui.button(eye).clicked() {
                        self.show_password = !self.show_password;
                    }
                    if ui.button(t.btn_generate).clicked()
                        && let Ok(pw) = gen_opts.generate()
                    {
                        self.password_plain = pw.as_str().to_string();
                    }
                });
                ui.end_row();

                ui.label(t.lbl_entropy);
                let est = estimate_password(&self.password_plain);
                let col = strength_color(est.level, palette);
                ui.horizontal(|ui| {
                    let frac = (est.entropy_bits / 110.0).clamp(0.0, 1.0) as f32;
                    ui.add(egui::ProgressBar::new(frac).desired_width(210.0).fill(col));
                    ui.colored_label(
                        col,
                        format!("{:.1} bits — {}", est.entropy_bits, est.level.label_en()),
                    );
                });
                ui.end_row();

                ui.label("URL");
                ui.add(
                    egui::TextEdit::singleline(&mut self.draft.url)
                        .hint_text("https://example.com")
                        .desired_width(410.0),
                );
                ui.end_row();

                ui.label(t.lbl_tags);
                ui.add(
                    egui::TextEdit::singleline(&mut self.tags_csv)
                        .hint_text("infra, prod, ssh")
                        .desired_width(410.0),
                );
                ui.end_row();

                ui.label(t.lbl_expires);
                ui.checkbox(&mut self.draft.times.expires, t.ed_enable_expiry);
                ui.end_row();
            });

        ui.add_space(8.0);
        ui.label(t.lbl_notes);
        ui.add(
            egui::TextEdit::multiline(&mut self.draft.notes)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
    }

    fn ui_totp(
        &mut self,
        ctx: &egui::Context,
        ui: &mut egui::Ui,
        palette: &VaultPalette,
        t: &'static Texts,
    ) {
        ui.label(t.ed_totp_hint);
        ui.add(
            egui::TextEdit::singleline(&mut self.otp_raw)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(8.0);

        if !self.otp_raw.trim().is_empty() {
            match TotpConfig::parse(&self.otp_raw) {
                Ok(mut cfg) => {
                    if cfg.issuer.is_empty() {
                        cfg.issuer.clone_from(&self.draft.title);
                    }
                    if cfg.account.is_empty() {
                        cfg.account.clone_from(&self.draft.username);
                    }
                    if let Ok((code, rem)) = cfg.generate_now() {
                        ctx.request_repaint_after(std::time::Duration::from_secs(1));
                        ui.horizontal(|ui| {
                            ui.label(t.ed_live_code);
                            ui.label(
                                RichText::new(&code)
                                    .monospace()
                                    .size(22.0)
                                    .strong()
                                    .color(palette.accent),
                            );
                            ui.label(format!("({rem}s remaining)"));
                        });
                    }

                    let uri = cfg.to_otpauth_uri();
                    let need_rebuild = self
                        .qr_cache
                        .as_ref()
                        .is_none_or(|(cached_uri, _)| cached_uri != &uri);
                    let tex_name = format!("editor_qr_{}", self.draft.uuid.simple());
                    if need_rebuild && let Ok(tex) = build_qr_texture(ctx, &tex_name, &uri) {
                        self.qr_cache = Some((uri, tex));
                    }
                    if let Some((_, ref tex)) = self.qr_cache {
                        ui.add_space(6.0);
                        ui.image((tex.id(), egui::vec2(168.0, 168.0)));
                    }
                }
                Err(e) => {
                    ui.colored_label(palette.danger, e.to_string());
                }
            }
        }
    }

    fn ui_attributes(&mut self, ui: &mut egui::Ui, t: &'static Texts) {
        let mut remove_idx = None;
        for (i, attr) in self.draft.custom_attributes.iter_mut().enumerate() {
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut attr.key).desired_width(150.0));
                let mut val = attr.value.as_str().to_string();
                if ui
                    .add(
                        egui::TextEdit::singleline(&mut val)
                            .password(attr.protected)
                            .desired_width(240.0),
                    )
                    .changed()
                {
                    attr.value = ProtectedString::new(val);
                }
                ui.checkbox(&mut attr.protected, t.ed_protected);
                if ui.button(t.btn_remove).clicked() {
                    remove_idx = Some(i);
                }
            });
        }
        if let Some(i) = remove_idx {
            self.draft.custom_attributes.remove(i);
        }

        ui.separator();
        ui.horizontal(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.new_attr_key)
                    .hint_text(t.ed_attr_name_hint)
                    .desired_width(150.0),
            );
            ui.add(
                egui::TextEdit::singleline(&mut self.new_attr_val)
                    .hint_text(t.ed_attr_value_hint)
                    .desired_width(220.0),
            );
            ui.checkbox(&mut self.new_attr_protected, t.ed_protected);
            if ui.button(t.btn_add).clicked() && !self.new_attr_key.trim().is_empty() {
                self.draft.custom_attributes.push(CustomAttribute {
                    key: self.new_attr_key.trim().to_string(),
                    value: ProtectedString::new(self.new_attr_val.clone()),
                    protected: self.new_attr_protected,
                });
                self.new_attr_key.clear();
                self.new_attr_val.clear();
            }
        });
    }

    fn ui_attachments(&mut self, ui: &mut egui::Ui, t: &'static Texts) {
        if ui.button(t.ed_attach_file).clicked()
            && let Some(path) = rfd::FileDialog::new().pick_file()
            && let Ok(data) = std::fs::read(&path)
        {
            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("attachment.bin")
                .to_string();
            self.draft.attachments.push(Attachment {
                name,
                data,
                protected: true,
            });
        }
        ui.add_space(6.0);
        let mut rm = None;
        for (idx, att) in self.draft.attachments.iter().enumerate() {
            ui.horizontal(|ui| {
                ui.label(RichText::new(&att.name).strong());
                ui.label(format!("({} bytes)", att.data.len()));
                if ui.button(t.btn_export).clicked()
                    && let Some(dest) = rfd::FileDialog::new().set_file_name(&att.name).save_file()
                    && let Err(e) = std::fs::write(&dest, &att.data)
                {
                    self.error_msg = Some(format!("Attachment export failed: {e}"));
                }
                if ui.button(t.btn_remove).clicked() {
                    rm = Some(idx);
                }
            });
        }
        if let Some(i) = rm {
            self.draft.attachments.remove(i);
        }
    }

    fn ui_autotype(&mut self, ui: &mut egui::Ui, t: &'static Texts) {
        ui.checkbox(&mut self.draft.auto_type.enabled, t.ed_at_enable);
        ui.add_space(6.0);
        ui.label(t.ed_at_seq_label);
        ui.add(
            egui::TextEdit::singleline(&mut self.draft.auto_type.default_sequence)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY),
        );
        ui.add_space(6.0);
        ui.weak(t.ed_at_placeholders);
    }

    fn ui_history(&mut self, ui: &mut egui::Ui, t: &'static Texts) {
        if self.draft.history.is_empty() {
            ui.weak(t.ed_no_history);
            return;
        }
        let mut restore_idx = None;
        for (i, snap) in self.draft.history.iter().enumerate().rev() {
            ui.horizontal(|ui| {
                ui.label(
                    snap.times
                        .last_modification_time
                        .format("%Y-%m-%d %H:%M:%S UTC")
                        .to_string(),
                );
                ui.label(crate::i18n::fill(
                    t.ed_history_line,
                    &[&snap.title, &snap.username],
                ));
                if ui.button(t.ed_restore).clicked() {
                    restore_idx = Some(i);
                }
            });
        }
        if let Some(idx) = restore_idx {
            // Full rollback: the snapshot is a complete entry clone, so restore every
            // field (tags, OTP seed, custom attributes, attachments, auto-type) — a
            // partial restore would silently keep the current values.
            let snap = self.draft.history[idx].clone();
            let keep_uuid = self.draft.uuid;
            let keep_history = std::mem::take(&mut self.draft.history);
            self.draft = snap;
            self.draft.uuid = keep_uuid; // identity must stay stable
            self.draft.history = keep_history;
            self.draft.times.touch_modified();
            self.password_plain = self.draft.password.as_str().to_string();
            self.otp_raw = self
                .draft
                .otp
                .as_ref()
                .map_or_else(String::new, |o| o.as_str().to_string());
            self.tags_csv = self.draft.tags.join(", ");
        }
    }
}

/// Converts an `otpauth://` string into an `egui::TextureHandle` backed by our clean-room ISO 18004 encoder.
pub fn build_qr_texture(
    ctx: &egui::Context,
    name: &str,
    payload: &str,
) -> crate::error::Result<TextureHandle> {
    let qr = QrMatrix::encode(payload.as_bytes())?;
    let quiet = 3usize;
    let scale = 4usize;
    let dim = (qr.size + quiet * 2) * scale;
    let mut pixels = vec![Color32::WHITE; dim * dim];
    for my in 0..qr.size {
        for mx in 0..qr.size {
            if qr.get(mx, my) {
                let px0 = (mx + quiet) * scale;
                let py0 = (my + quiet) * scale;
                for dy in 0..scale {
                    for dx in 0..scale {
                        pixels[(py0 + dy) * dim + (px0 + dx)] = Color32::from_rgb(12, 18, 22);
                    }
                }
            }
        }
    }
    let img = ColorImage {
        size: [dim, dim],
        source_size: egui::vec2(dim as f32, dim as f32),
        pixels,
    };
    Ok(ctx.load_texture(name, img, TextureOptions::NEAREST))
}

/// Standalone Password & Diceware Generator window.
pub struct GeneratorModal {
    pub open: bool,
    pub diceware_mode: bool,
    pub pw_opts: PasswordGeneratorOptions,
    pub dw_opts: DicewareOptions,
    pub current_output: String,
}

impl GeneratorModal {
    #[must_use]
    pub fn new(pw_opts: PasswordGeneratorOptions, dw_opts: DicewareOptions) -> Self {
        let initial = pw_opts
            .generate()
            .map_or_else(|_| String::new(), |p| p.as_str().to_string());
        Self {
            open: false,
            diceware_mode: false,
            pw_opts,
            dw_opts,
            current_output: initial,
        }
    }

    pub fn regenerate(&mut self) {
        if self.diceware_mode {
            if let Ok((phrase, _)) = self.dw_opts.generate() {
                self.current_output = phrase.as_str().to_string();
            }
        } else if let Ok(pw) = self.pw_opts.generate() {
            self.current_output = pw.as_str().to_string();
        }
    }

    /// Renders the Generator window and returns `Some(secret_to_copy)` if the user clicks Copy.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        palette: &VaultPalette,
        t: &'static Texts,
    ) -> Option<String> {
        if !self.open {
            return None;
        }
        let mut copy_requested = None;
        let mut open = self.open;

        egui::Window::new(t.gen_title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([480.0, 340.0])
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    if ui
                        .selectable_value(&mut self.diceware_mode, false, t.gen_mode_chars)
                        .clicked()
                    {
                        self.regenerate();
                    }
                    if ui
                        .selectable_value(&mut self.diceware_mode, true, t.gen_mode_diceware)
                        .clicked()
                    {
                        self.regenerate();
                    }
                });
                ui.separator();

                ui.add(
                    egui::TextEdit::multiline(&mut self.current_output)
                        .desired_rows(2)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY),
                );

                let est = estimate_password(&self.current_output);
                let col = strength_color(est.level, palette);
                ui.horizontal(|ui| {
                    let frac = (est.entropy_bits / 120.0).clamp(0.0, 1.0) as f32;
                    ui.add(egui::ProgressBar::new(frac).desired_width(220.0).fill(col));
                    ui.colored_label(
                        col,
                        format!(
                            "{:.1} bits · {} ({})",
                            est.entropy_bits,
                            est.level.label_en(),
                            est.crack_time_display
                        ),
                    );
                });

                ui.add_space(6.0);
                if self.diceware_mode {
                    let mut changed = false;
                    changed |= ui
                        .add(
                            egui::Slider::new(&mut self.dw_opts.word_count, 3..=12)
                                .text(t.gen_words),
                        )
                        .changed();
                    ui.horizontal(|ui| {
                        ui.label(t.gen_separator);
                        changed |= ui
                            .add(
                                egui::TextEdit::singleline(&mut self.dw_opts.separator)
                                    .desired_width(50.0),
                            )
                            .changed();
                        changed |= ui
                            .checkbox(&mut self.dw_opts.capitalize, t.gen_capitalize)
                            .changed();
                        changed |= ui
                            .checkbox(&mut self.dw_opts.include_number, t.gen_include_digits)
                            .changed();
                    });
                    if changed {
                        self.regenerate();
                    }
                } else {
                    let mut changed = false;
                    changed |= ui
                        .add(
                            egui::Slider::new(&mut self.pw_opts.length, 6..=64)
                                .text(t.gen_characters),
                        )
                        .changed();
                    ui.horizontal_wrapped(|ui| {
                        changed |= ui.checkbox(&mut self.pw_opts.lowercase, "a-z").changed();
                        changed |= ui.checkbox(&mut self.pw_opts.uppercase, "A-Z").changed();
                        changed |= ui.checkbox(&mut self.pw_opts.numbers, "0-9").changed();
                        changed |= ui.checkbox(&mut self.pw_opts.special, "!@#$%").changed();
                        changed |= ui
                            .checkbox(&mut self.pw_opts.exclude_similar, t.gen_no_lookalikes)
                            .changed();
                        changed |= ui
                            .checkbox(&mut self.pw_opts.ensure_every_group, t.gen_every_class)
                            .changed();
                    });
                    if changed {
                        self.regenerate();
                    }
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button(t.gen_regenerate).clicked() {
                        self.regenerate();
                    }
                    if ui
                        .button(RichText::new(t.gen_copy).strong().color(palette.accent))
                        .clicked()
                    {
                        copy_requested = Some(self.current_output.clone());
                    }
                });
            });

        self.open = open;
        copy_requested
    }
}

/// Vault Security Health Audit modal window.
#[derive(Default)]
pub struct SecurityAuditModal {
    pub open: bool,
    pub report: Option<AuditReport>,
    /// Last export outcome shown in the modal (no secrets involved).
    pub export_status: Option<String>,
}

impl SecurityAuditModal {
    /// Renders the Security Health report and returns `Some(entry_uuid)` if the user clicks a finding.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        palette: &VaultPalette,
        lang: Language,
    ) -> Option<Uuid> {
        if !self.open {
            return None;
        }
        let mut open = self.open;
        let mut jump_uuid = None;
        let t = crate::i18n::texts(lang);

        egui::Window::new(t.audit_title)
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size([620.0, 440.0])
            .show(ctx, |ui| {
                let Some(ref rep) = self.report else {
                    ui.label(t.audit_none);
                    return;
                };

                let score_col = if rep.health_score >= 85 {
                    palette.success
                } else if rep.health_score >= 60 {
                    palette.warning
                } else {
                    palette.danger
                };

                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!("{}/100", rep.health_score))
                            .size(28.0)
                            .strong()
                            .color(score_col),
                    );
                    ui.vertical(|ui| {
                        let avg_bits = format!("{:.1}", rep.average_entropy_bits);
                        ui.label(crate::i18n::fill(
                            t.audit_summary,
                            &[&rep.total_entries, &avg_bits],
                        ));
                        ui.label(crate::i18n::fill(
                            t.audit_counts,
                            &[
                                &rep.weak_count,
                                &rep.reused_count,
                                &rep.expired_count,
                                &rep.http_count,
                                &rep.totp_enabled_count,
                            ],
                        ));
                    });
                });
                ui.horizontal(|ui| {
                    if ui.button(t.audit_export_csv).clicked()
                        && let Some(dest) = rfd::FileDialog::new()
                            .set_file_name("rustpass-audit.csv")
                            .save_file()
                    {
                        self.export_status =
                            match std::fs::write(&dest, crate::health::export_audit_csv(rep)) {
                                Ok(()) => Some(format!("Wrote {}", dest.display())),
                                Err(e) => Some(format!("Export failed: {e}")),
                            };
                    }
                    if ui.button(t.audit_export_html).clicked()
                        && let Some(dest) = rfd::FileDialog::new()
                            .set_file_name("rustpass-audit.html")
                            .save_file()
                    {
                        self.export_status =
                            match std::fs::write(&dest, crate::health::export_audit_html(rep)) {
                                Ok(()) => Some(format!("Wrote {}", dest.display())),
                                Err(e) => Some(format!("Export failed: {e}")),
                            };
                    }
                });
                if let Some(ref status) = self.export_status {
                    ui.weak(status);
                }

                ui.separator();

                if rep.findings.is_empty() {
                    ui.colored_label(palette.success, t.audit_clean);
                } else {
                    egui::ScrollArea::vertical()
                        .max_height(320.0)
                        .show(ui, |ui| {
                            for f in &rep.findings {
                                let sev_col = match f.kind {
                                    FindingKind::EmptyPassword | FindingKind::CompromisedHibp => {
                                        palette.danger
                                    }
                                    FindingKind::WeakPassword | FindingKind::ReusedPassword => {
                                        Color32::from_rgb(249, 115, 22)
                                    }
                                    FindingKind::MissingTwoFactor => palette.text_muted,
                                    _ => palette.warning,
                                };
                                let desc = match lang {
                                    Language::English => f.kind.label_en(),
                                    Language::French => f.kind.label_fr(),
                                };
                                ui.horizontal(|ui| {
                                    ui.colored_label(
                                        sev_col,
                                        RichText::new(format!("[{}]", f.kind.severity()))
                                            .monospace()
                                            .strong(),
                                    );
                                    if ui.link(&f.entry_path).clicked() {
                                        jump_uuid = Some(f.entry_uuid);
                                    }
                                    ui.label(format!("— {desc} ({})", f.detail));
                                });
                            }
                        });
                }
            });

        if jump_uuid.is_some() {
            open = false;
        }
        self.open = open;
        jump_uuid
    }
}

/// Database Security & Encryption Settings modal.
#[derive(Default)]
pub struct DbSettingsModal {
    pub open: bool,
    pub db_name: String,
    pub db_description: String,
    pub default_username: String,
    pub recycle_bin_enabled: bool,
    pub is_kdbx4: bool,
    pub cipher: CipherAlgorithm,
    pub argon2_mib: u64,
    pub argon2_iterations: u64,
    pub argon2_lanes: u32,
}

impl DbSettingsModal {
    pub fn load_from(&mut self, db: &Database) {
        self.open = true;
        self.db_name.clone_from(&db.meta.database_name);
        self.db_description
            .clone_from(&db.meta.database_description);
        self.default_username.clone_from(&db.meta.default_username);
        self.recycle_bin_enabled = db.meta.recycle_bin_enabled;
        self.is_kdbx4 = matches!(db.version, KdbxVersion::V4_0 { .. });
        self.cipher = db.cipher;
        match db.kdf {
            KdfConfig::Argon2 {
                memory_bytes,
                iterations,
                parallelism,
                ..
            } => {
                self.argon2_mib = (memory_bytes / (1024 * 1024)).max(8);
                self.argon2_iterations = iterations.max(1);
                self.argon2_lanes = parallelism.max(1);
            }
            KdfConfig::AesKdf { .. } => {
                self.argon2_mib = 64;
                self.argon2_iterations = 3;
                self.argon2_lanes = 4;
            }
        }
    }

    /// Renders the Database Settings window and returns `true` when applied onto `db`.
    pub fn ui(
        &mut self,
        ctx: &egui::Context,
        db: &mut Database,
        palette: &VaultPalette,
        t: &'static Texts,
    ) -> bool {
        if !self.open {
            return false;
        }
        let mut applied = false;
        let mut open = self.open;

        egui::Window::new(t.dbs_title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .fixed_size([470.0, 350.0])
            .show(ctx, |ui| {
                egui::Grid::new("db_settings_grid")
                    .num_columns(2)
                    .spacing([12.0, 8.0])
                    .show(ui, |ui| {
                        ui.label(t.dbs_vault_name);
                        ui.text_edit_singleline(&mut self.db_name);
                        ui.end_row();

                        ui.label(t.dbs_description);
                        ui.text_edit_singleline(&mut self.db_description);
                        ui.end_row();

                        ui.label(t.dbs_default_username);
                        ui.text_edit_singleline(&mut self.default_username);
                        ui.end_row();

                        ui.label(t.dbs_format);
                        ui.horizontal(|ui| {
                            ui.selectable_value(&mut self.is_kdbx4, true, t.dbs_kdbx4);
                            ui.selectable_value(&mut self.is_kdbx4, false, t.dbs_kdbx3);
                        });
                        ui.end_row();

                        ui.label(t.dbs_cipher);
                        ui.horizontal(|ui| {
                            ui.selectable_value(
                                &mut self.cipher,
                                CipherAlgorithm::ChaCha20,
                                "ChaCha20 (256-bit)",
                            );
                            ui.selectable_value(
                                &mut self.cipher,
                                CipherAlgorithm::Aes256Cbc,
                                "AES-256-CBC",
                            );
                        });
                        ui.end_row();

                        if self.is_kdbx4 {
                            ui.label(t.dbs_argon2_memory);
                            ui.add(egui::Slider::new(&mut self.argon2_mib, 16..=512));
                            ui.end_row();

                            ui.label(t.dbs_argon2_iter);
                            ui.add(egui::Slider::new(&mut self.argon2_iterations, 1..=32));
                            ui.end_row();

                            ui.label(t.dbs_argon2_lanes);
                            ui.add(egui::Slider::new(&mut self.argon2_lanes, 1..=16));
                            ui.end_row();
                        }
                    });

                ui.add_space(6.0);
                ui.checkbox(&mut self.recycle_bin_enabled, t.dbs_recycle_bin);
                if self.is_kdbx4
                    && ui.button(t.dbs_benchmark).clicked()
                    && let Ok(KdfConfig::Argon2 {
                        memory_bytes,
                        iterations,
                        parallelism,
                        ..
                    }) = calibrate_argon2id(500)
                {
                    self.argon2_mib = memory_bytes / (1024 * 1024);
                    self.argon2_iterations = iterations;
                    self.argon2_lanes = parallelism;
                }

                ui.separator();
                if ui
                    .button(RichText::new(t.dbs_apply).strong().color(palette.accent))
                    .clicked()
                {
                    db.meta.database_name.clone_from(&self.db_name);
                    db.meta
                        .database_description
                        .clone_from(&self.db_description);
                    db.meta.default_username.clone_from(&self.default_username);
                    db.meta.recycle_bin_enabled = self.recycle_bin_enabled;
                    if self.is_kdbx4 {
                        db.version = KdbxVersion::V4_0 { minor: 0 };
                        db.cipher = self.cipher;
                        db.kdf = KdfConfig::Argon2 {
                            variant: Argon2Variant::Argon2id,
                            memory_bytes: self.argon2_mib * 1024 * 1024,
                            iterations: self.argon2_iterations,
                            parallelism: self.argon2_lanes,
                            version: 0x13,
                            salt: [0u8; 32],
                        };
                    } else {
                        db.version = KdbxVersion::V3_1;
                        db.cipher = CipherAlgorithm::Aes256Cbc;
                        db.kdf = KdfConfig::AesKdf {
                            rounds: 150_000,
                            seed: [0u8; 32],
                        };
                    }
                    applied = true;
                }
            });

        if applied {
            open = false;
        }
        self.open = open;
        applied
    }
}

/// Renders the Keyboard Shortcuts (`F1`) reference modal.
pub fn show_shortcuts_window(ctx: &egui::Context, open: &mut bool) {
    if !*open {
        return;
    }
    egui::Window::new("Keyboard Shortcuts (KeePassXC Compatible)")
        .open(open)
        .collapsible(false)
        .resizable(false)
        .fixed_size([460.0, 360.0])
        .show(ctx, |ui| {
            let rows = [
                ("Ctrl + N", "Create New Encrypted KDBX Vault"),
                ("Ctrl + O", "Open Existing KDBX Vault"),
                ("Ctrl + S", "Save Active Vault"),
                ("Ctrl + L", "Lock Active Vault Immediately"),
                ("Ctrl + W", "Close Active Vault Tab"),
                ("Ctrl + I", "Add New Entry"),
                ("Ctrl + E", "Edit Selected Entry"),
                ("Ctrl + K", "Clone Selected Entry"),
                ("Delete", "Delete Selected Entry (Recycle Bin)"),
                ("Ctrl + B", "Copy Username (timed auto-clear)"),
                ("Ctrl + C", "Copy Password (timed auto-clear)"),
                ("Ctrl + T", "Copy Current 2FA / TOTP Code"),
                ("Ctrl + U", "Open Login URL in Default Browser"),
                ("Ctrl + V", "Perform Auto-Type into Previous Window"),
                ("Ctrl + F", "Focus Structured Search Bar"),
                ("Ctrl + G", "Open Password & Diceware Generator"),
                ("Ctrl + Shift + P", "Open Command Palette"),
                ("F1", "Show Keyboard Shortcuts"),
            ];
            egui::Grid::new("shortcuts_ref_grid")
                .num_columns(2)
                .spacing([20.0, 5.0])
                .striped(true)
                .show(ui, |ui| {
                    for (k, desc) in rows {
                        ui.label(RichText::new(k).monospace().strong());
                        ui.label(desc);
                        ui.end_row();
                    }
                });
        });
}

/// Renders the About dialog.
pub fn show_about_window(ctx: &egui::Context, open: &mut bool, palette: &VaultPalette) {
    if !*open {
        return;
    }
    egui::Window::new("About RustPass")
        .open(open)
        .collapsible(false)
        .resizable(false)
        .fixed_size([420.0, 220.0])
        .show(ctx, |ui| {
            ui.label(
                RichText::new(format!("RustPass v{}", env!("CARGO_PKG_VERSION")))
                    .size(20.0)
                    .strong()
                    .color(palette.accent),
            );
            ui.add_space(4.0);
            ui.label("Clean-room MIT-licensed KDBX 4.0 & 3.1 password manager in 100% safe-first Rust.");
            ui.add_space(8.0);
            ui.label("• KDF: Argon2id / Argon2d / AES-KDF");
            ui.label("• Encryption: ChaCha20 (256-bit) & AES-256-CBC + HMAC-SHA-256 Block Stream");
            ui.label("• 2FA: RFC 6238 TOTP (SHA-1/256/512), Steam Guard & ISO/IEC 18004 QR");
            ui.label("• Memory Hygiene: Zeroize-on-drop secrets & timed clipboard auto-clear");
            ui.add_space(6.0);
            ui.weak("Interoperable with KeePassXC 2.8.0 · Companion binaries: rustpass-cli & rustpass-proxy");
        });
}
