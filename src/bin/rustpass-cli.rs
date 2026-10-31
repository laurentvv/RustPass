//! `rustpass-cli` — Drop-in `keepassxc-cli` compatible KDBX 3.1 & 4.0 command-line tool.

use clap::Parser;
use rustpass::cli::{CliCommand, CliRoot, VaultOpenArgs};
use rustpass::crypto::kdf::{MasterCredentials, calibrate_argon2id};
use rustpass::crypto::keyfile::write_new_keyfile;
use rustpass::error::{Result, RustPassError, assert_safe_output_path};
use rustpass::generator::{DicewareOptions, estimate_password};
use rustpass::health::analyze_database;
use rustpass::io::{ExportFormat, export_database, import_csv_into, import_keepass_xml};
use rustpass::model::{
    Attachment, Database, Entry, Group, KdbxVersion, KdfConfig, ProtectedString,
};
use rustpass::search::search_database;
use rustpass::totp::TotpConfig;
use std::io::{BufRead, BufReader, IsTerminal, Stdin, Write};
use std::path::Path;
use std::process::ExitCode;
use zeroize::Zeroizing;

fn main() -> ExitCode {
    let args = CliRoot::parse();
    match run(args.command) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("Error: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Buffered reader over `stdin` so multi-prompt piped commands (`db-create -p`, `add -p`, `merge`)
/// consume consecutive lines cleanly without losing buffered bytes.
struct PromptReader {
    is_tty: bool,
    reader: BufReader<Stdin>,
}

impl PromptReader {
    fn new() -> Self {
        let stdin = std::io::stdin();
        let is_tty = stdin.is_terminal();
        Self {
            is_tty,
            reader: BufReader::new(stdin),
        }
    }

    fn read_secret(&mut self, prompt: &str, quiet: bool) -> Result<Zeroizing<String>> {
        if self.is_tty {
            if !quiet {
                eprint!("{prompt}");
                let _ = std::io::stderr().flush();
            }
            let pw = rpassword::read_password().map_err(RustPassError::Io)?;
            Ok(Zeroizing::new(pw))
        } else {
            let mut line = Zeroizing::new(String::new());
            let n = self.reader.read_line(&mut line)?;
            if n == 0 && line.is_empty() {
                return Ok(Zeroizing::new(String::new()));
            }
            while line.ends_with('\n') || line.ends_with('\r') {
                line.pop();
            }
            Ok(line)
        }
    }

    fn read_confirmed_secret(&mut self, label: &str, quiet: bool) -> Result<Zeroizing<String>> {
        let first = self.read_secret(&format!("Enter {label}: "), quiet)?;
        if self.is_tty {
            let second = self.read_secret(&format!("Repeat {label}: "), quiet)?;
            if *first != *second {
                return Err(RustPassError::InvalidArgument(
                    "Passwords do not match".to_string(),
                ));
            }
        } else {
            // In piped mode (`printf "pw\npw\n" | keepassxc-cli db-create -p ...`), consume an
            // optional confirmation line if present and matching, or error if non-empty & different.
            let mut second = Zeroizing::new(String::new());
            let n = self.reader.read_line(&mut second)?;
            if n > 0 {
                while second.ends_with('\n') || second.ends_with('\r') {
                    second.pop();
                }
                if !second.is_empty() && *second != *first {
                    return Err(RustPassError::InvalidArgument(
                        "Passwords do not match".to_string(),
                    ));
                }
            }
        }
        Ok(first)
    }

    fn unlock_vault(
        &mut self,
        open: &VaultOpenArgs,
        db_path: &Path,
    ) -> Result<(Database, MasterCredentials)> {
        if open.yubikey.is_some() {
            return Err(RustPassError::UnsupportedFeature(
                "Hardware YubiKey challenge-response (-y/--yubikey) is outside clean-room scope"
                    .to_string(),
            ));
        }

        let pw_opt = if open.no_password {
            None
        } else {
            let prompt = format!("Enter password to unlock {}: ", db_path.display());
            let secret = self.read_secret(&prompt, open.quiet)?;
            Some(secret.as_str().to_string())
        };

        let creds = MasterCredentials::new(pw_opt, open.key_file.as_deref())?;
        let db = Database::open(db_path, &creds)?;
        Ok((db, creds))
    }
}

fn run(command: CliCommand) -> Result<()> {
    let mut prompts = PromptReader::new();

    match command {
        CliCommand::Close => Ok(()),

        CliCommand::Generate {
            quiet: _,
            gen_flags,
        } => {
            let pw = gen_flags.into_options().generate()?;
            println!("{}", pw.as_str());
            Ok(())
        }

        CliCommand::Diceware {
            quiet: _,
            words,
            word_list,
        } => {
            let opts = DicewareOptions {
                word_count: words,
                separator: " ".to_string(),
                capitalize: false,
                include_number: false,
                wordlist_path: word_list,
            };
            let (phrase, _) = opts.generate()?;
            println!("{}", phrase.as_str());
            Ok(())
        }

        CliCommand::Estimate {
            quiet,
            advanced,
            password,
        } => {
            let pw_buf = match password {
                Some(p) => Zeroizing::new(p),
                None => prompts.read_secret("Enter password to estimate: ", quiet)?,
            };
            let est = estimate_password(&pw_buf);
            println!(
                "Length {}   Entropy {:.2} bits   Rating: {}",
                est.length,
                est.entropy_bits,
                est.level.label_en()
            );
            if advanced {
                println!(
                    "Estimated offline crack time (10^10 H/s): {}",
                    est.crack_time_display
                );
                for w in est.warnings {
                    println!("Warning: {w}");
                }
            }
            Ok(())
        }

        CliCommand::DbCreate {
            quiet,
            set_key_file,
            legacy_key_file,
            set_password,
            decryption_time,
            kdbx3,
            database,
        } => {
            let kf_path = set_key_file.or(legacy_key_file);
            if let Some(ref kf) = kf_path
                && !kf.exists()
            {
                write_new_keyfile(kf, false)?;
            }

            let pw_opt = if set_password || kf_path.is_none() {
                let pw = prompts.read_confirmed_secret("password to encrypt database", quiet)?;
                Some(pw.as_str().to_string())
            } else {
                None
            };

            let stem = database
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Passwords");
            let mut db = Database::new(stem);
            if kdbx3 {
                db.version = KdbxVersion::V3_1;
                db.kdf = KdfConfig::AesKdf {
                    rounds: decryption_time.unwrap_or(1000) * 100,
                    seed: [0u8; 32],
                };
            } else if let Some(ms) = decryption_time {
                db.kdf = calibrate_argon2id(ms)?;
            }

            let creds = MasterCredentials::new(pw_opt, kf_path.as_deref())?;
            db.save_atomic(&database, &creds)?;
            if !quiet {
                eprintln!("Successfully created database {}", database.display());
            }
            Ok(())
        }

        CliCommand::DbInfo { open, database } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            println!("Format version: {}", db.version.label());
            println!(
                "Name: {}",
                if db.meta.database_name.is_empty() {
                    &db.root.name
                } else {
                    &db.meta.database_name
                }
            );
            println!("Description: {}", db.meta.database_description);
            println!("Cipher: {}", db.cipher.name());
            println!("KDF: {}", db.kdf.summary());
            println!(
                "Compression: {}",
                if db.compression_gzip { "GZip" } else { "None" }
            );
            println!("Groups: {}", db.root.total_group_count());
            println!("Entries: {}", db.root.total_entry_count());
            println!(
                "Recycle bin: {}",
                if db.meta.recycle_bin_enabled {
                    "enabled"
                } else {
                    "disabled"
                }
            );
            Ok(())
        }

        CliCommand::DbEdit {
            open,
            set_key_file,
            set_password,
            unset_key_file,
            unset_password,
            database,
        } => {
            let (mut db, mut creds) = prompts.unlock_vault(&open, &database)?;
            if unset_password {
                creds.password = None;
            } else if set_password {
                let new_pw = prompts.read_confirmed_secret("new password", open.quiet)?;
                creds.password = Some(ProtectedString::new(new_pw.as_str()));
            }

            if unset_key_file {
                creds.keyfile_path = None;
                creds.keyfile_key = None;
            } else if let Some(ref kf) = set_key_file {
                if !kf.exists() {
                    write_new_keyfile(kf, false)?;
                }
                let updated = MasterCredentials::new(
                    creds.password.as_ref().map(|p| p.as_str().to_string()),
                    Some(kf),
                )?;
                creds = updated;
            }

            let _ = creds.composite_key()?;
            db.meta.master_key_changed = chrono::Utc::now();
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Ls {
            open,
            recursive,
            flatten,
            database,
            group,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let target_group = db.resolve_group(group.as_deref().unwrap_or("/"))?;
            print_group_ls(target_group, "", 0, recursive, flatten);
            Ok(())
        }

        CliCommand::Show {
            open,
            totp,
            attributes,
            show_protected,
            all,
            show_attachments,
            database,
            entry,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let target = db.resolve_entry(&entry)?;

            if totp {
                let cfg = TotpConfig::from_entry(target)?;
                let (code, _) = cfg.generate_now()?;
                println!("{code}");
                return Ok(());
            }

            if !attributes.is_empty() {
                for attr in &attributes {
                    if attr.eq_ignore_ascii_case("totp") {
                        let cfg = TotpConfig::from_entry(target)?;
                        let (code, _) = cfg.generate_now()?;
                        println!("{code}");
                    } else if let Some(val) = target.get_attribute(attr) {
                        println!("{val}");
                    } else {
                        println!();
                    }
                }
                return Ok(());
            }

            let mask_or = |val: &str, is_secret: bool| -> String {
                if is_secret && !show_protected {
                    "PROTECTED".to_string()
                } else {
                    val.to_string()
                }
            };

            println!("Title: {}", target.title);
            println!("UserName: {}", target.username);
            println!("Password: {}", mask_or(target.password.as_str(), true));
            println!("URL: {}", target.url);
            println!("Notes: {}", target.notes);
            if all {
                println!("UUID: {}", target.uuid);
                println!("Tags: {}", target.tags.join(", "));
                if let Some(ref otp) = target.otp {
                    println!("otp: {}", mask_or(otp.as_str(), true));
                }
                for ca in &target.custom_attributes {
                    println!("{}: {}", ca.key, mask_or(ca.value.as_str(), ca.protected));
                }
            }
            if show_attachments || all {
                for att in &target.attachments {
                    println!("Attachment: {} ({} bytes)", att.name, att.data.len());
                }
            }
            Ok(())
        }

        CliCommand::Add {
            open,
            username,
            url,
            notes,
            totp,
            password_prompt,
            generate,
            gen_flags,
            database,
            entry,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let mut new_entry = Entry::new("");
            if let Some(u) = username {
                new_entry.username = u;
            }
            if let Some(u) = url {
                new_entry.url = u;
            }
            if let Some(n) = notes {
                new_entry.notes = n;
            }
            if let Some(t) = totp {
                let cfg = TotpConfig::parse(&t)?;
                new_entry.otp = Some(ProtectedString::new(cfg.to_otpauth_uri()));
            }
            if generate {
                new_entry.password = gen_flags.into_options().generate()?;
            } else if password_prompt {
                let pw =
                    prompts.read_secret(&format!("Enter password for {entry}: "), open.quiet)?;
                new_entry.password = ProtectedString::new(pw.as_str());
            }

            db.add_entry_at_path(&entry, new_entry)?;
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Edit {
            open,
            username,
            url,
            notes,
            title,
            totp,
            password_prompt,
            generate,
            gen_flags,
            database,
            entry,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let history_max = db.meta.history_max_items;
            let target = db.resolve_entry_mut(&entry)?;
            target.push_history_snapshot(history_max);

            if let Some(t) = title {
                target.title = t;
            }
            if let Some(u) = username {
                target.username = u;
            }
            if let Some(u) = url {
                target.url = u;
            }
            if let Some(n) = notes {
                target.notes = n;
            }
            if let Some(t) = totp {
                if t.is_empty() {
                    target.otp = None;
                } else {
                    let cfg = TotpConfig::parse(&t)?;
                    target.otp = Some(ProtectedString::new(cfg.to_otpauth_uri()));
                }
            }
            if generate {
                target.password = gen_flags.into_options().generate()?;
            } else if password_prompt {
                let pw = prompts
                    .read_secret(&format!("Enter new password for {entry}: "), open.quiet)?;
                target.password = ProtectedString::new(pw.as_str());
            }
            target.times.touch_modified();

            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Rm {
            open,
            database,
            entry,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let uuid = db.resolve_entry(&entry)?.uuid;
            db.delete_entry_by_uuid(uuid, false)?;
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Mv {
            open,
            database,
            entry,
            group,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            db.move_entry(&entry, &group)?;
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Mkdir {
            open,
            database,
            group,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let _ = db.mkdir_p(&group);
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Rmdir {
            open,
            database,
            group,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            db.remove_group(&group)?;
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Search {
            open,
            database,
            term,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            for (path, _) in search_database(&db, &term, false) {
                println!("{path}");
            }
            Ok(())
        }

        CliCommand::Analyze {
            open,
            hibp,
            okon: _,
            database,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let report = analyze_database(&db, hibp.as_deref())?;
            println!(
                "Vault Security Score: {}/100 ({} entries, avg {:.1} bits)",
                report.health_score, report.total_entries, report.average_entropy_bits
            );
            println!(
                "Weak: {} | Reused: {} | Expired: {} | HTTP: {} | HIBP Breached: {} | TOTP: {}",
                report.weak_count,
                report.reused_count,
                report.expired_count,
                report.http_count,
                report.hibp_count,
                report.totp_enabled_count
            );
            for f in &report.findings {
                println!(
                    "[{}] {} — {}: {}",
                    f.kind.severity(),
                    f.entry_path,
                    f.kind.label_en(),
                    f.detail
                );
            }
            Ok(())
        }

        CliCommand::Export {
            open,
            format,
            database,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let fmt = ExportFormat::parse(&format)?;
            let out = export_database(&db, fmt)?;
            print!("{out}");
            Ok(())
        }

        CliCommand::Import {
            quiet,
            set_key_file,
            legacy_key_file,
            set_password,
            decryption_time,
            xml,
            database,
        } => {
            let kf_path = set_key_file.or(legacy_key_file);
            if let Some(ref kf) = kf_path
                && !kf.exists()
            {
                write_new_keyfile(kf, false)?;
            }
            let pw_opt = if set_password || kf_path.is_none() {
                let pw = prompts.read_confirmed_secret("password to encrypt database", quiet)?;
                Some(pw.as_str().to_string())
            } else {
                None
            };

            let raw = std::fs::read_to_string(&xml)?;
            let is_csv = xml
                .extension()
                .and_then(|e| e.to_str())
                .is_some_and(|e| e.eq_ignore_ascii_case("csv"));
            let mut db = if is_csv {
                let mut d = Database::new("Imported");
                let _ = import_csv_into(&mut d, &raw)?;
                d
            } else {
                import_keepass_xml(&raw)?
            };

            if let Some(ms) = decryption_time {
                db.kdf = calibrate_argon2id(ms)?;
            }
            let creds = MasterCredentials::new(pw_opt, kf_path.as_deref())?;
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Merge {
            open,
            same_credentials,
            key_file_from,
            no_password_from,
            dry_run,
            yubikey_from,
            database,
            database2,
        } => {
            if yubikey_from.is_some() {
                return Err(RustPassError::UnsupportedFeature(
                    "Hardware YubiKey challenge-response is outside clean-room scope".to_string(),
                ));
            }
            let (mut dst_db, dst_creds) = prompts.unlock_vault(&open, &database)?;
            let src_db = if same_credentials {
                Database::open(&database2, &dst_creds)?
            } else {
                let src_open = VaultOpenArgs {
                    quiet: open.quiet,
                    key_file: key_file_from,
                    no_password: no_password_from,
                    yubikey: None,
                };
                let (d, _) = prompts.unlock_vault(&src_open, &database2)?;
                d
            };

            let report = dst_db.merge_from(&src_db, dry_run);
            if !open.quiet {
                println!(
                    "Merge summary: +{} added, ~{} updated, +{} groups, -{} deleted",
                    report.entries_added.len(),
                    report.entries_updated.len(),
                    report.groups_added.len(),
                    report.items_deleted
                );
            }
            if !dry_run {
                dst_db.save_atomic(&database, &dst_creds)?;
            }
            Ok(())
        }

        CliCommand::AttachmentImport {
            open,
            force,
            database,
            entry,
            attachment_name,
            import_file,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let data = std::fs::read(&import_file)?;
            let target = db.resolve_entry_mut(&entry)?;
            if let Some(existing) = target
                .attachments
                .iter_mut()
                .find(|a| a.name == attachment_name)
            {
                if !force {
                    return Err(RustPassError::InvalidArgument(format!(
                        "Attachment '{attachment_name}' already exists (pass -f/--force to overwrite)"
                    )));
                }
                existing.data = data;
            } else {
                target.attachments.push(Attachment {
                    name: attachment_name,
                    data,
                    protected: true,
                });
            }
            target.times.touch_modified();
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::AttachmentExport {
            open,
            stdout,
            database,
            entry,
            attachment_name,
            export_file,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let target = db.resolve_entry(&entry)?;
            let att = target
                .attachments
                .iter()
                .find(|a| a.name == attachment_name)
                .ok_or_else(|| {
                    RustPassError::InvalidArgument(format!(
                        "Attachment '{attachment_name}' not found on entry '{entry}'"
                    ))
                })?;

            if stdout {
                let mut out = std::io::stdout().lock();
                out.write_all(&att.data)?;
                out.flush()?;
                return Ok(());
            }

            let Some(out_path) = export_file else {
                // Default safely into current directory with Zip-Slip path traversal protection!
                let cwd = std::env::current_dir()?;
                let safe = assert_safe_output_path(&cwd, &att.name)?;
                std::fs::write(safe, &att.data)?;
                return Ok(());
            };
            // Also guard against malicious attachment names when `out_path` is an existing directory
            if out_path.is_dir() {
                let safe = assert_safe_output_path(&out_path, &att.name)?;
                std::fs::write(safe, &att.data)?;
            } else {
                if let Some(parent) = out_path.parent()
                    && !parent.as_os_str().is_empty()
                {
                    std::fs::create_dir_all(parent)?;
                }
                std::fs::write(&out_path, &att.data)?;
            }
            Ok(())
        }

        CliCommand::AttachmentRm {
            open,
            database,
            entry,
            name,
        } => {
            let (mut db, creds) = prompts.unlock_vault(&open, &database)?;
            let target = db.resolve_entry_mut(&entry)?;
            let before = target.attachments.len();
            target.attachments.retain(|a| a.name != name);
            if target.attachments.len() == before {
                return Err(RustPassError::InvalidArgument(format!(
                    "Attachment '{name}' not found on entry '{entry}'"
                )));
            }
            target.times.touch_modified();
            db.save_atomic(&database, &creds)?;
            Ok(())
        }

        CliCommand::Clip {
            open,
            attribute,
            totp,
            best_match,
            database,
            entry,
            timeout,
        } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let target = if let Ok(exact) = db.resolve_entry(&entry) {
                exact
            } else if best_match {
                let hits = search_database(&db, &entry, false);
                if hits.len() == 1 {
                    hits[0].1
                } else {
                    return Err(RustPassError::EntryNotFound(format!(
                        "Ambiguous or missing match for '{entry}' ({} matches)",
                        hits.len()
                    )));
                }
            } else {
                return Err(RustPassError::EntryNotFound(entry));
            };

            let secret = if totp || attribute.eq_ignore_ascii_case("totp") {
                let cfg = TotpConfig::from_entry(target)?;
                Zeroizing::new(cfg.generate_now()?.0)
            } else {
                let val = target.get_attribute(&attribute).ok_or_else(|| {
                    RustPassError::InvalidArgument(format!("Attribute '{attribute}' not found"))
                })?;
                Zeroizing::new(val.to_string())
            };

            let mut clipboard = arboard::Clipboard::new()
                .map_err(|e| RustPassError::UnsupportedFeature(format!("Clipboard error: {e}")))?;
            clipboard
                .set_text(secret.as_str())
                .map_err(|e| RustPassError::UnsupportedFeature(format!("Clipboard write: {e}")))?;

            let secs = timeout.unwrap_or(0);
            if secs > 0 {
                if !open.quiet {
                    eprintln!("Copied {attribute} to clipboard. Clearing in {secs} seconds…");
                }
                std::thread::sleep(std::time::Duration::from_secs(secs));
                if let Ok(curr) = clipboard.get_text()
                    && curr == secret.as_str()
                {
                    let _ = clipboard.clear();
                }
            }
            Ok(())
        }

        CliCommand::Open { open, database } => {
            let (db, _) = prompts.unlock_vault(&open, &database)?;
            let name = if db.meta.database_name.is_empty() {
                &db.root.name
            } else {
                &db.meta.database_name
            };
            let stdin = std::io::stdin();
            for line_res in stdin.lock().lines() {
                if !open.quiet {
                    eprint!("{name}> ");
                    let _ = std::io::stderr().flush();
                }
                let line = line_res?;
                let cmd = line.trim();
                if cmd.is_empty() {
                    continue;
                }
                if matches!(cmd, "exit" | "quit" | "close") {
                    break;
                }
                if cmd == "ls" {
                    print_group_ls(&db.root, "", 0, true, true);
                } else if let Some(q) = cmd.strip_prefix("search ") {
                    for (p, _) in search_database(&db, q.trim(), false) {
                        println!("{p}");
                    }
                } else if let Some(e_name) = cmd.strip_prefix("show ") {
                    match db.resolve_entry(e_name.trim()) {
                        Ok(ent) => {
                            println!("Title: {}", ent.title);
                            println!("UserName: {}", ent.username);
                            println!("URL: {}", ent.url);
                        }
                        Err(err) => eprintln!("{err}"),
                    }
                } else {
                    println!("Commands: ls | search <term> | show <entry> | close | quit");
                }
            }
            Ok(())
        }
    }
}

fn print_group_ls(group: &Group, prefix: &str, depth: usize, recursive: bool, flatten: bool) {
    let indent = if flatten {
        String::new()
    } else {
        "  ".repeat(depth)
    };

    for child in &group.children {
        let child_path = if prefix.is_empty() {
            format!("{}/", child.name)
        } else {
            format!("{prefix}{}/", child.name)
        };
        if flatten {
            println!("{child_path}");
        } else {
            println!("{indent}{}/", child.name);
        }
        if recursive {
            print_group_ls(child, &child_path, depth + 1, true, flatten);
        }
    }

    for entry in &group.entries {
        if flatten {
            println!("{prefix}{}", entry.title);
        } else {
            println!("{indent}{}", entry.title);
        }
    }
}
