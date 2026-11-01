//! Vault Import & Export pipelines: KeePassXC-compatible RFC 4180 CSV, plaintext KeePass 2.x XML,
//! and self-contained printable HTML reports.

use crate::crypto::cipher::InnerStream;
use crate::error::{Result, RustPassError};
use crate::kdbx::xml::{XmlSerializeMode, parse_keepass_xml, serialize_keepass_xml};
use crate::model::{Database, Entry, InnerStreamAlgorithm, ProtectedString};
use chrono::{DateTime, Utc};

/// Export format supported by `rustpass-cli export` and the GUI Export dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportFormat {
    /// KeePass 2.x plaintext XML (`--format xml`).
    Xml,
    /// KeePassXC RFC 4180 CSV (`--format csv`).
    Csv,
    /// Printable self-contained HTML table (`--format html`).
    Html,
}

impl ExportFormat {
    /// Parses `"xml"`, `"csv"`, or `"html"`.
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "xml" => Ok(Self::Xml),
            "csv" => Ok(Self::Csv),
            "html" | "htm" => Ok(Self::Html),
            other => Err(RustPassError::InvalidArgument(format!(
                "Unsupported export format '{other}' (expected xml, csv, or html)"
            ))),
        }
    }
}

/// Exports `db` into an in-memory UTF-8 document in `format`.
pub fn export_database(db: &Database, format: ExportFormat) -> Result<String> {
    match format {
        ExportFormat::Xml => {
            let mut stream = InnerStream::new(InnerStreamAlgorithm::None, &[]);
            let (xml, _) = serialize_keepass_xml(
                db,
                XmlSerializeMode {
                    is_kdbx4: false,
                    encrypt_protected: false,
                },
                &mut stream,
            )?;
            Ok(xml.to_string())
        }
        ExportFormat::Csv => Ok(export_csv(db)),
        ExportFormat::Html => Ok(export_html(db)),
    }
}

/// Exports `db` using KeePassXC's exact 10-column CSV schema:
/// `"Group","Title","Username","Password","URL","Notes","TOTP","Icon","Last Modified","Created"`.
#[must_use]
pub fn export_csv(db: &Database) -> String {
    let mut out = String::from(
        "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\",\"Icon\",\"Last Modified\",\"Created\"\n",
    );
    let root_name = &db.root.name;
    for (group_path, entry) in db.all_entries(false) {
        let full_group = if group_path.is_empty() {
            format!("Root/{root_name}")
        } else {
            format!("{root_name}/{group_path}")
        };
        let totp = entry.otp.as_ref().map_or("", ProtectedString::as_str);
        let modified = entry
            .times
            .last_modification_time
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let created = entry
            .times
            .creation_time
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string();
        let icon_str = entry.icon_id.to_string();

        let cols = [
            full_group.as_str(),
            entry.title.as_str(),
            entry.username.as_str(),
            entry.password.as_str(),
            entry.url.as_str(),
            entry.notes.as_str(),
            totp,
            icon_str.as_str(),
            modified.as_str(),
            created.as_str(),
        ];
        for (i, col) in cols.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push('"');
            for ch in col.chars() {
                if ch == '"' {
                    out.push_str("\"\"");
                } else {
                    out.push(ch);
                }
            }
            out.push('"');
        }
        out.push('\n');
    }
    out
}

/// Exports `db` to a clean, self-contained HTML emergency sheet.
#[must_use]
pub fn export_html(db: &Database) -> String {
    let title = if db.meta.database_name.is_empty() {
        &db.root.name
    } else {
        &db.meta.database_name
    };
    let entries = db.all_entries(false);
    let mut rows = String::new();
    for (group, e) in &entries {
        let grp = if group.is_empty() {
            "/"
        } else {
            group.as_str()
        };
        let totp = if e.otp.is_some() { "Yes" } else { "-" };
        rows.push_str(&format!(
            "<tr><td>{}</td><td><strong>{}</strong></td><td>{}</td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
            html_escape(grp),
            html_escape(&e.title),
            html_escape(&e.username),
            html_escape(e.password.as_str()),
            html_escape(&e.url),
            totp,
            html_escape(&e.notes),
        ));
    }

    format!(
        "<!DOCTYPE html>\n\
         <html lang=\"en\">\n\
         <head>\n\
         <meta charset=\"utf-8\">\n\
         <title>RustPass Export — {}</title>\n\
         <style>\n\
           body {{ font-family: 'Segoe UI', system-ui, sans-serif; margin: 2rem; color: #182026; background: #f8fafb; }}\n\
           h1 {{ font-size: 1.4rem; margin-bottom: 0.25rem; }}\n\
           p.meta {{ color: #5c7080; font-size: 0.9rem; margin-bottom: 1.5rem; }}\n\
           table {{ width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #dce3e8; }}\n\
           th, td {{ text-align: left; padding: 0.55rem 0.75rem; border-bottom: 1px solid #e8eef2; font-size: 0.85rem; vertical-align: top; }}\n\
           th {{ background: #eef3f7; font-weight: 600; }}\n\
           code {{ font-family: 'Cascadia Mono', Consolas, monospace; background: #f1f5f9; padding: 0.1rem 0.3rem; border-radius: 3px; }}\n\
         </style>\n\
         </head>\n\
         <body>\n\
           <h1>{}</h1>\n\
           <p class=\"meta\">Exported {} entries on {} UTC — Store securely!</p>\n\
           <table>\n\
             <thead><tr><th>Group</th><th>Title</th><th>Username</th><th>Password</th><th>URL</th><th>2FA</th><th>Notes</th></tr></thead>\n\
             <tbody>\n{}</tbody>\n\
           </table>\n\
         </body>\n\
         </html>\n",
        html_escape(title),
        html_escape(title),
        entries.len(),
        Utc::now().format("%Y-%m-%d %H:%M"),
        rows
    )
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            other => out.push(other),
        }
    }
    out
}

/// Imports a plaintext KeePass 2.x XML document into a new `Database`.
pub fn import_keepass_xml(xml_text: &str) -> Result<Database> {
    let mut stream = InnerStream::new(InnerStreamAlgorithm::None, &[]);
    let (meta, root, deleted_objects) = parse_keepass_xml(xml_text, &mut stream, &[])?;
    let mut db = Database::new(meta.database_name.clone());
    db.meta = meta;
    db.root = root;
    db.deleted_objects = deleted_objects;
    Ok(db)
}

/// Imports entries from a CSV document (KeePassXC, Bitwarden, Chrome/Edge `name,url,username,password`,
/// or generic headered CSV) into `db`, returning the number of imported entries.
pub fn import_csv_into(db: &mut Database, csv_text: &str) -> Result<usize> {
    let records = parse_rfc4180_csv(csv_text.trim_start_matches('\u{feff}'));
    let Some((header_row, data_rows)) = records.split_first() else {
        return Ok(0);
    };

    let col_idx = |names: &[&str]| -> Option<usize> {
        header_row.iter().position(|h| {
            let clean = h.trim().to_ascii_lowercase();
            names.iter().any(|&n| clean == n)
        })
    };

    let idx_group = col_idx(&["group", "folder"]);
    let idx_title = col_idx(&["title", "name", "account"]);
    let idx_user = col_idx(&["username", "login_username", "user", "user name"]);
    let idx_pass = col_idx(&["password", "login_password", "pass"]);
    let idx_url = col_idx(&["url", "login_uri", "website"]);
    let idx_notes = col_idx(&["notes", "extra", "comments"]);
    let idx_totp = col_idx(&["totp", "login_totp", "otp"]);
    let idx_icon = col_idx(&["icon"]);
    let idx_modified = col_idx(&["last modified", "modified"]);
    let idx_created = col_idx(&["created"]);

    if idx_title.is_none() && idx_user.is_none() && idx_pass.is_none() {
        return Err(RustPassError::CorruptedFormat(
            "CSV header does not contain recognizable Title/Username/Password columns".to_string(),
        ));
    }

    fn get_field(row: &[String], idx: Option<usize>) -> &str {
        idx.and_then(|i| row.get(i)).map_or("", String::as_str)
    }

    let mut imported = 0usize;
    for row in data_rows {
        if row.iter().all(|c| c.trim().is_empty()) {
            continue;
        }
        let raw_title = get_field(row, idx_title).trim();
        let title = if raw_title.is_empty() {
            "Imported Entry"
        } else {
            raw_title
        };
        let mut entry = Entry::new(title);
        entry.username = get_field(row, idx_user).to_string();
        entry.password = ProtectedString::new(get_field(row, idx_pass));
        entry.url = get_field(row, idx_url).to_string();
        entry.notes = get_field(row, idx_notes).to_string();

        let totp_val = get_field(row, idx_totp).trim();
        if !totp_val.is_empty() {
            entry.otp = Some(ProtectedString::new(totp_val));
        }
        if let Ok(icon) = get_field(row, idx_icon).trim().parse::<u32>() {
            entry.icon_id = icon;
        }
        if let Ok(dt) = DateTime::parse_from_rfc3339(get_field(row, idx_modified).trim()) {
            entry.times.last_modification_time = dt.with_timezone(&Utc);
        }
        if let Ok(dt) = DateTime::parse_from_rfc3339(get_field(row, idx_created).trim()) {
            entry.times.creation_time = dt.with_timezone(&Utc);
        }

        let mut group_raw = get_field(row, idx_group).trim().to_string();
        if let Some(rest) = group_raw.strip_prefix("Root/") {
            group_raw = rest.to_string();
        }
        let target_group = db.mkdir_p(&group_raw);
        target_group.entries.push(entry);
        imported += 1;
    }

    Ok(imported)
}

/// Complete RFC 4180 CSV parser supporting quoted fields, embedded newlines, and `""` escapes.
#[must_use]
pub fn parse_rfc4180_csv(input: &str) -> Vec<Vec<String>> {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut current_row: Vec<String> = Vec::new();
    let mut current_field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    let _ = chars.next();
                    current_field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current_field.push(ch);
            }
        } else {
            match ch {
                '"' if current_field.is_empty() => {
                    in_quotes = true;
                }
                ',' => {
                    current_row.push(std::mem::take(&mut current_field));
                }
                '\r' => {
                    if chars.peek() == Some(&'\n') {
                        let _ = chars.next();
                    }
                    current_row.push(std::mem::take(&mut current_field));
                    rows.push(std::mem::take(&mut current_row));
                }
                '\n' => {
                    current_row.push(std::mem::take(&mut current_field));
                    rows.push(std::mem::take(&mut current_row));
                }
                other => {
                    current_field.push(other);
                }
            }
        }
    }

    if !current_field.is_empty() || !current_row.is_empty() {
        current_row.push(current_field);
        rows.push(current_row);
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_and_xml_roundtrip_preserve_multiline_notes_and_totp() {
        let mut db = Database::new("TeamVault");
        let mut e = Entry::new("Prod DB");
        e.username = "postgres".to_string();
        e.password = "p@ss,\"quote\"\nline2".into();
        e.notes = "Line 1\nLine 2, with \"quotes\"".to_string();
        e.otp = Some("otpauth://totp/DB?secret=JBSWY3DPEHPK3PXP".into());
        db.add_entry_at_path("Servers/Prod DB", e).expect("add");

        let csv = export_csv(&db);
        let mut imported_db = Database::new("TeamVault");
        let count = import_csv_into(&mut imported_db, &csv).expect("import csv");
        assert_eq!(count, 1);
        let got = imported_db
            .resolve_entry("Servers/Prod DB")
            .expect("resolved");
        assert_eq!(got.password.as_str(), "p@ss,\"quote\"\nline2");
        assert_eq!(got.notes, "Line 1\nLine 2, with \"quotes\"");

        let xml = export_database(&db, ExportFormat::Xml).expect("export xml");
        let from_xml = import_keepass_xml(&xml).expect("import xml");
        assert_eq!(
            from_xml
                .resolve_entry("Servers/Prod DB")
                .expect("xml entry")
                .username,
            "postgres"
        );
    }
}
