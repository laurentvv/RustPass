//! Vault Security Health Audit (`rustpass-cli analyze` & GUI Security Reports) including offline
//! HaveIBeenPwned (`SHA-1`) hash file checking.

use crate::error::Result;
use crate::generator::{StrengthLevel, estimate_password};
use crate::model::{Database, Entry};
use sha1::{Digest, Sha1};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::path::Path;
use uuid::Uuid;

/// Category of security finding reported on a vault entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingKind {
    /// Empty password.
    EmptyPassword,
    /// Password appeared in an offline HaveIBeenPwned SHA-1 dump (`-H`).
    CompromisedHibp,
    /// Effective entropy `< 50` bits (`VeryWeak` or `Weak`).
    WeakPassword,
    /// Exact password shared across 2 or more active entries.
    ReusedPassword,
    /// Password shorter than 10 characters.
    ShortPassword,
    /// Entry `Times::is_expired()` is true.
    Expired,
    /// Login URL uses unencrypted `http://`.
    InsecureHttpUrl,
    /// Entry has an HTTPS login URL, no TOTP configured, and is older/sensitive.
    MissingTwoFactor,
}

impl FindingKind {
    /// Severity label (`"CRITICAL"`, `"HIGH"`, `"MEDIUM"`, `"INFO"`).
    #[must_use]
    pub const fn severity(self) -> &'static str {
        match self {
            Self::EmptyPassword | Self::CompromisedHibp => "CRITICAL",
            Self::WeakPassword | Self::ReusedPassword => "HIGH",
            Self::ShortPassword | Self::Expired | Self::InsecureHttpUrl => "MEDIUM",
            Self::MissingTwoFactor => "INFO",
        }
    }

    /// English summary label.
    #[must_use]
    pub const fn label_en(self) -> &'static str {
        match self {
            Self::EmptyPassword => "Empty password",
            Self::CompromisedHibp => "Known breached password (HIBP)",
            Self::WeakPassword => "Low entropy / weak password",
            Self::ReusedPassword => "Reused password across multiple entries",
            Self::ShortPassword => "Short password (< 10 chars)",
            Self::Expired => "Expired entry",
            Self::InsecureHttpUrl => "Unencrypted HTTP login URL",
            Self::MissingTwoFactor => "No 2FA / TOTP configured",
        }
    }

    /// French summary label.
    #[must_use]
    pub const fn label_fr(self) -> &'static str {
        match self {
            Self::EmptyPassword => "Mot de passe vide",
            Self::CompromisedHibp => "Mot de passe compromis (HIBP)",
            Self::WeakPassword => "Entropie faible",
            Self::ReusedPassword => "Mot de passe réutilisé",
            Self::ShortPassword => "Mot de passe court (< 10 car.)",
            Self::Expired => "Entrée expirée",
            Self::InsecureHttpUrl => "URL HTTP non chiffrée",
            Self::MissingTwoFactor => "Aucun TOTP / 2FA configuré",
        }
    }
}

/// Individual security finding tied to a vault entry.
#[derive(Debug, Clone)]
pub struct AuditFinding {
    /// Entry UUID.
    pub entry_uuid: Uuid,
    /// Full `/Group/Title` path.
    pub entry_path: String,
    /// Entry title.
    pub title: String,
    /// Finding type.
    pub kind: FindingKind,
    /// Estimated password entropy in bits.
    pub entropy_bits: f64,
    /// Additional context (e.g. number of duplicates or breach count).
    pub detail: String,
}

/// Complete Security Health Audit report for a `Database`.
#[derive(Debug, Clone, Default)]
pub struct AuditReport {
    /// Total active (non-Recycle-Bin) entries scanned.
    pub total_entries: usize,
    /// Average password entropy across non-empty entries (bits).
    pub average_entropy_bits: f64,
    /// Overall vault security score (`0..=100`).
    pub health_score: u8,
    /// Count of weak or empty passwords.
    pub weak_count: usize,
    /// Count of entries sharing a reused password.
    pub reused_count: usize,
    /// Count of expired entries.
    pub expired_count: usize,
    /// Count of unencrypted `http://` URLs.
    pub http_count: usize,
    /// Count of HIBP breached passwords.
    pub hibp_count: usize,
    /// Count of entries with TOTP enabled.
    pub totp_enabled_count: usize,
    /// Detailed findings sorted by severity.
    pub findings: Vec<AuditFinding>,
}

/// Runs a comprehensive Security Health Audit over active entries in `db`, optionally cross-checking
/// password SHA-1 hashes against an offline HIBP file (`SHA1[:COUNT]` lines).
pub fn analyze_database(db: &Database, hibp_file: Option<&Path>) -> Result<AuditReport> {
    let entries = db.all_entries(false);
    let total_entries = entries.len();
    if total_entries == 0 {
        return Ok(AuditReport {
            health_score: 100,
            ..AuditReport::default()
        });
    }

    // Precompute SHA-1 uppercase hex of all non-empty passwords if HIBP file is requested
    let mut hibp_hits: HashMap<[u8; 20], u64> = HashMap::new();
    if let Some(hibp_path) = hibp_file {
        let mut target_hashes: HashSet<[u8; 20]> = HashSet::new();
        for (_, e) in &entries {
            if !e.password.is_empty() {
                let digest = Sha1::digest(e.password.as_str().as_bytes());
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&digest);
                target_hashes.insert(arr);
            }
        }
        if !target_hashes.is_empty() {
            scan_hibp_file(hibp_path, &target_hashes, &mut hibp_hits)?;
        }
    }

    // Count duplicate passwords
    let mut pw_groups: HashMap<&str, Vec<(&str, &Entry)>> = HashMap::new();
    for (g_path, entry) in &entries {
        let pw = entry.password.as_str();
        if !pw.is_empty() {
            pw_groups
                .entry(pw)
                .or_default()
                .push((g_path.as_str(), entry));
        }
    }

    let mut findings = Vec::new();
    let mut entropy_sum = 0.0f64;
    let mut entropy_n = 0usize;
    let mut weak_count = 0usize;
    let mut reused_count = 0usize;
    let mut expired_count = 0usize;
    let mut http_count = 0usize;
    let mut hibp_count = 0usize;
    let mut totp_enabled_count = 0usize;

    for (g_path, entry) in &entries {
        let full_path = if g_path.is_empty() {
            format!("/{}", entry.title)
        } else {
            format!("/{g_path}/{}", entry.title)
        };

        let has_totp = entry.otp.as_ref().is_some_and(|o| !o.is_empty())
            || entry.get_attribute("TOTP Seed").is_some();
        if has_totp {
            totp_enabled_count += 1;
        }

        let pw = entry.password.as_str();
        let est = estimate_password(pw);
        if pw.is_empty() {
            weak_count += 1;
            findings.push(AuditFinding {
                entry_uuid: entry.uuid,
                entry_path: full_path.clone(),
                title: entry.title.clone(),
                kind: FindingKind::EmptyPassword,
                entropy_bits: 0.0,
                detail: "No password set".to_string(),
            });
        } else {
            entropy_sum += est.entropy_bits;
            entropy_n += 1;

            if !hibp_hits.is_empty() {
                let mut sha = [0u8; 20];
                sha.copy_from_slice(&Sha1::digest(pw.as_bytes()));
                if let Some(&breach_n) = hibp_hits.get(&sha) {
                    hibp_count += 1;
                    findings.push(AuditFinding {
                        entry_uuid: entry.uuid,
                        entry_path: full_path.clone(),
                        title: entry.title.clone(),
                        kind: FindingKind::CompromisedHibp,
                        entropy_bits: est.entropy_bits,
                        detail: format!("Found {breach_n} times in HIBP dataset"),
                    });
                }
            }

            if est.level <= StrengthLevel::Weak {
                weak_count += 1;
                findings.push(AuditFinding {
                    entry_uuid: entry.uuid,
                    entry_path: full_path.clone(),
                    title: entry.title.clone(),
                    kind: FindingKind::WeakPassword,
                    entropy_bits: est.entropy_bits,
                    detail: format!("{:.1} bits ({})", est.entropy_bits, est.level.label_en()),
                });
            } else if est.length < 10 {
                findings.push(AuditFinding {
                    entry_uuid: entry.uuid,
                    entry_path: full_path.clone(),
                    title: entry.title.clone(),
                    kind: FindingKind::ShortPassword,
                    entropy_bits: est.entropy_bits,
                    detail: format!("{} characters", est.length),
                });
            }

            if let Some(dups) = pw_groups.get(pw)
                && dups.len() > 1
            {
                reused_count += 1;
                findings.push(AuditFinding {
                    entry_uuid: entry.uuid,
                    entry_path: full_path.clone(),
                    title: entry.title.clone(),
                    kind: FindingKind::ReusedPassword,
                    entropy_bits: est.entropy_bits,
                    detail: format!("Shared across {} entries", dups.len()),
                });
            }
        }

        if entry.times.is_expired() {
            expired_count += 1;
            findings.push(AuditFinding {
                entry_uuid: entry.uuid,
                entry_path: full_path.clone(),
                title: entry.title.clone(),
                kind: FindingKind::Expired,
                entropy_bits: est.entropy_bits,
                detail: format!("Expired on {}", entry.times.expiry_time.format("%Y-%m-%d")),
            });
        }

        let lower_url = entry.url.trim().to_ascii_lowercase();
        if lower_url.starts_with("http://") {
            http_count += 1;
            findings.push(AuditFinding {
                entry_uuid: entry.uuid,
                entry_path: full_path.clone(),
                title: entry.title.clone(),
                kind: FindingKind::InsecureHttpUrl,
                entropy_bits: est.entropy_bits,
                detail: entry.url.clone(),
            });
        } else if lower_url.starts_with("https://") && !has_totp {
            findings.push(AuditFinding {
                entry_uuid: entry.uuid,
                entry_path: full_path,
                title: entry.title.clone(),
                kind: FindingKind::MissingTwoFactor,
                entropy_bits: est.entropy_bits,
                detail: "HTTPS login without TOTP".to_string(),
            });
        }
    }

    findings.sort_by_key(|f| match f.kind {
        FindingKind::CompromisedHibp => 0,
        FindingKind::EmptyPassword => 1,
        FindingKind::WeakPassword => 2,
        FindingKind::ReusedPassword => 3,
        FindingKind::Expired => 4,
        FindingKind::ShortPassword => 5,
        FindingKind::InsecureHttpUrl => 6,
        FindingKind::MissingTwoFactor => 7,
    });

    let average_entropy_bits = if entropy_n > 0 {
        entropy_sum / (entropy_n as f64)
    } else {
        0.0
    };

    // Compute balanced 0..=100 score
    let n = total_entries as f64;
    let penalty = (hibp_count as f64 / n) * 60.0
        + (weak_count as f64 / n) * 45.0
        + (reused_count as f64 / n) * 30.0
        + (expired_count as f64 / n) * 15.0
        + (http_count as f64 / n) * 10.0;
    let health_score = (100.0 - penalty).round().clamp(0.0, 100.0) as u8;

    Ok(AuditReport {
        total_entries,
        average_entropy_bits,
        health_score,
        weak_count,
        reused_count,
        expired_count,
        http_count,
        hibp_count,
        totp_enabled_count,
        findings,
    })
}

fn scan_hibp_file(
    path: &Path,
    targets: &HashSet<[u8; 20]>,
    hits: &mut HashMap<[u8; 20], u64>,
) -> Result<()> {
    let file = std::fs::File::open(path)?;
    let reader = BufReader::new(file);
    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.len() < 40 {
            continue;
        }
        let (hex_part, count_part) = match trimmed.split_once(':') {
            Some((h, c)) => (h.trim(), c.trim()),
            None => (trimmed, "1"),
        };
        if hex_part.len() == 40 {
            let mut decoded = [0u8; 20];
            if hex::decode_to_slice(hex_part.as_bytes(), &mut decoded).is_ok()
                && targets.contains(&decoded)
            {
                let count = count_part.parse::<u64>().unwrap_or(1);
                hits.insert(decoded, count);
            }
        }
    }
    Ok(())
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Exports the audit report as CSV (`Severity,Entry,Entropy bits,Detail`).
/// Contains paths and finding details, never passwords.
#[must_use]
pub fn export_audit_csv(report: &AuditReport) -> String {
    let mut out = String::from("Severity,Entry,Entropy bits,Detail\n");
    for f in &report.findings {
        let severity = match f.kind {
            FindingKind::EmptyPassword | FindingKind::CompromisedHibp => "critical",
            FindingKind::WeakPassword | FindingKind::ReusedPassword => "warning",
            _ => "info",
        };
        let field = |v: &str| format!("\"{}\"", v.replace('"', "\"\""));
        out.push_str(&format!(
            "{},{},{:.1},{}\n",
            severity,
            field(&f.entry_path),
            f.entropy_bits,
            field(&f.detail),
        ));
    }
    out
}

/// Exports the audit report as a standalone styled HTML page (no secrets).
#[must_use]
pub fn export_audit_html(report: &AuditReport) -> String {
    let mut rows = String::new();
    for f in &report.findings {
        let (sev, color) = match f.kind {
            FindingKind::EmptyPassword | FindingKind::CompromisedHibp => ("critical", "#c0392b"),
            FindingKind::WeakPassword | FindingKind::ReusedPassword => ("warning", "#b9770e"),
            _ => ("info", "#1f618d"),
        };
        rows.push_str(&format!(
            "<tr><td><span style=\"color:{color};font-weight:600\">{sev}</span></td><td>{}</td><td>{:.1}</td><td>{}</td></tr>\n",
            escape_html(&f.entry_path),
            f.entropy_bits,
            escape_html(&f.detail),
        ));
    }
    format!(
        "<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">\n<title>RustPass Security Health Audit</title>\n<style>body{{font-family:Segoe UI,system-ui,sans-serif;margin:32px;background:#f6f7f9;color:#1d2126}}\nh1{{font-size:22px}}table{{border-collapse:collapse;width:100%;background:#fff}}\nth,td{{text-align:left;padding:8px 12px;border-bottom:1px solid #e3e6ea;font-size:14px}}\nth{{background:#eef1f4}}\n.score{{font-size:40px;font-weight:700}}</style></head>\n<body>\n<h1>RustPass Security Health Audit</h1>\n<p><span class=\"score\">{score}</span><span style=\"font-size:18px\">/100</span> &middot; {total} entries &middot; avg entropy {avg:.1} bits</p>\n<p>Weak: {weak} &middot; Reused: {reused} &middot; Expired: {expired} &middot; HTTP: {http} &middot; HIBP: {hibp} &middot; 2FA: {totp}</p>\n<table><thead><tr><th>Severity</th><th>Entry</th><th>Entropy (bits)</th><th>Detail</th></tr></thead>\n<tbody>\n{rows}</tbody></table>\n<p style=\"color:#6b7280;font-size:12px;margin-top:16px\">Generated by RustPass \u{2014} this report contains no passwords.</p>\n</body></html>\n",
        score = report.health_score,
        total = report.total_entries,
        avg = report.average_entropy_bits,
        weak = report.weak_count,
        reused = report.reused_count,
        expired = report.expired_count,
        http = report.http_count,
        hibp = report.hibp_count,
        totp = report.totp_enabled_count,
        rows = rows,
    )
}

#[cfg(test)]
mod export_tests {
    use super::*;
    use crate::model::{Database, Entry};

    #[test]
    fn audit_exports_csv_and_html_with_findings() {
        let mut db = Database::new("Export");
        let mut e = Entry::new("WeakOne");
        e.password = "abc".into();
        db.add_entry_at_path("G/WeakOne", e).expect("add");
        let report = analyze_database(&db, None).expect("audit");
        assert!(!report.findings.is_empty());

        let csv = export_audit_csv(&report);
        assert!(csv.starts_with("Severity,Entry,Entropy bits,Detail"));
        assert!(csv.contains("/G/WeakOne"));

        let html = export_audit_html(&report);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("/G/WeakOne"));
        assert!(html.contains("no passwords"));
    }
}
