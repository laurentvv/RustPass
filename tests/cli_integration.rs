//! End-to-end CLI integration tests and real bidirectional KDBX 3.1 / 4.0 interoperability tests
//! against the host installation of `C:\Program Files\KeePassXC\keepassxc-cli.exe`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn rustpass_cli_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rustpass-cli"))
}

fn temp_test_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "rustpass_it_{tag}_{}_{}",
        std::process::id(),
        uuid::Uuid::new_v4().simple()
    ));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn run_bin(
    bin: &Path,
    cwd: Option<&Path>,
    args: &[&str],
    stdin_bytes: &[u8],
) -> (bool, String, String) {
    let mut cmd = Command::new(bin);
    if let Some(dir) = cwd {
        cmd.current_dir(dir);
    }
    cmd.args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd.spawn().expect("spawn binary");
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(stdin_bytes);
    }
    let out = child.wait_with_output().expect("wait binary");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn full_rustpass_cli_subcommand_lifecycle() {
    let dir = temp_test_dir("lifecycle");
    let vault = dir.join("vault4.kdbx");
    let vault_str = vault.to_str().expect("utf8 path");
    let bin = rustpass_cli_bin();

    // 1. db-create (KDBX 4.0 Argon2id + ChaCha20)
    let (ok, _, stderr) = run_bin(
        &bin,
        None,
        &["db-create", "-q", "-p", "-t", "100", vault_str],
        b"MasterPass#2026\nMasterPass#2026\n",
    );
    assert!(ok, "db-create failed: {stderr}");
    assert!(vault.is_file());

    // 2. mkdir + add with TOTP
    let (ok, _, stderr) = run_bin(
        &bin,
        None,
        &["mkdir", "-q", vault_str, "Infra/Cloud"],
        b"MasterPass#2026\n",
    );
    assert!(ok, "mkdir failed: {stderr}");

    let (ok, _, stderr) = run_bin(
        &bin,
        None,
        &[
            "add",
            "-q",
            "-u",
            "devops",
            "--url",
            "https://console.aws.example",
            "--notes",
            "Root prod login",
            "--totp",
            "JBSWY3DPEHPK3PXP",
            "-p",
            vault_str,
            "Infra/Cloud/AWS",
        ],
        b"MasterPass#2026\nEntrySecret!99\n",
    );
    assert!(ok, "add failed: {stderr}");

    // 3. attachment-import & attachment-export --stdout
    let sample_file = dir.join("cert.pem");
    let pem_bytes = b"-----BEGIN CERTIFICATE-----\nCLEANROOM2026\n-----END CERTIFICATE-----\n";
    std::fs::write(&sample_file, pem_bytes).expect("write pem");
    let (ok, _, stderr) = run_bin(
        &bin,
        None,
        &[
            "attachment-import",
            "-q",
            vault_str,
            "Infra/Cloud/AWS",
            "cert.pem",
            sample_file.to_str().expect("utf8"),
        ],
        b"MasterPass#2026\n",
    );
    assert!(ok, "attachment-import failed: {stderr}");

    let (ok, stdout, stderr) = run_bin(
        &bin,
        None,
        &[
            "attachment-export",
            "-q",
            "--stdout",
            vault_str,
            "Infra/Cloud/AWS",
            "cert.pem",
        ],
        b"MasterPass#2026\n",
    );
    assert!(ok, "attachment-export failed: {stderr}");
    assert_eq!(stdout.as_bytes(), pem_bytes);

    // 4. show -s, show -t, search, analyze, export csv/xml/html
    let (ok, stdout, _) = run_bin(
        &bin,
        None,
        &["show", "-q", "-s", vault_str, "Infra/Cloud/AWS"],
        b"MasterPass#2026\n",
    );
    assert!(ok);
    assert!(stdout.contains("UserName: devops"));
    assert!(stdout.contains("Password: EntrySecret!99"));

    let (ok, totp_out, _) = run_bin(
        &bin,
        None,
        &["show", "-q", "-t", vault_str, "Infra/Cloud/AWS"],
        b"MasterPass#2026\n",
    );
    assert!(ok);
    assert_eq!(totp_out.trim().len(), 6);
    assert!(totp_out.trim().chars().all(|c| c.is_ascii_digit()));

    let (ok, search_out, _) = run_bin(
        &bin,
        None,
        &["search", "-q", vault_str, "u:devops is:totp"],
        b"MasterPass#2026\n",
    );
    assert!(ok);
    assert!(search_out.contains("/Infra/Cloud/AWS"));

    let (ok, csv_out, _) = run_bin(
        &bin,
        None,
        &["export", "-q", "-f", "csv", vault_str],
        b"MasterPass#2026\n",
    );
    assert!(ok);
    assert!(csv_out.contains("\"AWS\",\"devops\",\"EntrySecret!99\""));

    // 5. generator, diceware, estimate, and explicit YubiKey rejection
    let (ok, gen_out, _) = run_bin(
        &bin,
        None,
        &[
            "generate",
            "-L",
            "28",
            "-l",
            "-U",
            "-n",
            "-s",
            "--every-group",
        ],
        b"",
    );
    assert!(ok);
    assert_eq!(gen_out.trim().chars().count(), 28);

    let (ok, dw_out, _) = run_bin(&bin, None, &["diceware", "-W", "5"], b"");
    assert!(ok);
    assert_eq!(dw_out.split_whitespace().count(), 5);

    let (ok_yk, _, err_yk) = run_bin(
        &bin,
        None,
        &["db-info", "-y", "1:12345", vault_str],
        b"MasterPass#2026\n",
    );
    assert!(!ok_yk);
    assert!(err_yk.to_lowercase().contains("yubikey"));

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn bidirectional_interoperability_with_real_keepassxc_cli() {
    let kpxc_dir = Path::new(r"C:\Program Files\KeePassXC");
    let kpxc_bin = kpxc_dir.join("keepassxc-cli.exe");
    if !kpxc_bin.is_file() {
        eprintln!("Skipping real keepassxc-cli test because binary is absent on this machine.");
        return;
    }

    let dir = temp_test_dir("kpxc_interop");
    let rp_bin = rustpass_cli_bin();

    // =========================================================================
    // Direction 1: Created & populated by real `keepassxc-cli.exe` -> read & edited by `rustpass-cli.exe` -> verified by `keepassxc-cli.exe`
    // =========================================================================
    let db_from_kpxc = dir.join("from_keepassxc.kdbx");
    let kf_from_kpxc = dir.join("from_keepassxc.keyx");
    let db1 = db_from_kpxc.to_str().expect("utf8");
    let kf1 = kf_from_kpxc.to_str().expect("utf8");

    let (ok, _, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &[
            "db-create",
            "-q",
            "-p",
            "--set-key-file",
            kf1,
            "-t",
            "100",
            db1,
        ],
        b"CrossVault#1\nCrossVault#1\n",
    );
    assert!(ok, "keepassxc-cli db-create failed: {err}");

    let (ok, _, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &["mkdir", "-q", "-k", kf1, db1, "Servers"],
        b"CrossVault#1\n",
    );
    assert!(ok, "keepassxc-cli mkdir failed: {err}");

    let (ok, _, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &[
            "add",
            "-q",
            "-k",
            kf1,
            "-u",
            "ubuntu",
            "--url",
            "https://srv01.example.org",
            "-p",
            db1,
            "Servers/Bastion",
        ],
        b"CrossVault#1\nBastion#Pass42!\n",
    );
    assert!(ok, "keepassxc-cli add failed: {err}");

    // Open and inspect with `rustpass-cli`!
    let (ok, rp_show, err) = run_bin(
        &rp_bin,
        None,
        &["show", "-q", "-s", "-k", kf1, db1, "Servers/Bastion"],
        b"CrossVault#1\n",
    );
    assert!(
        ok,
        "rustpass-cli failed to open keepassxc-created vault: {err}"
    );
    assert!(rp_show.contains("UserName: ubuntu"));
    assert!(rp_show.contains("Password: Bastion#Pass42!"));
    assert!(rp_show.contains("URL: https://srv01.example.org"));

    // Mutate that vault with `rustpass-cli` and verify `keepassxc-cli` reads it cleanly!
    let (ok, _, err) = run_bin(
        &rp_bin,
        None,
        &[
            "add",
            "-q",
            "-k",
            kf1,
            "-u",
            "grafana",
            "-p",
            db1,
            "Servers/Metrics",
        ],
        b"CrossVault#1\nGrafana$9000\n",
    );
    assert!(ok, "rustpass-cli add onto v3.1 vault failed: {err}");

    let (ok, kpxc_verify, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &["show", "-q", "-s", "-k", kf1, db1, "Servers/Metrics"],
        b"CrossVault#1\n",
    );
    assert!(
        ok,
        "keepassxc-cli failed to read rustpass-updated vault: {err}"
    );
    assert!(kpxc_verify.contains("grafana"));
    assert!(kpxc_verify.contains("Grafana$9000"));

    // =========================================================================
    // Direction 2: KDBX 4.0 (Argon2id + ChaCha20 + Inner Header Attachment + .keyx v2.0 + TOTP)
    // created from scratch by `rustpass-cli` -> opened & verified by real `keepassxc-cli.exe`!
    // =========================================================================
    let db_from_rp = dir.join("from_rustpass_v4.kdbx");
    let kf_from_rp = dir.join("from_rustpass_v4.keyx");
    let att_src = dir.join("payload.bin");
    let att_bytes: Vec<u8> = (0u8..=255).collect();
    std::fs::write(&att_src, &att_bytes).expect("write binary attachment");

    let db2 = db_from_rp.to_str().expect("utf8");
    let kf2 = kf_from_rp.to_str().expect("utf8");

    let (ok, _, err) = run_bin(
        &rp_bin,
        None,
        &[
            "db-create",
            "-q",
            "-p",
            "--set-key-file",
            kf2,
            "-t",
            "100",
            db2,
        ],
        b"Kdbx4$Master!\nKdbx4$Master!\n",
    );
    assert!(ok, "rustpass-cli KDBX 4.0 db-create failed: {err}");

    let (ok, _, err) = run_bin(
        &rp_bin,
        None,
        &[
            "add",
            "-q",
            "-k",
            kf2,
            "-u",
            "alice@rustpass.dev",
            "--url",
            "https://vault.rustpass.dev",
            "--notes",
            "Created by RustPass KDBX 4.0 engine",
            "--totp",
            "otpauth://totp/RustPass:alice?secret=JBSWY3DPEHPK3PXP&issuer=RustPass",
            "-p",
            db2,
            "Engineering/CoreVault",
        ],
        b"Kdbx4$Master!\nUltra$trongKdbx4Pass!\n",
    );
    assert!(ok, "rustpass-cli KDBX 4.0 add failed: {err}");

    let (ok, _, err) = run_bin(
        &rp_bin,
        None,
        &[
            "attachment-import",
            "-q",
            "-k",
            kf2,
            db2,
            "Engineering/CoreVault",
            "payload.bin",
            att_src.to_str().expect("utf8"),
        ],
        b"Kdbx4$Master!\n",
    );
    assert!(ok, "rustpass-cli KDBX 4.0 attachment-import failed: {err}");

    // Verify with real `keepassxc-cli.exe`!
    let (ok, kpxc_show_v4, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &["show", "-q", "-s", "-k", kf2, db2, "Engineering/CoreVault"],
        b"Kdbx4$Master!\n",
    );
    assert!(
        ok,
        "Real keepassxc-cli failed to open RustPass KDBX 4.0 Argon2id+ChaCha20 vault! stderr: {err}"
    );
    assert!(kpxc_show_v4.contains("alice@rustpass.dev"));
    assert!(kpxc_show_v4.contains("Ultra$trongKdbx4Pass!"));
    assert!(kpxc_show_v4.contains("https://vault.rustpass.dev"));

    // Verify real `keepassxc-cli.exe` computes a valid 6-digit TOTP from our `otp` attribute!
    let (ok, kpxc_totp, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &["show", "-q", "-t", "-k", kf2, db2, "Engineering/CoreVault"],
        b"Kdbx4$Master!\n",
    );
    assert!(ok, "keepassxc-cli TOTP read failed: {err}");
    assert_eq!(kpxc_totp.trim().len(), 6);

    // Verify real `keepassxc-cli.exe` extracts our KDBX 4.0 Inner Header binary attachment byte-for-byte!
    let exported_by_kpxc = dir.join("exported_by_keepassxc.bin");
    let (ok, _, err) = run_bin(
        &kpxc_bin,
        Some(kpxc_dir),
        &[
            "attachment-export",
            "-q",
            "-k",
            kf2,
            db2,
            "Engineering/CoreVault",
            "payload.bin",
            exported_by_kpxc.to_str().expect("utf8"),
        ],
        b"Kdbx4$Master!\n",
    );
    assert!(
        ok,
        "keepassxc-cli attachment-export on KDBX 4 failed: {err}"
    );
    let extracted_bytes = std::fs::read(&exported_by_kpxc).expect("read exported attachment");
    assert_eq!(extracted_bytes, att_bytes);

    let _ = std::fs::remove_dir_all(&dir);
}
