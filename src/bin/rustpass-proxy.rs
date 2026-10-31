//! `rustpass-proxy` — Chrome / Firefox / Edge Native Messaging host (`u32 LE` JSON framing).

use clap::Parser;
use rustpass::crypto::kdf::MasterCredentials;
use rustpass::model::Database;
use rustpass::proxy::{
    generate_chromium_native_manifest, handle_browser_message, read_native_message,
    write_native_message,
};
use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Debug, Parser)]
#[command(
    name = "rustpass-proxy",
    version,
    about = "KeePassXC-Browser compatible Native Messaging stdio host for RustPass"
)]
struct ProxyArgs {
    /// Print a ready-to-register Chrome/Edge Native Messaging host manifest JSON and exit.
    #[arg(long = "print-chromium-manifest")]
    print_chromium_manifest: bool,

    /// Optional `.kdbx` vault unlocked directly for standalone headless browser integration tests.
    #[arg(long = "database")]
    database: Option<PathBuf>,

    /// Optional key file for `--database`.
    #[arg(long = "key-file")]
    key_file: Option<PathBuf>,

    /// Browser extension origin argument passed automatically by Chrome/Edge/Firefox (ignored).
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    browser_args: Vec<String>,
}

fn main() -> ExitCode {
    let args = ProxyArgs::parse();
    let _ = &args.browser_args;

    if args.print_chromium_manifest {
        let exe = std::env::current_exe()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "rustpass-proxy.exe".to_string());
        println!("{}", generate_chromium_native_manifest(&exe));
        return ExitCode::SUCCESS;
    }

    let open_db = match args.database {
        Some(ref path) => {
            let pw = std::env::var("RUSTPASS_PROXY_PASSWORD").ok();
            match MasterCredentials::new(pw, args.key_file.as_deref())
                .and_then(|creds| Database::open(path, &creds))
            {
                Ok(db) => Some(db),
                Err(e) => {
                    eprintln!("rustpass-proxy failed to open vault: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        None => None,
    };

    let stdin = std::io::stdin();
    if stdin.is_terminal() {
        eprintln!(
            "rustpass-proxy {}: Native Messaging stdio host ready (pass --print-chromium-manifest for manifest JSON).",
            env!("CARGO_PKG_VERSION")
        );
        return ExitCode::SUCCESS;
    }

    let mut reader = stdin.lock();
    let mut writer = std::io::stdout().lock();

    loop {
        match read_native_message(&mut reader) {
            Ok(Some(msg)) => {
                let response = handle_browser_message(&msg, open_db.as_ref());
                if let Err(e) = write_native_message(&mut writer, &response) {
                    eprintln!("rustpass-proxy write error: {e}");
                    return ExitCode::FAILURE;
                }
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("rustpass-proxy frame error: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
