//! `clap` command-line argument definitions for `rustpass` (GUI) and `rustpass-cli` (25 subcommands
//! drop-in compatible with `keepassxc-cli`).

use crate::generator::PasswordGeneratorOptions;
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// Desktop GUI command-line options (`rustpass.exe`), compatible with `KeePassXC.exe` flags.
#[derive(Debug, Default, Parser)]
#[command(
    name = "rustpass",
    version,
    about = "Clean-room KDBX 4.0 & 3.1 desktop password manager in pure Rust"
)]
pub struct GuiCliArgs {
    /// Optional `.kdbx` vault file to pre-select or unlock on launch.
    pub database: Option<PathBuf>,

    /// Path to a key file (`.keyx` / `.key`) used to unlock `database`.
    #[arg(long = "keyfile", short = 'k')]
    pub keyfile: Option<PathBuf>,

    /// Read the master password from `stdin` on startup (for scripted / headless smoke checks).
    #[arg(long = "pw-stdin")]
    pub pw_stdin: bool,

    /// Optional custom configuration file path.
    #[arg(long = "config")]
    pub config: Option<PathBuf>,

    /// Open directly with the interactive KDBX 4.0 Showcase Vault loaded.
    #[arg(long = "showcase")]
    pub showcase: bool,

    /// Optional modal to open immediately on launch (`generator`, `audit`, `editor`, `shortcuts`, `settings`, `palette`).
    #[arg(long = "open-modal")]
    pub open_modal: Option<String>,
}

/// Drop-in `keepassxc-cli` compatible command-line tool (`rustpass-cli.exe`).
#[derive(Debug, Parser)]
#[command(
    name = "rustpass-cli",
    version,
    about = "Drop-in keepassxc-cli compatible KDBX 4.0 & 3.1 command-line vault manager"
)]
pub struct CliRoot {
    /// Subcommand to execute.
    #[command(subcommand)]
    pub command: CliCommand,
}

/// Common database unlock flags shared across vault-reading subcommands.
#[derive(Debug, Clone, Args)]
pub struct VaultOpenArgs {
    /// Silence password prompts and secondary informational messages.
    #[arg(short = 'q', long = "quiet")]
    pub quiet: bool,

    /// Key file of the database (`.keyx`, `.key`, or raw file).
    #[arg(short = 'k', long = "key-file")]
    pub key_file: Option<PathBuf>,

    /// Open the database without a master password (key file only).
    #[arg(long = "no-password")]
    pub no_password: bool,

    /// Hardware YubiKey challenge-response slot (explicitly unsupported in clean-room build).
    #[arg(short = 'y', long = "yubikey")]
    pub yubikey: Option<String>,
}

/// Shared generator flags for `generate`, `add -g`, and `edit -g`.
#[derive(Debug, Clone, Args)]
pub struct GeneratorFlags {
    /// Length of the generated password (default: 20).
    #[arg(short = 'L', long = "length", default_value_t = 20)]
    pub length: usize,

    /// Include lowercase ASCII letters (`a-z`).
    #[arg(short = 'l', long = "lower")]
    pub lower: bool,

    /// Include uppercase ASCII letters (`A-Z`).
    #[arg(short = 'U', long = "upper")]
    pub upper: bool,

    /// Include ASCII digits (`0-9`).
    #[arg(short = 'n', long = "numeric")]
    pub numeric: bool,

    /// Include special symbols.
    #[arg(short = 's', long = "special")]
    pub special: bool,

    /// Include extended Latin-1 characters.
    #[arg(short = 'e', long = "extended")]
    pub extended: bool,

    /// Characters to exclude from generation.
    #[arg(short = 'x', long = "exclude", default_value = "")]
    pub exclude: String,

    /// Exclude visually ambiguous look-alike characters (`Il1O0o...`).
    #[arg(long = "exclude-similar")]
    pub exclude_similar: bool,

    /// Ensure at least one character from every active character class.
    #[arg(long = "every-group")]
    pub every_group: bool,

    /// Additional or custom character pool.
    #[arg(short = 'c', long = "custom", default_value = "")]
    pub custom: String,
}

impl GeneratorFlags {
    /// Converts CLI generator flags into `PasswordGeneratorOptions` (when none of `-l/-U/-n/-s/-e/-c`
    /// are passed, KeePassXC enables `lower + upper + numeric` by default, or all standard sets).
    #[must_use]
    pub fn into_options(self) -> PasswordGeneratorOptions {
        let explicit_any = self.lower
            || self.upper
            || self.numeric
            || self.special
            || self.extended
            || !self.custom.is_empty();
        PasswordGeneratorOptions {
            length: self.length,
            lowercase: if explicit_any { self.lower } else { true },
            uppercase: if explicit_any { self.upper } else { true },
            numbers: if explicit_any { self.numeric } else { true },
            special: if explicit_any { self.special } else { false },
            extended_ascii: self.extended,
            exclude_similar: self.exclude_similar,
            ensure_every_group: self.every_group,
            exclude_chars: self.exclude,
            custom_chars: self.custom,
        }
    }
}

/// All 25 `keepassxc-cli` compatible subcommands.
#[derive(Debug, Subcommand)]
pub enum CliCommand {
    /// Add a new entry to a database.
    #[command(name = "add")]
    Add {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Username for the entry.
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        /// URL for the entry.
        #[arg(long = "url")]
        url: Option<String>,
        /// Notes for the entry.
        #[arg(long = "notes")]
        notes: Option<String>,
        /// Optional `otpauth://` URI or Base32 TOTP secret.
        #[arg(long = "totp")]
        totp: Option<String>,
        /// Prompt for the entry's password on stdin/TTY.
        #[arg(short = 'p', long = "password-prompt")]
        password_prompt: bool,
        /// Generate a random password for the entry.
        #[arg(short = 'g', long = "generate")]
        generate: bool,
        #[command(flatten)]
        gen_flags: GeneratorFlags,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path inside the vault (e.g. `Infra/GitLab`).
        entry: String,
    },

    /// Analyze password health and weaknesses across a database.
    #[command(name = "analyze")]
    Analyze {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to an offline HaveIBeenPwned SHA-1 hash file.
        #[arg(short = 'H', long = "hibp")]
        hibp: Option<PathBuf>,
        /// Optional okon-cli path (compatibility flag).
        #[arg(long = "okon")]
        okon: Option<PathBuf>,
        /// Path to the `.kdbx` database.
        database: PathBuf,
    },

    /// Export an attachment from an entry.
    #[command(name = "attachment-export")]
    AttachmentExport {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Write raw attachment bytes to stdout instead of a file.
        #[arg(long = "stdout")]
        stdout: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
        /// Attachment name on the entry.
        attachment_name: String,
        /// Output file path (optional when `--stdout` is set).
        export_file: Option<PathBuf>,
    },

    /// Import a binary file attachment into an entry.
    #[command(name = "attachment-import")]
    AttachmentImport {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Overwrite existing attachment of the same name.
        #[arg(short = 'f', long = "force")]
        force: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
        /// Attachment display name to store inside the entry.
        attachment_name: String,
        /// Source file on disk to embed.
        import_file: PathBuf,
    },

    /// Remove an attachment from an entry.
    #[command(name = "attachment-rm")]
    AttachmentRm {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
        /// Attachment name to remove.
        name: String,
    },

    /// Copy an entry attribute (password or TOTP) to the system clipboard.
    #[command(name = "clip")]
    Clip {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Attribute to copy (`password`, `username`, `url`, `notes`, `totp`, or custom key).
        #[arg(short = 'a', long = "attribute", default_value = "password")]
        attribute: String,
        /// Copy the current TOTP code.
        #[arg(short = 't', long = "totp")]
        totp: bool,
        /// Require a single best-matching entry.
        #[arg(short = 'b', long = "best-match")]
        best_match: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or search term.
        entry: String,
        /// Seconds before clearing clipboard (`0` = do not wait/clear; default `0` in non-interactive CLI).
        timeout: Option<u64>,
    },

    /// Close interactive session (`open` shell helper).
    #[command(name = "close")]
    Close,

    /// Create a new encrypted KDBX database.
    #[command(name = "db-create")]
    DbCreate {
        /// Silence prompts and secondary messages.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Set (and generate if missing) a key file for the new database.
        #[arg(long = "set-key-file")]
        set_key_file: Option<PathBuf>,
        /// Deprecated alias for `--set-key-file`.
        #[arg(short = 'k')]
        legacy_key_file: Option<PathBuf>,
        /// Prompt for a master password on stdin/TTY.
        #[arg(short = 'p', long = "set-password")]
        set_password: bool,
        /// Target Argon2id decryption time in milliseconds (`100..=5000`).
        #[arg(short = 't', long = "decryption-time")]
        decryption_time: Option<u64>,
        /// Create a legacy KDBX 3.1 vault (AES-KDF + AES-256-CBC) instead of KDBX 4.0.
        #[arg(long = "kdbx3")]
        kdbx3: bool,
        /// Output `.kdbx` path.
        database: PathBuf,
    },

    /// Change master credentials (password and/or key file) of an existing database.
    #[command(name = "db-edit")]
    DbEdit {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Set a new key file path (generating a v2.0 `.keyx` if the file does not yet exist).
        #[arg(long = "set-key-file")]
        set_key_file: Option<PathBuf>,
        /// Prompt for a new master password.
        #[arg(short = 'p', long = "set-password")]
        set_password: bool,
        /// Remove key file requirement.
        #[arg(long = "unset-key-file")]
        unset_key_file: bool,
        /// Remove master password requirement (requires an active key file).
        #[arg(long = "unset-password")]
        unset_password: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
    },

    /// Display cryptographic parameters and statistics of a database.
    #[command(name = "db-info")]
    DbInfo {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
    },

    /// Generate a random Diceware passphrase.
    #[command(name = "diceware")]
    Diceware {
        /// Silence secondary outputs.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Number of words in the passphrase (default: 6).
        #[arg(short = 'W', long = "words", default_value_t = 6)]
        words: usize,
        /// Optional custom wordlist path.
        #[arg(short = 'w', long = "word-list")]
        word_list: Option<PathBuf>,
    },

    /// Edit an existing entry in a database.
    #[command(name = "edit")]
    Edit {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// New username.
        #[arg(short = 'u', long = "username")]
        username: Option<String>,
        /// New URL.
        #[arg(long = "url")]
        url: Option<String>,
        /// New notes.
        #[arg(long = "notes")]
        notes: Option<String>,
        /// New title.
        #[arg(short = 't', long = "title")]
        title: Option<String>,
        /// New `otpauth://` URI or Base32 TOTP secret.
        #[arg(long = "totp")]
        totp: Option<String>,
        /// Prompt for a new entry password.
        #[arg(short = 'p', long = "password-prompt")]
        password_prompt: bool,
        /// Generate a new random password for the entry.
        #[arg(short = 'g', long = "generate")]
        generate: bool,
        #[command(flatten)]
        gen_flags: GeneratorFlags,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
    },

    /// Estimate the entropy and strength of a password.
    #[command(name = "estimate")]
    Estimate {
        /// Silence secondary outputs.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Show detailed pattern warnings and crack-time estimate.
        #[arg(short = 'a', long = "advanced")]
        advanced: bool,
        /// Password to evaluate (prompted if omitted).
        password: Option<String>,
    },

    /// Export database contents to stdout as `xml`, `csv`, or `html`.
    #[command(name = "export")]
    Export {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Output format (`xml`, `csv`, or `html`).
        #[arg(short = 'f', long = "format", default_value = "xml")]
        format: String,
        /// Path to the `.kdbx` database.
        database: PathBuf,
    },

    /// Generate a cryptographically random character password.
    #[command(name = "generate")]
    Generate {
        /// Silence secondary outputs.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        #[command(flatten)]
        gen_flags: GeneratorFlags,
    },

    /// Import an unencrypted KeePass 2.x XML (or CSV) file into a new encrypted `.kdbx` database.
    #[command(name = "import")]
    Import {
        /// Silence secondary outputs.
        #[arg(short = 'q', long = "quiet")]
        quiet: bool,
        /// Set key file for the created database.
        #[arg(long = "set-key-file")]
        set_key_file: Option<PathBuf>,
        /// Legacy alias for `--set-key-file`.
        #[arg(short = 'k')]
        legacy_key_file: Option<PathBuf>,
        /// Prompt for a master password.
        #[arg(short = 'p', long = "set-password")]
        set_password: bool,
        /// Target decryption time in milliseconds (`100..=5000`).
        #[arg(short = 't', long = "decryption-time")]
        decryption_time: Option<u64>,
        /// Source `.xml` (or `.csv`) file.
        xml: PathBuf,
        /// Target new `.kdbx` file.
        database: PathBuf,
    },

    /// List groups and entries inside a database.
    #[command(name = "ls")]
    Ls {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Recursively list sub-groups and entries.
        #[arg(short = 'R', long = "recursive")]
        recursive: bool,
        /// Flatten output to full paths on single lines.
        #[arg(short = 'f', long = "flatten")]
        flatten: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Optional group path (defaults to `/`).
        group: Option<String>,
    },

    /// Merge entries and groups from `database2` into `database`.
    #[command(name = "merge")]
    Merge {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Reuse identical credentials for `database2`.
        #[arg(short = 's', long = "same-credentials")]
        same_credentials: bool,
        /// Key file for `database2`.
        #[arg(long = "key-file-from")]
        key_file_from: Option<PathBuf>,
        /// Open `database2` without a password.
        #[arg(long = "no-password-from")]
        no_password_from: bool,
        /// Only report detected changes without modifying `database`.
        #[arg(short = 'd', long = "dry-run")]
        dry_run: bool,
        /// Unsupported YubiKey slot for `database2`.
        #[arg(long = "yubikey-from")]
        yubikey_from: Option<String>,
        /// Destination `.kdbx` database.
        database: PathBuf,
        /// Source `.kdbx` database to merge from.
        database2: PathBuf,
    },

    /// Create a new group (and missing parent groups) inside a database.
    #[command(name = "mkdir")]
    Mkdir {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Group path to create.
        group: String,
    },

    /// Move an entry to another group.
    #[command(name = "mv")]
    Mv {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Source entry path.
        entry: String,
        /// Destination group path.
        group: String,
    },

    /// Open an interactive REPL shell over an unlocked database.
    #[command(name = "open")]
    Open {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
    },

    /// Remove an entry from a database.
    #[command(name = "rm")]
    Rm {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
    },

    /// Remove a group from a database.
    #[command(name = "rmdir")]
    Rmdir {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Group path to remove.
        group: String,
    },

    /// Search entries using KeePassXC query syntax (`locate` alias supported).
    #[command(name = "search", visible_alias = "locate")]
    Search {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Search query term.
        term: String,
    },

    /// Display attributes, protected secrets, TOTP code, or attachments of an entry.
    #[command(name = "show")]
    Show {
        #[command(flatten)]
        open: VaultOpenArgs,
        /// Show the entry's current TOTP code.
        #[arg(short = 't', long = "totp")]
        totp: bool,
        /// Attribute name(s) to output one-per-line.
        #[arg(short = 'a', long = "attributes")]
        attributes: Vec<String>,
        /// Reveal protected values (e.g. Password) in cleartext.
        #[arg(short = 's', long = "show-protected")]
        show_protected: bool,
        /// Show all standard and custom attributes.
        #[arg(long = "all")]
        all: bool,
        /// List binary attachments on the entry.
        #[arg(long = "show-attachments")]
        show_attachments: bool,
        /// Path to the `.kdbx` database.
        database: PathBuf,
        /// Entry path or UUID.
        entry: String,
    },
}
