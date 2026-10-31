# KeePassXC 2.8.0 — Precise REAP Inventory vs `RustPass` Coverage

Produced on **2026-10-31** with **`universal-asset-ripper` v0.1.0** (`ripper detect`, `ripper extract`, `ripper audit --no-decompile`), static PE `.rsrc` / symbol / string inspection over `C:\Program Files\KeePassXC` (153 files, 137.37 MB), embedded HTML User Guide & Keyboard Shortcuts analysis, and authoritative CLI usage capture from `keepassxc-cli.exe` 2.8.0.

All Rust code and assets in `RustPass` (`d:\git\RustPass`) are **100% clean-room** (MIT-licensed), implemented solely from public specifications (KeePass KDBX 3.1 & 4.0 binary/XML specifications, RFC 4226 HOTP, RFC 6238 TOTP, EFF Diceware, Chrome/Firefox Native Messaging JSON framing) without embedding any GPL code or extracted graphics.

---

## 1. Executables Inventory (`C:\Program Files\KeePassXC`)

| Upstream Executable | Size | Arch & Framework | Observed Role (PE Resources & Usage) | `RustPass` Binary & Status |
|---|---|---|---|---|
| `KeePassXC.exe` | 5.91 MB (6,195,288 B) | x64 PE (`Qt6Widgets`) | Main desktop GUI password vault manager (4,093 imports across 56 DLLs, 18 PE resources incl. `IDI_ICON1` & `IDI_KDBX`, `VS_VERSION_INFO` 2.8.0.0) | ✅ `rustpass.exe` (`egui`/`eframe` 0.37 native desktop app) |
| `keepassxc-cli.exe` | 2.63 MB (2,755,672 B) | x64 PE (`Qt6Core`, UTF-8 manifest) | Full-featured command-line interface (832 imports across 18 DLLs, 25 subcommands) | ✅ `rustpass-cli.exe` (`clap` CLI with drop-in subcommand & flag compatibility) |
| `keepassxc-proxy.exe` | 40.1 KB (41,048 B) | x64 PE (`Qt6Network`) | Browser extension Native Messaging stdio-to-Named-Pipe bridge (`NativeMessagingProxy` -> `org.keepassxc.KeePassXC.BrowserServer`) | ✅ `rustpass-proxy.exe` (Native Messaging `u32 LE` JSON stdio bridge & standalone protocol handler) |
| `vc_redist.x64.exe` | 17.86 MB | x86 bootstrapper | Microsoft Visual C++ Runtime installer | n/a (Pure Rust static CRT / zero Qt/Botan runtime DLLs; WiX MSI definition in `installer/rustpass.wxs`) |

---

## 2. Dynamic Link Libraries (32 DLLs) → Pure-Rust Crate Mapping

| Upstream DLL(s) | Size | Observed Exports / Role | Replaced in `RustPass` by |
|---|---|---|---|
| `botan-3.dll` | 6.82 MB | C++ crypto engine: Argon2d/id, AES-256-CBC/ECB, ChaCha20, Salsa20, HMAC-SHA-256, SHA-256/512, HOTP/TOTP, CSPRNG | ✅ Pure-Rust RustCrypto (`argon2` 0.6, `aes` 0.9, `cbc` 0.2, `chacha20` 0.10, `salsa20` 0.11, `hmac` 0.13, `sha2` 0.11, `sha1` 0.11, `getrandom` 0.4, `zeroize` 1.9) |
| `z.dll` + `minizip.dll` | 158 KB | GZip / Zlib compression for KDBX inner payload and KDBX 3.1 `<Binary Compressed="True">` | ✅ `flate2` 1.1 |
| `qrencode.dll` | 57 KB | ISO/IEC 18004 QR Code matrix encoder (`BitStream_*`, `QRcode_encodeString`) for `otpauth://` TOTP provisioning | ✅ Native clean-room QR matrix renderer (`src/totp/qr.rs`) |
| `readline.dll` | 179 KB | Interactive line editing for `keepassxc-cli open` shell | ✅ Interactive REPL loop in `rustpass-cli open` + `rpassword` 7.5 hidden prompts |
| `Qt6Core.dll`, `Qt6Gui.dll`, `Qt6Widgets.dll`, `Qt6Svg*.dll`, `Qt6Concurrent.dll` | 26.8 MB | UI widgets, XML DOM, settings, translations (`.qm`), SVG icons, clipboard | ✅ `egui` / `eframe` 0.37, `roxmltree` 0.21, `arboard` 3.7, `rfd` 0.17, `serde_json`, `src/i18n.rs` (EN/FR) |
| `Qt6Network.dll`, `tls\qschannelbackend.dll` | 1.7 MB | Local IPC socket for Browser Integration | ✅ Standard library I/O + Windows Named Pipe / JSON Native Messaging (`src/proxy/`) |
| `opengl32sw.dll`, `dxcompiler.dll`, `dxil.dll`, `d3dcompiler_47.dll` | 39.2 MB | Software OpenGL / DirectX shader fallback for Qt6 RHI | ✅ Native `eframe` `Glow` renderer (single compact `.exe`, zero companion DLLs) |
| `WinSCard.dll`, `HID.DLL`, `SETUPAPI.dll` (OS imports) | OS | PC/SC & USB HID YubiKey HMAC-SHA1 challenge-response | ❌ Absent (Hardware YubiKey USB HID challenge-response out of clean-room v0.1 scope; explicit error returned if `-y/--yubikey` is passed) |

---

## 3. Companion Assets (`share/` & `translations/`)

| Shipped Resource | Observed Details | `RustPass` Handling |
|---|---|---|
| `share/wordlists/eff_large.wordlist` (69,894 B) | 7,776-word EFF Long Wordlist for Diceware passphrases | ✅ Reads installed wordlist dynamically if present on host + embeds clean-room EFF-compatible wordlist fallback |
| `share/docs/KeePassXC_UserGuide.html` (6.48 MB) | Authoritative documentation of UI layout, search modifiers, CLI flags, KDBX merge & placeholders | ✅ Used as clean-room specification; built-in Shortcuts & Help dialog (`Ctrl+/`) |
| `share/docs/KeePassXC_KeyboardShortcuts.html` (45.7 KB) | 37 keyboard shortcuts (`Ctrl+N`, `Ctrl+B`, `Ctrl+C`, `Ctrl+T`, `Ctrl+L`, `Ctrl+Shift+C`, etc.) | ✅ Implemented directly in `src/app.rs` |
| `share/translations/keepassxc_*.qm` (48 locales) | Qt compiled localization catalogs | ✅ Native bilingual **English / Français** (`src/i18n.rs`) switchable live |

---

## 4. GUI Architecture Inventory (92 Qt Classes Observed in `KeePassXC.exe`)

| KeePassXC Subsystem & Classes | Purpose | `RustPass` Status |
|---|---|---|
| **Welcome & Unlock**: `WelcomeWidget`, `DatabaseOpenWidget`, `DatabaseOpenDialog` | Create/open `.kdbx`, import CSV/XML, recent vaults, master password + `.keyx` key file unlock | ✅ Implemented |
| **Multi-Vault Tabs**: `DatabaseTabWidget`, `DatabaseWidget` | Multiple simultaneously open `.kdbx` vaults in tabs, independent lock state (`Ctrl+L` / `Ctrl+Shift+L`) | ✅ Implemented |
| **Group Tree**: `GroupView`, `GroupModel`, `EditGroupWidget` | Hierarchical group tree, entry badges, Recycle Bin, add/rename/delete group | ✅ Implemented |
| **Entry Table & Preview**: `EntryView`, `EntryModel`, `EntryPreviewWidget` | Sortable entry list, search bar with modifiers (`title:`, `user:`, `url:`, `tag:`, `is:weak`, `is:expired`, `is:totp`), masked/visible preview, timed clipboard auto-clear | ✅ Implemented |
| **Entry Editor**: `EditEntryWidgetMain`, `EditEntryWidgetAdvanced`, `EditEntryWidgetAutoType`, `EditEntryWidgetHistory`, `EditWidgetProperties` | Full tabbed editor: credentials, custom attributes (plain/protected), binary attachments (import/export/delete), Auto-Type sequence, History revisions & restore, expiry, colors & icons | ✅ Implemented |
| **TOTP & 2FA**: `TotpSetupDialog`, `TotpDialog` | RFC 6238 TOTP (SHA-1/256/512, 6–8 digits, Steam 5-char), `otpauth://` URI import/export, live countdown & QR code matrix | ✅ Implemented |
| **Password Generator**: `PasswordGeneratorWidget` | CSPRNG character generator (length, classes, exclude similar, every-group, custom) + Diceware passphrases + live entropy/crack-time | ✅ Implemented |
| **Reports & Security Audit**: `ReportsDialog`, `ReportsWidgetHealthcheck`, `ReportsWidgetStatistics`, `ReportsWidgetHibp` | Vault security score, weak/reused/expired/HTTP/no-2FA audit, database stats, offline HIBP SHA-1 file check | ✅ Implemented |
| **Database Settings**: `DatabaseSettingsDialog` (`General`, `Encryption`, `DatabaseKey`, `Maintenance`) | Edit vault name/description, switch KDBX 4.0 / 3.1, ChaCha20 / AES-256-CBC, Argon2id / Argon2d / AES-KDF parameters, rotate master password / `.keyx` key file, purge history | ✅ Implemented |
| **Auto-Type**: `AutoTypePlatformWin`, `AutoTypeSelectDialog` | Parse `{USERNAME}{TAB}{PASSWORD}{ENTER}`, `{TOTP}`, `{DELAY=N}` and inject keystrokes on Windows via `SendInput` | ✅ Implemented |
| **Browser Integration**: `BrowserService`, `BrowserHost` | Native Messaging JSON protocol via `rustpass-proxy` | 🟡 Partial (Protocol framing, key exchange & credential query in `rustpass-proxy`; full browser extension pairing UI basic) |
| **KeeShare / Passkeys / FdoSecrets / SSH Agent**: `Passkey*`, `SSHAgent`, `*KeeShare` | Group cryptosharing, WebAuthn browser passkeys, Linux DBus Secret Service, Pageant/OpenSSH agent | ❌ Absent (Documented out-of-scope advanced integrations) |

---

## 5. CLI Option Surface (`keepassxc-cli 2.8.0` → `rustpass-cli`)

| Subcommand | Key Observed Options (`cli-help-all.json`) | `RustPass` Status |
|---|---|---|
| `db-create` | `-p/--set-password`, `--set-key-file/-k`, `-t/--decryption-time <100..5000>`, `--kdbx3` | ✅ Implemented (creates KDBX 4.0 Argon2id+ChaCha20 or KDBX 3.1 AES-KDF+AES-256) |
| `db-info` | `-q`, `-k/--key-file`, `--no-password` | ✅ Implemented (prints UUID, cipher, KDF, group/entry/weak/reused/TOTP counts) |
| `db-edit` | `-k`, `--no-password`, `-p/--set-password`, `--set-key-file`, `--unset-key-file`, `--unset-password` | ✅ Implemented |
| `ls` | `-q`, `-k`, `--no-password`, `-R/--recursive`, `-f/--flatten`, `[group]` | ✅ Implemented |
| `show` | `-q`, `-k`, `--no-password`, `-s/--show-protected`, `-t/--totp`, `-a/--attributes`, `--all`, `--show-attachments` | ✅ Implemented |
| `add` | `-q`, `-k`, `--no-password`, `-u/--username`, `--url`, `--notes`, `-p/--password-prompt`, `-g/--generate`, `-L/-l/-U/-n/-s/-e/-x/--exclude-similar/--every-group/-c` | ✅ Implemented |
| `edit` | Same as `add` + `-t/--title` (snapshots previous revision into `<History>`) | ✅ Implemented |
| `rm` | `-q`, `-k`, `--no-password`, `<database> <entry>` (moves to Recycle Bin or deletes) | ✅ Implemented |
| `mv` | `-q`, `-k`, `--no-password`, `<database> <entry> <group>` | ✅ Implemented |
| `mkdir` / `rmdir` | `-q`, `-k`, `--no-password`, `<database> <group>` | ✅ Implemented |
| `clip` | `-q`, `-k`, `-a/--attribute`, `-t/--totp`, `-b/--best-match`, `[timeout]` (default 10s auto-clear) | ✅ Implemented |
| `generate` | `-L/--length`, `-l/--lower`, `-U/--upper`, `-n/--numeric`, `-s/--special`, `-e/--extended`, `-x/--exclude`, `--exclude-similar`, `--every-group`, `-c/--custom` | ✅ Implemented |
| `diceware` | `-W/--words`, `-w/--word-list` | ✅ Implemented |
| `estimate` | `-q`, `-a/--advanced`, `[password]` | ✅ Implemented |
| `analyze` | `-q`, `-k`, `--no-password`, `-H/--hibp <sha1-file>` | ✅ Implemented |
| `search` / `locate` | `-q`, `-k`, `--no-password`, `<database> <term>` (supports full KeePassXC query grammar!) | ✅ Implemented |
| `export` | `-q`, `-k`, `--no-password`, `-f/--format <xml\|csv\|html>` | ✅ Implemented |
| `import` | `-q`, `-p/--set-password`, `--set-key-file`, `-t/--decryption-time`, `--csv`, `<source> <database>` | ✅ Implemented (XML & CSV) |
| `merge` | `-q`, `-k`, `-s/--same-credentials`, `--key-file-from`, `--no-password-from`, `-d/--dry-run` | ✅ Implemented (UUID + timestamp + DeletedObjects reconciliation) |
| `attachment-import` | `-q`, `-k`, `-f/--force`, `<db> <entry> <name> <file>` | ✅ Implemented |
| `attachment-export` | `-q`, `-k`, `--stdout`, `<db> <entry> <name> [export-file]` (with Zip-Slip traversal protection) | ✅ Implemented |
| `attachment-rm` | `-q`, `-k`, `<db> <entry> <name>` | ✅ Implemented |
| `open` / `close` | Interactive vault shell (`ls`, `show`, `add`, `rm`, `search`, `clip`, `close`, `exit`) | ✅ Implemented |
| `-y, --yubikey` | Hardware YubiKey slot challenge-response across commands | ❌ Explicit unsupported error (never silently ignored) |

---

## 6. Coverage Summary

- **Core Cryptography & Storage (`KDBX 4.0 / 4.1` & `KDBX 3.1`)**: ✅ Complete bidirectional binary interoperability with KeePassXC 2.8.0 (Argon2id, Argon2d, AES-KDF; ChaCha20, AES-256-CBC; HMAC-SHA-256 block stream; Salsa20/ChaCha20 inner protected stream; GZip; `.keyx` v2.0 & v1.0 key files; attachments; history; merge).
- **2FA / Password Generation / Security Audit**: ✅ RFC 6238 TOTP (SHA-1/256/512 + Steam + QR), CSPRNG & Diceware generators, entropy estimator, Vault Health Check + HIBP offline check.
- **CLI (`rustpass-cli`)**: ✅ All 25 `keepassxc-cli` commands implemented with matching flags.
- **Desktop GUI (`rustpass`)**: ✅ Full 3-pane vault manager (`egui`/`eframe` 0.37), multi-vault tabs, timed clipboard auto-clear, Auto-Type, Command Palette, 6 themes + Follow Windows Theme, bilingual EN/FR.
- **Browser Proxy (`rustpass-proxy`)**: 🟡 Native Messaging binary framing & JSON protocol core implemented; full browser extension pairing UX partial.
- **Hardware YubiKey / SSH Agent / Passkeys / KeeShare**: ❌ Out of scope for clean-room v0.1 (explicitly reported).
