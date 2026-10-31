<div align="center">

<img src="assets/banner.png" alt="RustPass Header Banner" width="100%" />

# RustPass

### Clean-Room, Memory-Safe KeePassXC Password Manager Suite in Pure Rust

[![Rust Edition](https://img.shields.io/badge/Rust-2024%20Edition-DEA584?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)
[![KeePassXC Compatibility](https://img.shields.io/badge/KDBX-v4.1%20%7C%20v3.1%20Interop-10B981?style=for-the-badge&logo=keepassxc&logoColor=white)](https://keepassxc.org/)
[![Clippy](https://img.shields.io/badge/Clippy-0%20Warnings-brightgreen?style=for-the-badge&logo=rust)](https://github.com/rust-lang/rust-clippy)
[![Tests Passing](https://img.shields.io/badge/Tests-23%2F23%20Passed-success?style=for-the-badge&logo=checkmarx&logoColor=white)](cargo-test)
[![Memory Safety](https://img.shields.io/badge/Memory-Zeroize%20Protected-orange?style=for-the-badge&logo=shield&logoColor=white)](https://crates.io/crates/zeroize)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational?style=for-the-badge)](https://github.com/laurentvv/RustPass)

<p align="center">
  <b>A modern, high-performance, and memory-safe reimplementation of the KeePassXC v2.8.0 password manager ecosystem.</b><br>
  Built from clean-room specifications in pure Rust with hardware-accelerated cryptography, zero plaintext secret leakage, and bidirectional binary compatibility with official KeePassXC databases.
</p>

[Key Features](#key-features) •
[Screenshots](#interface-showcase) •
[Architecture](#cryptography--security-architecture) •
[Installation](#installation--build) •
[CLI Quickstart](#cli-cheatsheet-rustpass-cli) •
[Browser Extension](#browser-integration-rustpass-proxy) •
[Verification](#verification--interoperability) •
[License](#license)

</div>

---

## Overview

**RustPass** is an independent, clean-room implementation of the KeePass password management suite, written in pure Rust (2024 Edition). It delivers a seamless, drop-in alternative to KeePassXC with native GPU-accelerated desktop rendering, an exhaustive 25-subcommand CLI, and a high-throughput browser native messaging proxy.

### Why RustPass?

- 🛡️ **Zero Master Secret Leaks:** Master keys, intermediate KDF states, composite credentials, and decrypted secrets are wrapped in `zeroize::Zeroizing` buffers that are securely scrubbed from memory immediately upon drop or database locking.
- ⚡ **Native GPU Desktop GUI:** Powered by `egui` and `eframe` 0.37 with instant keyboard-first workflows, sub-millisecond search queries, multi-vault tabs, live RFC 6238 TOTP clocks with inline scannable QR codes, and 7 themes (including automatic Windows/system theme matching).
- 🔄 **100% Binary Interoperability:** Tested directly against official `keepassxc-cli.exe` binaries for round-trip KDBX v4.1, v4.0, and v3.1 vaults.
- 💾 **Crash-Proof Atomic Saves:** Vault modifications are always written to isolated `.kdbx.tmp` files and atomically renamed over the target to prevent file corruption in case of power loss or disk failure.
- 🚀 **Zero C++ Legacy Debt:** No Qt/Botan/OpenSSL runtime bloat. Ships lean, self-contained single-file release binaries (1.5 MB – 11 MB) with Thin-LTO and stripped debug symbols.

---

## Interface Showcase

<div align="center">

### Main Vault Workspace (3-Pane Layout)
*Real-time group hierarchy, structured search grammar, entry details, live TOTP countdown, and scannable QR code preview.*

<img src="assets/screenshots/main_interface.png" alt="RustPass Main Vault Interface" width="92%" />

<br/><br/>

| **Comprehensive Entry Editor** | **CSPRNG & Diceware Generator** |
|:---:|:---:|
| <img src="assets/screenshots/entry_editor.png" alt="Entry Editor Modal" width="100%" /> | <img src="assets/screenshots/password_generator.png" alt="Password Generator Modal" width="100%" /> |
| *6 tabs: Entry, Advanced, TOTP, History, Auto-Type, Properties.* | *Configurable character sets, EFF Diceware passphrases, entropy meter.* |

<br/>

| **Security Health Audit** | **KDF & Security Settings** |
|:---:|:---:|
| <img src="assets/screenshots/security_audit.png" alt="Security Health Audit Modal" width="100%" /> | <img src="assets/screenshots/database_settings.png" alt="Database Security Settings Modal" width="100%" /> |
| *Calculates health score (0-100), scans weak, reused, or expired entries.* | *Configure Argon2id, Argon2d, AES-KDF, ChaCha20, or AES-256-CBC.* |

</div>

---

## Binaries Shipped

| Binary | Description | Upstream Counterpart |
| :--- | :--- | :--- |
| **`rustpass.exe`** | GPU-accelerated desktop password manager with multi-vault tabs and command palette (`Ctrl+Shift+P`). | `KeePassXC.exe` |
| **`rustpass-cli.exe`** | Comprehensive 25-subcommand scriptable CLI for automation, head-less servers, and terminal workflows. | `keepassxc-cli.exe` |
| **`rustpass-proxy.exe`** | High-throughput `u32 LE` JSON stdio Native Messaging host connecting KeePassXC-Browser extensions. | `keepassxc-proxy.exe` |

---

## Key Features

### 🔐 Cryptography & Vault Formats
- **Full KDBX v4.1, v4.0 & v3.1 Support:** Complete parser, serializer, and block stream validator.
- **Key Derivation Functions (KDF):**
  - **Argon2id & Argon2d** (configurable memory, iteration passes, and parallelism lanes).
  - Hardware-accelerated **AES-KDF** (KDBX 3.1 & 4.x compatibility).
- **Ciphers & Block Stream Integrity:**
  - **ChaCha20** (256-bit, RFC 8439) with HMAC-SHA-256 block stream authentication.
  - **AES-256-CBC** with PKCS#7 padding and HMAC-SHA-256 verification.
  - Inner stream protection using **ChaCha20** or **Salsa20** for memory-sensitive attributes and binary attachments.
- **Composite Key Credentials:**
  - Master Passwords.
  - XML v2.0 `.keyx` Key Files (with 4-byte SHA-256 integrity hash), XML v1.0, 64-hex strings, and 32-byte raw binary files.
  - Dual password + keyfile composite credentials.

### ⏱️ Two-Factor Authentication (TOTP & Steam Guard)
- **RFC 6238 & RFC 4226 Compliance:** HMAC-SHA1, HMAC-SHA256, and HMAC-SHA512 algorithms.
- **Custom Parameters:** 6 to 10 digits, custom time steps (10s, 30s, 60s), and counter-based HOTP.
- **Steam Guard Support:** Alphanumeric 5-character token generation.
- **Integrated QR Code Generator:** Pure-Rust ISO/IEC 18004 QR encoder rendering scannable `otpauth://` matrices in the GUI.

### 🛡️ Security Health Audit & Password Generation
- **Automated Vault Audit:** Evaluates password strength, flags reused/duplicate passwords, identifies expired or near-expiry credentials, detects insecure HTTP URLs, and alerts on entries lacking 2FA.
- **Dual Password Generators:**
  - **CSPRNG Generator:** Cryptographically secure unbiased rejection sampling with custom character sets (upper, lower, digits, special, extended, exclude lookalike characters).
  - **EFF Diceware Passphrases:** Wordlist-driven memorable passphrases with custom delimiters (`-`, `.`, `_`, space) and title casing.

### 💻 Desktop Experience & Ergonomics
- **Command Palette:** Instant quick navigation with `Ctrl+Shift+P` to switch groups, trigger audit, or generate credentials.
- **Structured Search Grammar:** Filter with syntax like `u:alice is:totp -g:Archive | t:GitHub`.
- **Auto-Type Integration:** Windows `SendInput` Unicode keystroke emulation (`Ctrl+V`).
- **Timed Clipboard Clearing:** Configurable clipboard clearing timer (default 10s) with active countdown.
- **Bilingual Interface:** Instant runtime switching between English and French (FR/EN).

---

## Cryptography & Security Architecture

```
[ Master Password ] + [ Key File (.keyx) ]
          │
          ▼
   [ Composite Key ] (zeroize::Zeroizing)
          │
          ▼
   [ KDF: Argon2id / Argon2d / AES-KDF ] ──► Derived Master Key
          │
          ▼
   [ Outer Cipher: ChaCha20 / AES-256-CBC ]
          │
          ▼
   [ HMAC-SHA-256 Block Stream ] ──► Authenticated Payload
          │
          ▼
   [ Inner Decrypted XML DOM ]
     ├─ Protected Attributes (<Value Protected="True">) ──► ChaCha20/Salsa20 Inner Stream
     ├─ Binary Attachments (Base64 / GZip / Raw) ────────► In-Memory Zeroized Decryption
     └─ Version History Snapshots ───────────────────────► Automatic Diff History
```

---

## Installation & Build

### Prerequisites
- **Rust:** Rust 1.85+ (Edition 2024 supported).
- **Cargo:** Bundled with Rust toolchain.
- **Platform:** Windows 10/11, Linux (X11/Wayland), macOS 12+.

### Build from Source

```bash
# Clone the repository
git clone https://github.com/laurentvv/RustPass.git
cd RustPass

# Run static analysis and clippy checks
cargo fmt --check
cargo clippy --all-targets -- -D warnings

# Execute test suite (23 unit and integration tests)
cargo test

# Build optimized release binaries
cargo build --release
```

Release binaries will be generated in `target/release/`:
- `rustpass.exe`
- `rustpass-cli.exe`
- `rustpass-proxy.exe`

---

## CLI Cheatsheet (`rustpass-cli`)

`rustpass-cli` provides 25 scriptable subcommands compatible with KeePassXC automation:

```powershell
# 1. Create a new KDBX v4.1 vault with Argon2id and a generated XML v2.0 keyfile
rustpass-cli db-create -p --set-key-file vault.keyx -t 500 vault.kdbx

# 2. Add an entry with custom URL, notes, and a generated 24-character password
rustpass-cli add -k vault.keyx -u alice --url https://github.com -g -L 24 vault.kdbx Development/GitHub

# 3. Add an entry with an RFC 6238 TOTP seed
rustpass-cli add -k vault.keyx -u bob --totp JBSWY3DPEHPK3PXP vault.kdbx Services/AWS

# 4. Show decrypted password or print the live 6-digit TOTP token
rustpass-cli show -s -k vault.keyx vault.kdbx Development/GitHub
rustpass-cli show -t -k vault.keyx vault.kdbx Services/AWS

# 5. Copy credentials directly to system clipboard
rustpass-cli clip -k vault.keyx vault.kdbx Development/GitHub

# 6. Generate Diceware passphrases (5 words, hyphen separator)
rustpass-cli diceware -W 5 -d "-"

# 7. Run a complete Security Health Audit on the vault
rustpass-cli analyze -k vault.keyx vault.kdbx

# 8. Merge two databases together
rustpass-cli merge --same-credentials -k vault.keyx target.kdbx source.kdbx

# 9. Export or import entries in CSV / XML formats
rustpass-cli export -k vault.keyx -f csv vault.kdbx backup.csv
rustpass-cli import -f csv backup.csv imported.kdbx
```

---

## Browser Integration (`rustpass-proxy`)

`rustpass-proxy` is a native messaging host communicating over standard input/output using length-prefixed `u32 LE` JSON packets:

1. **Manifest Installation:**
   Register the manifest in Windows Registry or Linux/macOS Application Support:
   - Key: `HKCU\Software\Google\Chrome\NativeMessagingHosts\org.keepassxc.keepassxc_browser`
2. **KeePassXC-Browser Extension:**
   Works seamlessly with the official KeePassXC-Browser extension on Chrome, Firefox, Brave, and Edge for auto-fill, credential fetching, and form submission.

---

## Verification & Interoperability

RustPass has been verified through a rigorous dual verification matrix:

- **Official KeePassXC Interoperability:**
  Cross-binary tests are executed against official `C:\Program Files\KeePassXC\keepassxc-cli.exe`. Databases created in RustPass decrypt identically in KeePassXC, and databases created in KeePassXC decrypt cleanly in RustPass without loss of history or attributes.
- **Automated GUI Test Suite:**
  7 comprehensive headless GUI workflow tests validate database creation, nested group tree mutations, 6-tab entry editor modifications, live TOTP ticks, Diceware generators, and session locking.
- **Zeroize Memory Verification:**
  Secret buffers implement `zeroize::ZeroizeOnDrop` ensuring deterministic memory erasure.

---

## Project Structure

```
RustPass/
├── assets/                  # Application icons, manifest, and screenshots
│   ├── banner.png           # Hero header illustration
│   ├── icon.ico             # Multi-resolution procedural icon (16-256px)
│   └── screenshots/         # Verified GUI interface captures
├── src/
│   ├── app.rs               # egui/eframe 0.37 desktop application loop
│   ├── audit.rs             # Security health audit scanner
│   ├── autotype.rs          # Unicode Auto-Type sequence parser
│   ├── cli.rs               # 25-subcommand CLI router & argument parsing
│   ├── crypto/              # Argon2id, AES, ChaCha20, and XML v2.0 KeyFiles
│   ├── generator.rs         # CSPRNG & EFF Diceware passphrase generators
│   ├── io.rs                # CSV & XML import/export engines
│   ├── kdbx/                # KDBX 3.1 & 4.1 parsers, serializers, and block streams
│   ├── proxy.rs             # Browser Native Messaging host
│   ├── search.rs            # Structured search query parser
│   ├── totp/                # RFC 6238 TOTP, Steam Guard & QR code encoder
│   └── ui/                  # 3-pane layout, modals, command palette, themes
└── tests/
    └── cli_integration.rs   # Cross-binary test against official KeePassXC
```

---

## License

This project is licensed under the **MIT License** — see the [LICENSE](LICENSE) file for details.

### Clean-Room Attestation
*RustPass is a clean-room implementation authored from public RFCs (`RFC 4226`, `RFC 6238`, `RFC 8439`, `RFC 4180`), official KeePass 2.x KDBX File Format specifications, and black-box behavioral testing. It contains no proprietary, decompiled, or non-permissive source code.*
