# RustPass

**Clean-room KDBX 4.0 & 3.1 Password Manager in Pure Rust — Desktop GUI (`egui`), Drop-in `keepassxc-cli` CLI, and Browser Native Messaging Proxy.**

`RustPass` is an independent, MIT-licensed clean-room reimplementation of the KeePassXC v2.8.0 password management suite, built on Rust Edition 2024 with audited `RustCrypto` primitives, `Zeroizing` memory hygiene, and bidirectional binary `.kdbx` compatibility verified directly against `keepassxc-cli.exe`.

---

## Binaries Shipped

| Binary | Role | Upstream Counterpart |
| :--- | :--- | :--- |
| `rustpass.exe` | Native GPU-accelerated 3-pane desktop password manager (`egui`/`eframe` 0.37) | `KeePassXC.exe` |
| `rustpass-cli.exe` | 25-subcommand scriptable vault CLI | `keepassxc-cli.exe` |
| `rustpass-proxy.exe` | Chrome / Firefox / Edge Native Messaging `u32 LE` JSON stdio host | `keepassxc-proxy.exe` |

---

## Key Capabilities

- **Full Binary KDBX 4.0/4.1 & KDBX 3.1 Interoperability**
  - **Key Derivation**: **Argon2id** & **Argon2d** (`VariantDictionary`) + hardware-accelerated **AES-KDF**
  - **Outer Ciphers**: **ChaCha20** (256-bit, RFC 8439) and **AES-256-CBC** (PKCS#7)
  - **Integrity**: Header SHA-256 + Header HMAC-SHA-256 + **HMAC-SHA-256 Block Stream** (KDBX 4) and SHA-256 Hashed Block Stream (KDBX 3.1)
  - **Inner Protection**: Stateful **ChaCha20** / **Salsa20** XOR stream protection for `<Value Protected="True">` secrets and KDBX 4 Inner Header binary attachments
  - **Composite Master Keys**: Master password + **Key Files** (`.keyx` XML v2.0 with 4-byte SHA-256 verification hash, XML v1.00, 64-hex, 32-byte raw, or SHA-256 file fallback)
- **Built-in 2FA / TOTP & QR Codes**
  - RFC 4226 / RFC 6238 (`HMAC-SHA1`, `HMAC-SHA256`, `HMAC-SHA512`, 6–10 digits, custom step) + **Steam Guard** 5-character tokens
  - Pure-Rust ISO/IEC 18004 QR Code encoder rendering scannable `otpauth://` codes directly in the Inspector and Entry Editor
- **CSPRNG & Diceware Generators + Vault Security Health Audit**
  - Unbiased rejection-sampled OS CSPRNG character generator & EFF Diceware passphrase generator
  - Security Health Score (`0..=100`), weak/reused/short/expired/HTTP/missing-2FA detection, and offline HaveIBeenPwned (`-H`) SHA-1 breach scanning
- **Desktop UX & Security Hygiene**
  - Multi-vault tabs, KeePassXC structured search grammar (`u:alice is:totp -g:Archive | t:GitHub`), Command Palette (`Ctrl+Shift+P`), Windows `SendInput` Unicode Auto-Type (`Ctrl+V`), **timed clipboard auto-clear**, idle auto-lock, 7 themes (including `Follow Windows Theme`), and bilingual **FR / EN** interface.

---

## Build & Verify

```powershell
# Generate multi-resolution procedural icon (assets/icon.ico)
cargo run --example gen_icon

# Static checks & full test suite (including live keepassxc-cli cross-binary tests)
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test

# Optimized release binaries (1.5–11.0 MB, LTO thin, symbols stripped)
cargo build --release
```

---

## CLI Quick Examples (`rustpass-cli`)

```powershell
# Create a KDBX 4.0 (Argon2id + ChaCha20) vault with a generated v2.0 .keyx file
rustpass-cli db-create -p --set-key-file vault.keyx -t 500 vault.kdbx

# Add an entry with TOTP and a generated 24-char password
rustpass-cli add -k vault.keyx -u alice --url https://github.com --totp JBSWY3DPEHPK3PXP -g -L 24 vault.kdbx Dev/GitHub

# Inspect cleartext credentials or print the live 6-digit TOTP code
rustpass-cli show -s -k vault.keyx vault.kdbx Dev/GitHub
rustpass-cli show -t -k vault.keyx vault.kdbx Dev/GitHub

# Run a vault Security Health Audit
rustpass-cli analyze -k vault.keyx vault.kdbx
```

---

## License

MIT — Clean-room implementation authored from public specifications (`KDBX 3.1/4.0`, `RFC 4226/6238`, `ISO/IEC 18004`, `RFC 4180`) and black-box behavioral observation. See [`PORTING.md`](PORTING.md) and [`docs/inventory.md`](docs/inventory.md).
