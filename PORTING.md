# Clean-Room Porting Notes — KeePassXC 2.8.0 → `RustPass`

## 1. Clean-Room Methodology

`RustPass` was engineered via the **REAP (`universal-asset-ripper` + `clean-room-port`)** black-box reconnaissance workflow against an installed Windows x86_64 binary distribution of **KeePassXC 2.8.0** (`C:\Program Files\KeePassXC`).

1. **Zero Upstream Source Inspection**: No GPLv2/GPLv3 C++ source files from KeePassXC were read, translated, or copied, and no icons, translations (`.qm`), or UI assets from `C:\Program Files\KeePassXC` are embedded in this repository.
2. **Public Format & Cryptographic Specifications**:
   - KeePass KDBX 3.1 & KDBX 4.0/4.1 binary container specification (magic signature `0x9AA2D903 0xB54BFB67`, outer TLV headers, `VariantDictionary`, SHA-256 + HMAC-SHA-256 header authentication, 64-byte per-block derived HMAC-SHA-256 block stream, GZip inner header + `KeePassFile` XML schema, Base64 `i64 LE` timestamps from `0001-01-01T00:00:00Z`).
   - Key File v2.0 `.keyx` XML schema (`SHA-256(key)[0..4]` uppercase hex `Hash` attribute) and v1.00 / hex / raw / SHA-256 keyfile derivation.
   - IETF RFC 4226 (HOTP), RFC 6238 (TOTP), RFC 8439 (ChaCha20), RFC 9106 (Argon2), RFC 4180 (CSV), and ISO/IEC 18004 (QR Code Byte mode + GF(256) Reed-Solomon ECC).
3. **Black-Box Surface Verification**:
   - All 25 subcommands of `keepassxc-cli.exe` were inventoried via `--help` output and cross-tested via `tests/cli_integration.rs` in both directions (`keepassxc-cli` → `rustpass-cli` and `rustpass-cli` → `keepassxc-cli`).

---

## 2. Architectural Mapping (C++17 / Qt6 / Botan3 → Safe Rust 2024)

| KeePassXC Subsystem | Upstream Stack | `RustPass` Clean-Room Module |
| :--- | :--- | :--- |
| Container & XML | QtXml + `z.dll` + `botan-3.dll` | `src/kdbx/{header,variant_dict,xml,mod}.rs` (`roxmltree` + `flate2`) |
| Cryptography & KDF | `botan-3.dll` (C++) | `src/crypto/{kdf,cipher,hmac_stream,keyfile}.rs` (`argon2`, `chacha20`, `aes`, `cbc`, `salsa20`, `hmac`, `sha2`, `zeroize`) |
| 2FA & QR Rendering | `Totp` + `qrencode.dll` (C) | `src/totp/{mod,qr}.rs` (pure-Rust RFC 6238 + Steam + ISO/IEC 18004 QR) |
| Password / Passphrase | `PasswordGenerator` + `Diceware` | `src/generator/{mod,wordlist}.rs` (rejection-sampled OS CSPRNG) |
| Search & Health Reports | `SearchParser` + `PasswordHealth` | `src/search/mod.rs` & `src/health/mod.rs` (incl. offline HIBP SHA-1 scan) |
| Auto-Type | `AutoTypeWindows` (`user32.dll`) | `src/autotype/mod.rs` (`windows-sys` Unicode `SendInput`) |
| Desktop UI | `Qt6Widgets.dll` (~45 MB runtime) | `src/app.rs` + `src/ui/*` (`egui`/`eframe` 0.37 single self-contained `.exe`) |
| CLI & Browser Host | `keepassxc-cli.exe`, `keepassxc-proxy.exe` | `src/bin/rustpass-cli.rs`, `src/bin/rustpass-proxy.rs` |

---

## 3. Intentional Scope Exclusions

To keep `RustPass` self-contained, auditable, and free of hardware/driver dependencies, the following hardware/network integrations are explicitly out of scope and report `UnsupportedFeature` when requested:

- **Hardware YubiKey USB HID Challenge-Response (`-y / --yubikey`)**: Requires `libyubikey` / Windows USB HID smartcard drivers; `.keyx` 256-bit key files are supported instead.
- **KeeShare Signed Container Sync & Freedesktop Secret Service (`org.freedesktop.secrets`)**: Linux D-Bus specific or multi-user PKI sharing workflows; standard UUID+timestamp KDBX `merge` is supported in both GUI and CLI.
- **Built-in SSH Agent (`Pageant` / Named Pipe)**: Dedicated SSH key management lives in sibling repository `cuty-ssh`; SSH keys can be stored as protected KDBX 4 Inner Header binary attachments.

## 4. Hardening Deviations & Rationale (2026-11 review sprint)

The full code review of 2026-11 introduced deliberate behavior deviations from KeePassXC,
each with a security or data-integrity rationale:

- **Unauthenticated KDF parameters are range-checked on read** (`P ≤ 64`, `8 KiB ≤ M ≤ 2 GiB`,
  `I ≤ 10M`, AES-KDF `1 ≤ R ≤ 100M`, Argon2 `V ∈ {0x10, 0x13}`): hostile KDBX headers can no
  longer trigger an out-of-memory abort or an unbounded derivation loop before the header HMAC
  is verified. Out-of-range values error with `CorruptedFormat` instead of a misleading
  "wrong password". The same bounds apply to KDBX 3.1 `TransformRounds`.
- **XML serialization drops characters forbidden by XML 1.0** (C0 controls except tab/LF/CR,
  `U+FFFE`/`U+FFFF`): writing them verbatim produced vaults no XML parser (ours, KeePassXC,
  KeePass) could reopen — silent self-inflicted corruption. KeePassXC sanitizes similarly.
- **GZip decompression is capped at 1 GiB** to block decompression bombs from shared vaults.
- **Malformed UUIDs and timestamps are hard errors.** KeePassXC also errors; the previous
  behavior (random UUID / `Utc::now()` on every open) churned entry identity and could flip
  expiry semantics. An *empty* UUID is still the KeePass "none" (nil) UUID; an *empty*
  timestamp is the deterministic epoch, never `now()`.
- **KDBX 3.1 files missing `ProtectedStreamKey` are rejected**: "decrypting" with an empty
  key silently produced mojibake protected values.
- **`save_atomic` fsyncs the `.kdbx.tmp` before renaming** (power-loss durability) and removes
  the temp file if the rename fails; `settings.json` is written atomically too.
- **The plaintext-XML save path is fully `Zeroizing`** (`serialize_keepass_xml` returns
  `Zeroizing<String>`, as do the compressed/payload intermediates).
- **`ProtectedString` serializes as `"***"` through serde**: an accidental
  `serde_json::to_*(…)` can never dump secrets; use `as_str()` explicitly.
- **HOTP (`otpauth://hotp/…`) URIs are rejected with `UnsupportedFeature`** instead of being
  silently mistreated as time-based codes (KeePassXC-compatible HOTP is future work).
- **`rustpass-proxy` refuses to return credentials in plaintext** (`get-logins`,
  `associate`, `test-associate` answer an explicit error) until a real KeePassXC-Browser
  encrypted channel (NaCl box over `change-public-keys`) exists. Local integration testing
  can opt in with `RUSTPASS_ALLOW_PLAINTEXT_LOGINS=1` (loudly warned).
- **Idle auto-lock saves dirty vaults before locking** (KeePassXC keeps them in memory; we
  cannot, since locking drops the decrypted `Database`); path-less unsaved vaults stay open
  rather than losing edits. Manual `Ctrl+L` saves-then-locks any vault.
- **Auto-Type unknown placeholders and malformed `{DELAY=…}` are hard errors**, `{CLEARFIELD}`
  is actually implemented (`Ctrl+A`, `Delete`), and partial `SendInput` batches are detected.
- **The shortcuts (F1) and About help windows remain English-only** (documentation content);
  every interactive surface is localized FR/EN.
- **`rustpass-cli` runs on a 16 MiB worker thread**: the unoptimized debug build of the deep
  `clap` derive overflows the default 1 MiB Windows main-thread stack; release builds are
  unaffected.
- **HOTP is fully supported** (RFC 4226 vectors pinned; the GUI increments the counter after
  each use), and Google Authenticator exports (`otpauth-migration://offline`) import via a
  hand-rolled minimal protobuf decoder (`rustpass-cli otp-import`).
- **KDBX 4.1 metadata is preserved on round-trip**: `Meta/CustomIcons`, entry/group
  `<CustomData>` (KeePassXC-Browser settings), `<PreviousParentGroup>`, `<QualityCheck>` and
  the UI-state group references (`EntryTemplatesGroup`, `LastSelectedGroup`,
  `LastTopVisibleGroup`) are parsed and written back instead of being reset.
- **All vault crypto runs off the UI thread** (open/create/save/unlock/merge): the window
  stays responsive (spinner + localized progress) while Argon2 derives; a headless test
  drives the spawn → poll → apply cycle.
- **Copied secrets are excluded from the Windows clipboard history** (Win+V) and cloud
  monitoring via arboard's `exclude_from_history`/`exclude_from_monitoring`.
- **The proxy implements the KeePassXC-Browser encrypted channel** (X25519 key exchange +
  NaCl box via `crypto_box`, response nonce = client nonce + 1): `associate` persists an
  id → idKey association for the proxy process, `test-associate` verifies it, and
  `get-logins` only ever emits credentials inside the box. Plaintext responses remain a
  loudly-warned `RUSTPASS_ALLOW_PLAINTEXT_LOGINS=1` test-only opt-in.
