//! `RustPass` — Clean-room KDBX 3.1 & 4.0 password manager library in pure Rust.
//!
//! Provides complete binary KDBX 3.1 and 4.0/4.1 parsing & serialization, Argon2d/Argon2id &
//! AES-KDF key derivation, ChaCha20 & AES-256-CBC encryption, HMAC-SHA-256 block stream
//! authentication, `.keyx` v2.0 key files, RFC 6238 TOTP + Steam Guard + ISO/IEC 18004 QR codes,
//! CSPRNG & Diceware password generation, KeePassXC structured search, Security Health Audits,
//! CSV/XML/HTML import/export, Windows Auto-Type, Native Messaging browser proxy framing, and
//! native `egui`/`eframe` desktop UI components.

pub mod app;
pub mod autotype;
pub mod cli;
pub mod crypto;
pub mod error;
pub mod generator;
pub mod health;
pub mod i18n;
pub mod io;
pub mod kdbx;
pub mod model;
pub mod proxy;
pub mod search;
pub mod settings;
pub mod totp;
pub mod ui;
