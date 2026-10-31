//! Cryptographically secure password generator, Diceware passphrase generator, and password
//! entropy / strength estimator.

pub mod wordlist;

use crate::crypto::random_array;
use crate::error::{Result, RustPassError};
use crate::generator::wordlist::resolve_wordlist;
use crate::model::ProtectedString;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::PathBuf;

const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMERIC: &str = "0123456789";
const SPECIAL: &str = "!@#$%^&*()-_=+[]{};:,.<>/?|~";
const EXTENDED_ASCII: &str = "¡¢£¤¥¦§¨©ª«¬®¯°±²³´µ¶·¸¹º»¼½¾¿ÀÁÂÃÄÅÆÇÈÉÊËÌÍÎÏÐÑÒÓÔÕÖ×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíîïðñòóôõö÷øùúûüýþÿ";
const SIMILAR_LOOKALIKES: &str = "Il1O0oB8S5Z2|";

/// Configuration for the character-based CSPRNG password generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordGeneratorOptions {
    /// Target length in characters (`1..=512`, default `20`).
    pub length: usize,
    /// Include `a-z`.
    pub lowercase: bool,
    /// Include `A-Z`.
    pub uppercase: bool,
    /// Include `0-9`.
    pub numbers: bool,
    /// Include ASCII symbols (`!@#$%...`).
    pub special: bool,
    /// Include Latin-1 extended characters (`U+00A1..=U+00FF`).
    pub extended_ascii: bool,
    /// Exclude visually ambiguous look-alike characters (`Il1O0o...`).
    pub exclude_similar: bool,
    /// Guarantee at least one character from every enabled character group.
    pub ensure_every_group: bool,
    /// Explicit characters to exclude from the pool.
    pub exclude_chars: String,
    /// Additional custom characters to merge into the pool (or sole pool when all flags are `false`).
    pub custom_chars: String,
}

impl Default for PasswordGeneratorOptions {
    fn default() -> Self {
        Self {
            length: 20,
            lowercase: true,
            uppercase: true,
            numbers: true,
            special: true,
            extended_ascii: false,
            exclude_similar: false,
            ensure_every_group: true,
            exclude_chars: String::new(),
            custom_chars: String::new(),
        }
    }
}

impl PasswordGeneratorOptions {
    /// Builds the deduplicated character groups and combined pool.
    pub fn build_groups(&self) -> Result<(Vec<Vec<char>>, Vec<char>)> {
        let mut excluded: HashSet<char> = self.exclude_chars.chars().collect();
        if self.exclude_similar {
            excluded.extend(SIMILAR_LOOKALIKES.chars());
        }

        let filter_group = |src: &str| -> Vec<char> {
            let mut seen = HashSet::new();
            src.chars()
                .filter(|c| !excluded.contains(c) && seen.insert(*c))
                .collect()
        };

        let mut groups = Vec::new();
        if self.lowercase {
            let g = filter_group(LOWERCASE);
            if !g.is_empty() {
                groups.push(g);
            }
        }
        if self.uppercase {
            let g = filter_group(UPPERCASE);
            if !g.is_empty() {
                groups.push(g);
            }
        }
        if self.numbers {
            let g = filter_group(NUMERIC);
            if !g.is_empty() {
                groups.push(g);
            }
        }
        if self.special {
            let g = filter_group(SPECIAL);
            if !g.is_empty() {
                groups.push(g);
            }
        }
        if self.extended_ascii {
            let g = filter_group(EXTENDED_ASCII);
            if !g.is_empty() {
                groups.push(g);
            }
        }
        if !self.custom_chars.is_empty() {
            let g = filter_group(&self.custom_chars);
            if !g.is_empty() {
                groups.push(g);
            }
        }

        let mut seen_all = HashSet::new();
        let mut combined = Vec::new();
        for g in &groups {
            for &ch in g {
                if seen_all.insert(ch) {
                    combined.push(ch);
                }
            }
        }

        if combined.is_empty() {
            return Err(RustPassError::InvalidArgument(
                "Password character pool is empty; enable at least one character set".to_string(),
            ));
        }

        Ok((groups, combined))
    }

    /// Generates a cryptographically uniform password with zero modulo bias.
    pub fn generate(&self) -> Result<ProtectedString> {
        if self.length == 0 || self.length > 4096 {
            return Err(RustPassError::InvalidArgument(
                "Password length must be between 1 and 4096".to_string(),
            ));
        }
        let (groups, pool) = self.build_groups()?;
        let mut chars = Vec::with_capacity(self.length);

        if self.ensure_every_group && self.length >= groups.len() {
            for g in &groups {
                let idx = uniform_index(g.len())?;
                chars.push(g[idx]);
            }
        }

        while chars.len() < self.length {
            let idx = uniform_index(pool.len())?;
            chars.push(pool[idx]);
        }

        // Cryptographic Fisher-Yates shuffle
        for i in (1..chars.len()).rev() {
            let j = uniform_index(i + 1)?;
            chars.swap(i, j);
        }

        let s: String = chars.into_iter().collect();
        Ok(ProtectedString::new(s))
    }

    /// Theoretical pool-based entropy in bits (`length * log2(pool_size)`).
    pub fn theoretical_entropy_bits(&self) -> Result<f64> {
        let (_, pool) = self.build_groups()?;
        Ok((self.length as f64) * (pool.len() as f64).log2())
    }
}

/// Configuration for the Diceware passphrase generator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DicewareOptions {
    /// Number of words (`1..=64`, default `6`).
    pub word_count: usize,
    /// Word separator string (default `" "` in CLI, `"-"` option in GUI).
    pub separator: String,
    /// Capitalize the first letter of every word (`TitleCase`).
    pub capitalize: bool,
    /// Append a random 2-digit number (`10..=99`) to one randomly chosen word.
    pub include_number: bool,
    /// Optional custom wordlist file path.
    pub wordlist_path: Option<PathBuf>,
}

impl Default for DicewareOptions {
    fn default() -> Self {
        Self {
            word_count: 6,
            separator: " ".to_string(),
            capitalize: false,
            include_number: false,
            wordlist_path: None,
        }
    }
}

impl DicewareOptions {
    /// Generates a cryptographically random Diceware passphrase and returns `(passphrase, entropy_bits)`.
    pub fn generate(&self) -> Result<(ProtectedString, f64)> {
        if self.word_count == 0 || self.word_count > 128 {
            return Err(RustPassError::InvalidArgument(
                "Word count must be between 1 and 128".to_string(),
            ));
        }
        let words = resolve_wordlist(self.wordlist_path.as_deref())?;
        let mut chosen = Vec::with_capacity(self.word_count);
        for _ in 0..self.word_count {
            let idx = uniform_index(words.len())?;
            let mut w = words[idx].clone();
            if self.capitalize {
                let mut chars = w.chars();
                if let Some(first) = chars.next() {
                    w = format!("{}{}", first.to_uppercase(), chars.as_str());
                }
            }
            chosen.push(w);
        }

        let mut extra_bits = 0.0;
        if self.include_number && !chosen.is_empty() {
            let slot = uniform_index(chosen.len())?;
            let num = 10 + uniform_index(90)?;
            chosen[slot].push_str(&num.to_string());
            extra_bits = (90.0f64 * chosen.len() as f64).log2();
        }

        let bits = (self.word_count as f64) * (words.len() as f64).log2() + extra_bits;
        let joined = chosen.join(&self.separator);
        Ok((ProtectedString::new(joined), bits))
    }
}

/// Qualitative password strength tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum StrengthLevel {
    /// `< 35` bits — crackable in seconds/minutes.
    VeryWeak,
    /// `35..50` bits — vulnerable to GPU clusters.
    Weak,
    /// `50..70` bits — reasonable for rate-limited online services.
    Fair,
    /// `70..95` bits — strong protection.
    Strong,
    /// `>= 95` bits — cryptographic-grade resistance.
    Excellent,
}

impl StrengthLevel {
    /// Short English label.
    #[must_use]
    pub const fn label_en(self) -> &'static str {
        match self {
            Self::VeryWeak => "Very Weak",
            Self::Weak => "Weak",
            Self::Fair => "Fair",
            Self::Strong => "Strong",
            Self::Excellent => "Excellent",
        }
    }

    /// Short French label.
    #[must_use]
    pub const fn label_fr(self) -> &'static str {
        match self {
            Self::VeryWeak => "Très faible",
            Self::Weak => "Faible",
            Self::Fair => "Moyen",
            Self::Strong => "Fort",
            Self::Excellent => "Excellent",
        }
    }
}

/// Result of `estimate_password` (used by `rustpass-cli estimate`, Security Health, and Entry Editor).
#[derive(Debug, Clone)]
pub struct PasswordEstimate {
    /// Length in Unicode scalar values.
    pub length: usize,
    /// Estimated effective entropy in bits (penalizing repeats, sequences, and common patterns).
    pub entropy_bits: f64,
    /// Qualitative rating (`0..=4`).
    pub level: StrengthLevel,
    /// Estimated offline crack time at `10^10` guesses/sec.
    pub crack_time_display: String,
    /// Detected pattern warnings (if any).
    pub warnings: Vec<&'static str>,
}

/// Estimates effective password entropy, pattern weaknesses, and offline crack time (at `10^10` H/s).
#[must_use]
pub fn estimate_password(password: &str) -> PasswordEstimate {
    let chars: Vec<char> = password.chars().collect();
    let len = chars.len();
    if len == 0 {
        return PasswordEstimate {
            length: 0,
            entropy_bits: 0.0,
            level: StrengthLevel::VeryWeak,
            crack_time_display: "instant".to_string(),
            warnings: vec!["Password is empty"],
        };
    }

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_non_ascii = false;

    for &c in &chars {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii() {
            has_symbol = true;
        } else {
            has_non_ascii = true;
        }
    }

    let mut pool = 0usize;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 32;
    }
    if has_non_ascii {
        pool += 96;
    }
    pool = pool.max(10);

    // Effective character count discounts consecutive duplicates and ±1 sequences
    let mut effective_chars = 1.0f64;
    let mut repeats = 0usize;
    let mut sequences = 0usize;
    for i in 1..len {
        let prev = chars[i - 1] as i32;
        let curr = chars[i] as i32;
        if curr == prev {
            repeats += 1;
            effective_chars += 0.15;
        } else if (curr - prev).abs() == 1 {
            sequences += 1;
            effective_chars += 0.35;
        } else {
            effective_chars += 1.0;
        }
    }

    let mut warnings = Vec::new();
    let lower_pw = password.to_ascii_lowercase();
    const COMMON_PASSWORDS: &[&str] = &[
        "password",
        "123456",
        "12345678",
        "123456789",
        "qwerty",
        "azerty",
        "admin",
        "letmein",
        "welcome",
        "monkey",
        "dragon",
        "master",
        "trustno1",
        "iloveyou",
        "passw0rd",
        "changeme",
    ];

    let mut bits = effective_chars * (pool as f64).log2();
    if COMMON_PASSWORDS.iter().any(|&w| lower_pw == w) {
        bits = bits.min(10.0);
        warnings.push("Top compromised dictionary password");
    } else if COMMON_PASSWORDS.iter().any(|&w| lower_pw.contains(w)) && len <= 12 {
        bits *= 0.55;
        warnings.push("Contains a common dictionary substring");
    }
    if repeats >= 3 {
        warnings.push("Repeated adjacent characters reduce entropy");
    }
    if sequences >= 3 {
        warnings.push("Sequential character run (e.g. abc / 123) reduces entropy");
    }
    if len < 10 {
        warnings.push("Short password (< 10 characters)");
    }

    let level = if bits < 35.0 {
        StrengthLevel::VeryWeak
    } else if bits < 50.0 {
        StrengthLevel::Weak
    } else if bits < 70.0 {
        StrengthLevel::Fair
    } else if bits < 95.0 {
        StrengthLevel::Strong
    } else {
        StrengthLevel::Excellent
    };

    // Offline fast hash cluster baseline: 10^10 guesses/sec, average 0.5 * 2^bits
    let guesses = 2.0f64.powf(bits.min(200.0)) * 0.5;
    let seconds = guesses / 1e10;
    let crack_time_display = format_duration_human(seconds);

    PasswordEstimate {
        length: len,
        entropy_bits: (bits * 100.0).round() / 100.0,
        level,
        crack_time_display,
        warnings,
    }
}

fn format_duration_human(seconds: f64) -> String {
    if seconds < 0.001 {
        "instant (< 1 ms)".to_string()
    } else if seconds < 1.0 {
        format!("{:.0} ms", seconds * 1000.0)
    } else if seconds < 60.0 {
        format!("{seconds:.1} seconds")
    } else if seconds < 3600.0 {
        format!("{:.1} minutes", seconds / 60.0)
    } else if seconds < 86_400.0 {
        format!("{:.1} hours", seconds / 3600.0)
    } else if seconds < 86_400.0 * 365.25 {
        format!("{:.1} days", seconds / 86_400.0)
    } else if seconds < 86_400.0 * 365.25 * 1_000_000.0 {
        format!("{:.1} years", seconds / (86_400.0 * 365.25))
    } else {
        "centuries+".to_string()
    }
}

/// Unbiased CSPRNG integer in `0..upper` via rejection sampling.
pub fn uniform_index(upper: usize) -> Result<usize> {
    if upper <= 1 {
        return Ok(0);
    }
    let bound = upper as u64;
    let zone = u64::MAX - (u64::MAX % bound);
    loop {
        let raw = u64::from_le_bytes(random_array::<8>()?);
        if raw < zone {
            return Ok((raw % bound) as usize);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generator_respects_length_and_every_group() {
        let opts = PasswordGeneratorOptions {
            length: 24,
            ensure_every_group: true,
            exclude_similar: true,
            ..PasswordGeneratorOptions::default()
        };
        let pw = opts.generate().expect("generate");
        let s = pw.as_str();
        assert_eq!(s.chars().count(), 24);
        assert!(s.chars().any(|c| c.is_ascii_lowercase()));
        assert!(s.chars().any(|c| c.is_ascii_uppercase()));
        assert!(s.chars().any(|c| c.is_ascii_digit()));
        assert!(!s.chars().any(|c| SIMILAR_LOOKALIKES.contains(c)));
    }

    #[test]
    fn diceware_and_estimator_work() {
        let dw = DicewareOptions {
            word_count: 6,
            separator: "-".to_string(),
            capitalize: true,
            include_number: true,
            wordlist_path: None,
        };
        let (phrase, bits) = dw.generate().expect("diceware");
        assert!(bits > 50.0);
        assert_eq!(phrase.as_str().split('-').count(), 6);

        let weak = estimate_password("password");
        assert_eq!(weak.level, StrengthLevel::VeryWeak);
        let strong = estimate_password(phrase.as_str());
        assert!(strong.level >= StrengthLevel::Strong);
    }
}
