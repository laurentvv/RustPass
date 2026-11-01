//! KeePassXC Auto-Type sequence parser (`{USERNAME}{TAB}{PASSWORD}{ENTER}`) and Windows `SendInput`
//! Unicode keystroke injector.

use crate::error::{Result, RustPassError};
use crate::model::Entry;
use crate::totp::TotpConfig;
use zeroize::Zeroizing;

/// Canonical KeePass default Auto-Type sequence when an entry/group defines no override.
pub const DEFAULT_AUTOTYPE_SEQUENCE: &str = "{USERNAME}{TAB}{PASSWORD}{ENTER}";

/// Atomic action inside a compiled Auto-Type sequence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AutoTypeAction {
    /// Type UTF-8 text (zeroized when dropped).
    Text(Zeroizing<String>),
    /// Press a virtual key (`Tab`, `Enter`, `Space`, `Backspace`, `Escape`).
    VirtualKey(VirtualSpecialKey),
    /// Pause execution for `ms` milliseconds.
    DelayMs(u64),
    /// Clear the focused input field (`Ctrl+A` then `Delete`, the `{CLEARFIELD}` placeholder).
    ClearField,
}

/// Special non-character keys supported in Auto-Type sequences.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtualSpecialKey {
    /// `{TAB}` (`VK_TAB = 0x09`)
    Tab,
    /// `{ENTER}` (`VK_RETURN = 0x0D`)
    Enter,
    /// `{SPACE}` (`VK_SPACE = 0x20`)
    Space,
    /// `{BACKSPACE}` / `{BS}` (`VK_BACK = 0x08`)
    Backspace,
    /// `{ESC}` (`VK_ESCAPE = 0x1B`)
    Escape,
}

/// Compiles `sequence` (defaulting to `{USERNAME}{TAB}{PASSWORD}{ENTER}` if empty) against `entry`.
pub fn compile_autotype_sequence(
    entry: &Entry,
    sequence_override: Option<&str>,
) -> Result<Vec<AutoTypeAction>> {
    let raw_seq = match sequence_override {
        Some(s) if !s.trim().is_empty() => s,
        _ if !entry.auto_type.default_sequence.trim().is_empty() => {
            &entry.auto_type.default_sequence
        }
        _ => DEFAULT_AUTOTYPE_SEQUENCE,
    };

    let mut actions = Vec::new();
    let mut literal = Zeroizing::new(String::new());
    let mut chars = raw_seq.chars().peekable();

    let flush_literal = |lit: &mut Zeroizing<String>, out: &mut Vec<AutoTypeAction>| {
        if !lit.is_empty() {
            out.push(AutoTypeAction::Text(lit.clone()));
            lit.clear();
        }
    };

    while let Some(ch) = chars.next() {
        if ch == '{' {
            if chars.peek() == Some(&'{') {
                let _ = chars.next();
                literal.push('{');
                continue;
            }
            let mut token = String::new();
            let mut closed = false;
            for inner in chars.by_ref() {
                if inner == '}' {
                    closed = true;
                    break;
                }
                token.push(inner);
            }
            if !closed {
                return Err(RustPassError::InvalidArgument(
                    "Unclosed '{' placeholder in Auto-Type sequence".to_string(),
                ));
            }
            flush_literal(&mut literal, &mut actions);
            let upper = token.trim().to_ascii_uppercase();
            match upper.as_str() {
                "USERNAME" | "USER" => {
                    if !entry.username.is_empty() {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(entry.username.clone())));
                    }
                }
                "PASSWORD" | "PASS" => {
                    if !entry.password.is_empty() {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(
                            entry.password.as_str().to_string(),
                        )));
                    }
                }
                "TOTP" | "TIMEOTP" => {
                    let cfg = TotpConfig::from_entry(entry)?;
                    let (code, _) = cfg.generate_now()?;
                    actions.push(AutoTypeAction::Text(Zeroizing::new(code)));
                }
                "URL" => {
                    if !entry.url.is_empty() {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(entry.url.clone())));
                    }
                }
                "TITLE" => {
                    if !entry.title.is_empty() {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(entry.title.clone())));
                    }
                }
                "NOTES" => {
                    if !entry.notes.is_empty() {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(entry.notes.clone())));
                    }
                }
                "TAB" => actions.push(AutoTypeAction::VirtualKey(VirtualSpecialKey::Tab)),
                "ENTER" | "RETURN" => {
                    actions.push(AutoTypeAction::VirtualKey(VirtualSpecialKey::Enter))
                }
                "SPACE" => actions.push(AutoTypeAction::VirtualKey(VirtualSpecialKey::Space)),
                "BACKSPACE" | "BS" | "BKSP" => {
                    actions.push(AutoTypeAction::VirtualKey(VirtualSpecialKey::Backspace))
                }
                "ESC" | "ESCAPE" => {
                    actions.push(AutoTypeAction::VirtualKey(VirtualSpecialKey::Escape))
                }
                "CLEARFIELD" => actions.push(AutoTypeAction::ClearField),
                other => {
                    if let Some(ms_str) = other
                        .strip_prefix("DELAY=")
                        .or_else(|| other.strip_prefix("DELAY "))
                    {
                        let ms = ms_str.trim().parse::<u64>().map_err(|_| {
                            RustPassError::InvalidArgument(format!(
                                "Malformed Auto-Type delay value: {{{token}}}"
                            ))
                        })?;
                        actions.push(AutoTypeAction::DelayMs(ms.min(10_000)));
                    } else if let Some(attr_name) = token
                        .trim()
                        .strip_prefix("S:")
                        .or_else(|| token.trim().strip_prefix("s:"))
                        && let Some(val) = entry.get_attribute(attr_name.trim())
                        && !val.is_empty()
                    {
                        actions.push(AutoTypeAction::Text(Zeroizing::new(val.to_string())));
                    } else if !token.trim().is_empty()
                        && !token.trim().to_ascii_uppercase().starts_with("S:")
                    {
                        // A typo like {PASWORD} would silently type no password and
                        // submit the form with it missing — refuse loudly instead.
                        return Err(RustPassError::InvalidArgument(format!(
                            "Unknown Auto-Type placeholder: {{{token}}}"
                        )));
                    }
                }
            }
        } else if ch == '}' && chars.peek() == Some(&'}') {
            let _ = chars.next();
            literal.push('}');
        } else {
            literal.push(ch);
        }
    }
    flush_literal(&mut literal, &mut actions);
    Ok(actions)
}

/// Switches focus to the previously active window (`Alt+Tab` when `switch_previous_window` is `true`)
/// and injects the compiled Auto-Type sequence via OS Unicode input events.
pub fn execute_autotype(actions: &[AutoTypeAction], switch_previous_window: bool) -> Result<()> {
    #[cfg(windows)]
    {
        execute_autotype_windows(actions, switch_previous_window)
    }
    #[cfg(not(windows))]
    {
        let _ = (actions, switch_previous_window);
        Err(RustPassError::UnsupportedFeature(
            "OS keystroke injection is only enabled on Windows builds".to_string(),
        ))
    }
}

#[cfg(windows)]
fn execute_autotype_windows(
    actions: &[AutoTypeAction],
    switch_previous_window: bool,
) -> Result<()> {
    use std::thread;
    use std::time::Duration;
    use windows_sys::Win32::UI::Input::KeyboardAndMouse::{
        INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYEVENTF_KEYUP, KEYEVENTF_UNICODE, SendInput,
    };

    const VK_BACK: u16 = 0x08;
    const VK_TAB: u16 = 0x09;
    const VK_RETURN: u16 = 0x0D;
    const VK_MENU: u16 = 0x12; // Alt
    const VK_ESCAPE: u16 = 0x1B;
    const VK_SPACE: u16 = 0x20;

    let make_vk = |vk: u16, up: bool| -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: vk,
                    wScan: 0,
                    dwFlags: if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    };

    let make_utf16 = |unit: u16, up: bool| -> INPUT {
        INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: 0,
                    wScan: unit,
                    dwFlags: KEYEVENTF_UNICODE | if up { KEYEVENTF_KEYUP } else { 0 },
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        }
    };

    let send_batch = |batch: &[INPUT]| -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        // SAFETY: `batch` points to valid initialized `INPUT` structs with exact `size_of::<INPUT>()`.
        let sent = unsafe {
            SendInput(
                batch.len() as u32,
                batch.as_ptr(),
                core::mem::size_of::<INPUT>() as i32,
            )
        };
        // `SendInput` returns the count of injected events: a partial injection (e.g.
        // Alt down but not up) leaves modifier keys logically held and would turn the
        // following keystrokes into menu accelerators in the wrong window.
        if sent != batch.len() as u32 {
            return Err(RustPassError::UnsupportedFeature(format!(
                "Windows SendInput injected only {sent}/{} events (blocked by UIPI or locked desktop)",
                batch.len()
            )));
        }
        Ok(())
    };

    if switch_previous_window {
        let alt_tab = [
            make_vk(VK_MENU, false),
            make_vk(VK_TAB, false),
            make_vk(VK_TAB, true),
            make_vk(VK_MENU, true),
        ];
        send_batch(&alt_tab)?;
        thread::sleep(Duration::from_millis(220));
    }

    for action in actions {
        match action {
            AutoTypeAction::DelayMs(ms) => {
                thread::sleep(Duration::from_millis(*ms));
            }
            AutoTypeAction::VirtualKey(vk_kind) => {
                let vk = match vk_kind {
                    VirtualSpecialKey::Tab => VK_TAB,
                    VirtualSpecialKey::Enter => VK_RETURN,
                    VirtualSpecialKey::Space => VK_SPACE,
                    VirtualSpecialKey::Backspace => VK_BACK,
                    VirtualSpecialKey::Escape => VK_ESCAPE,
                };
                send_batch(&[make_vk(vk, false), make_vk(vk, true)])?;
                thread::sleep(Duration::from_millis(25));
            }
            AutoTypeAction::ClearField => {
                // Select everything in the focused control, then delete it.
                const VK_CONTROL: u16 = 0x11;
                const VK_A: u16 = 0x41;
                const VK_DELETE: u16 = 0x2E;
                send_batch(&[
                    make_vk(VK_CONTROL, false),
                    make_vk(VK_A, false),
                    make_vk(VK_A, true),
                    make_vk(VK_CONTROL, true),
                ])?;
                thread::sleep(Duration::from_millis(25));
                send_batch(&[make_vk(VK_DELETE, false), make_vk(VK_DELETE, true)])?;
                thread::sleep(Duration::from_millis(25));
            }
            AutoTypeAction::Text(secret) => {
                let mut units = Zeroizing::new(Vec::<u16>::with_capacity(secret.len()));
                units.extend(secret.encode_utf16());
                for &u in units.iter() {
                    send_batch(&[make_utf16(u, false), make_utf16(u, true)])?;
                    thread::sleep(Duration::from_millis(8));
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiles_standard_and_custom_placeholders() {
        let mut e = Entry::new("Portal");
        e.username = "jdoe".to_string();
        e.password = "s3cr3t!".into();
        e.set_custom_attribute("PIN", "9876", true);

        let seq = compile_autotype_sequence(
            &e,
            Some("{USERNAME}{TAB}{PASSWORD}{DELAY=50}{S:PIN}{ENTER}"),
        )
        .expect("compile");
        assert_eq!(seq.len(), 6);
        assert_eq!(
            seq[0],
            AutoTypeAction::Text(Zeroizing::new("jdoe".to_string()))
        );
        assert_eq!(seq[1], AutoTypeAction::VirtualKey(VirtualSpecialKey::Tab));
        assert_eq!(seq[3], AutoTypeAction::DelayMs(50));
        assert_eq!(
            seq[4],
            AutoTypeAction::Text(Zeroizing::new("9876".to_string()))
        );
        assert_eq!(seq[5], AutoTypeAction::VirtualKey(VirtualSpecialKey::Enter));
    }
}
