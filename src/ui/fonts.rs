//! System typography setup (`Segoe UI Variable` / `Segoe UI` + `Cascadia Mono` / `Consolas`) for
//! crisp native legibility on Windows 11.

use eframe::egui::{self, FontData, FontDefinitions, FontFamily};
use std::path::Path;
use std::sync::Arc;

/// Loads native Windows proportional and monospace fonts into `ctx` when present, gracefully
/// retaining `eframe`'s built-in fonts for fallback glyphs and symbols.
pub fn configure_fonts(ctx: &egui::Context) {
    let mut fonts = FontDefinitions::default();

    let proportional_candidates = [
        r"C:\Windows\Fonts\SegUIVar.ttf",
        r"C:\Windows\Fonts\segoeui.ttf",
    ];
    for candidate in proportional_candidates {
        if let Ok(bytes) = std::fs::read(Path::new(candidate)) {
            fonts
                .font_data
                .insert("sys_ui".to_string(), Arc::new(FontData::from_owned(bytes)));
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Proportional) {
                fam.insert(0, "sys_ui".to_string());
            }
            break;
        }
    }

    let mono_candidates = [
        r"C:\Windows\Fonts\CascadiaMono.ttf",
        r"C:\Windows\Fonts\CascadiaCode.ttf",
        r"C:\Windows\Fonts\consola.ttf",
    ];
    for candidate in mono_candidates {
        if let Ok(bytes) = std::fs::read(Path::new(candidate)) {
            fonts.font_data.insert(
                "sys_mono".to_string(),
                Arc::new(FontData::from_owned(bytes)),
            );
            if let Some(fam) = fonts.families.get_mut(&FontFamily::Monospace) {
                fam.insert(0, "sys_mono".to_string());
            }
            break;
        }
    }

    ctx.set_fonts(fonts);
}
