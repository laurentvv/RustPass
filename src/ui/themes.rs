//! Visual themes and color tokens for the `RustPass` desktop interface.

use crate::generator::StrengthLevel;
use crate::settings::ThemeChoice;
use eframe::egui::{self, Color32, CornerRadius, Stroke};

/// Resolved semantic color palette used by custom vault widgets.
#[derive(Debug, Clone, Copy)]
pub struct VaultPalette {
    pub dark: bool,
    pub bg_canvas: Color32,
    pub bg_sidebar: Color32,
    pub bg_surface: Color32,
    pub bg_elevated: Color32,
    pub selection_bg: Color32,
    pub border: Color32,
    pub text_primary: Color32,
    pub text_muted: Color32,
    pub accent: Color32,
    pub success: Color32,
    pub warning: Color32,
    pub danger: Color32,
}

const fn rgb(r: u8, g: u8, b: u8) -> Color32 {
    Color32::from_rgb(r, g, b)
}

/// Detects whether Windows 11/10 is currently in Light Mode (`AppsUseLightTheme == 1`).
#[must_use]
pub fn os_prefers_light() -> bool {
    #[cfg(windows)]
    {
        if let Ok(key) = windows_registry::CURRENT_USER
            .open(r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
            && let Ok(val) = key.get_u32("AppsUseLightTheme")
        {
            return val != 0;
        }
        false
    }
    #[cfg(not(windows))]
    {
        false
    }
}

/// Resolves `ThemeChoice` (including `FollowSystem`) into a concrete `VaultPalette`.
#[must_use]
pub fn resolve_palette(choice: ThemeChoice) -> VaultPalette {
    let concrete = match choice {
        ThemeChoice::FollowSystem => {
            if os_prefers_light() {
                ThemeChoice::FluentLight
            } else {
                ThemeChoice::EmeraldDark
            }
        }
        other => other,
    };

    match concrete {
        ThemeChoice::EmeraldDark | ThemeChoice::FollowSystem => VaultPalette {
            dark: true,
            bg_canvas: rgb(13, 19, 23),
            bg_sidebar: rgb(17, 25, 31),
            bg_surface: rgb(22, 32, 39),
            bg_elevated: rgb(29, 42, 51),
            selection_bg: rgb(18, 74, 58),
            border: rgb(39, 56, 67),
            text_primary: rgb(232, 241, 245),
            text_muted: rgb(140, 163, 176),
            accent: rgb(16, 185, 129),
            success: rgb(52, 211, 153),
            warning: rgb(245, 158, 11),
            danger: rgb(239, 68, 68),
        },
        ThemeChoice::ObsidianDark => VaultPalette {
            dark: true,
            bg_canvas: rgb(15, 16, 22),
            bg_sidebar: rgb(20, 22, 30),
            bg_surface: rgb(26, 29, 40),
            bg_elevated: rgb(35, 39, 54),
            selection_bg: rgb(74, 46, 30),
            border: rgb(48, 53, 72),
            text_primary: rgb(238, 240, 246),
            text_muted: rgb(148, 154, 176),
            accent: rgb(234, 118, 53),
            success: rgb(52, 211, 153),
            warning: rgb(251, 191, 36),
            danger: rgb(248, 113, 113),
        },
        ThemeChoice::FluentDark => VaultPalette {
            dark: true,
            bg_canvas: rgb(24, 24, 24),
            bg_sidebar: rgb(31, 31, 31),
            bg_surface: rgb(38, 38, 38),
            bg_elevated: rgb(46, 46, 46),
            selection_bg: rgb(28, 68, 98),
            border: rgb(58, 58, 58),
            text_primary: rgb(242, 242, 242),
            text_muted: rgb(162, 162, 162),
            accent: rgb(96, 205, 255),
            success: rgb(108, 203, 95),
            warning: rgb(252, 225, 0),
            danger: rgb(255, 153, 164),
        },
        ThemeChoice::SolarizedDark => VaultPalette {
            dark: true,
            bg_canvas: rgb(0, 43, 54),
            bg_sidebar: rgb(5, 50, 62),
            bg_surface: rgb(7, 54, 66),
            bg_elevated: rgb(14, 66, 80),
            selection_bg: rgb(14, 84, 98),
            border: rgb(28, 82, 96),
            text_primary: rgb(238, 232, 213),
            text_muted: rgb(147, 161, 161),
            accent: rgb(42, 161, 152),
            success: rgb(133, 153, 0),
            warning: rgb(181, 137, 0),
            danger: rgb(220, 50, 47),
        },
        ThemeChoice::FluentLight => VaultPalette {
            dark: false,
            bg_canvas: rgb(249, 250, 251),
            bg_sidebar: rgb(241, 245, 249),
            bg_surface: rgb(255, 255, 255),
            bg_elevated: rgb(236, 242, 248),
            selection_bg: rgb(208, 232, 250),
            border: rgb(214, 222, 230),
            text_primary: rgb(22, 30, 38),
            text_muted: rgb(94, 108, 124),
            accent: rgb(0, 103, 192),
            success: rgb(16, 124, 65),
            warning: rgb(180, 95, 6),
            danger: rgb(196, 43, 28),
        },
        ThemeChoice::ClassicLight => VaultPalette {
            dark: false,
            bg_canvas: rgb(246, 249, 248),
            bg_sidebar: rgb(236, 243, 240),
            bg_surface: rgb(255, 255, 255),
            bg_elevated: rgb(228, 238, 234),
            selection_bg: rgb(202, 242, 224),
            border: rgb(206, 220, 214),
            text_primary: rgb(20, 34, 28),
            text_muted: rgb(88, 110, 100),
            accent: rgb(5, 150, 105),
            success: rgb(5, 150, 105),
            warning: rgb(180, 83, 9),
            danger: rgb(185, 28, 28),
        },
    }
}

/// Applies `palette` onto an `egui::Context` with refined spacing and widget strokes.
pub fn apply_theme(ctx: &egui::Context, choice: ThemeChoice) -> VaultPalette {
    let p = resolve_palette(choice);
    let mut v = if p.dark {
        egui::Visuals::dark()
    } else {
        egui::Visuals::light()
    };

    v.panel_fill = p.bg_sidebar;
    v.window_fill = p.bg_surface;
    v.extreme_bg_color = p.bg_canvas;
    v.faint_bg_color = p.bg_elevated;
    v.selection.bg_fill = p.selection_bg;
    v.selection.stroke = Stroke::new(1.0, p.accent);
    v.hyperlink_color = p.accent;
    v.override_text_color = Some(p.text_primary);
    v.window_stroke = Stroke::new(1.0, p.border);
    v.window_corner_radius = CornerRadius::same(8);

    v.widgets.noninteractive.bg_fill = p.bg_surface;
    v.widgets.noninteractive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.noninteractive.fg_stroke = Stroke::new(1.0, p.text_primary);

    v.widgets.inactive.bg_fill = p.bg_elevated;
    v.widgets.inactive.weak_bg_fill = p.bg_elevated;
    v.widgets.inactive.bg_stroke = Stroke::new(1.0, p.border);
    v.widgets.inactive.fg_stroke = Stroke::new(1.0, p.text_primary);
    v.widgets.inactive.corner_radius = CornerRadius::same(5);

    v.widgets.hovered.bg_fill = p.selection_bg;
    v.widgets.hovered.weak_bg_fill = p.selection_bg;
    v.widgets.hovered.bg_stroke = Stroke::new(1.0, p.accent);
    v.widgets.hovered.fg_stroke = Stroke::new(1.0, p.text_primary);
    v.widgets.hovered.corner_radius = CornerRadius::same(5);

    v.widgets.active.bg_fill = p.selection_bg;
    v.widgets.active.weak_bg_fill = p.selection_bg;
    v.widgets.active.bg_stroke = Stroke::new(1.5, p.accent);
    v.widgets.active.fg_stroke = Stroke::new(1.0, p.text_primary);
    v.widgets.active.corner_radius = CornerRadius::same(5);

    ctx.set_visuals(v);
    p
}

/// Maps a `StrengthLevel` to its semantic badge color in `palette`.
#[must_use]
pub const fn strength_color(level: StrengthLevel, palette: &VaultPalette) -> Color32 {
    match level {
        StrengthLevel::VeryWeak => palette.danger,
        StrengthLevel::Weak => Color32::from_rgb(249, 115, 22),
        StrengthLevel::Fair => palette.warning,
        StrengthLevel::Strong => palette.success,
        StrengthLevel::Excellent => palette.accent,
    }
}
