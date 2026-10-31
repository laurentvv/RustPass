//! Procedural 2x2-supersampled SDF application icon for `RustPass` (emerald vault shield +
//! warm-amber padlock & keyhole).

use eframe::egui::IconData;

/// Generates a 64x64 RGBA window/taskbar icon for `eframe`.
#[must_use]
pub fn generate_app_icon() -> IconData {
    const SIZE: u32 = 64;
    IconData {
        rgba: render_icon_rgba(SIZE),
        width: SIZE,
        height: SIZE,
    }
}

/// Renders the `RustPass` icon at any target pixel dimension (`16..=256`) using 2x2 supersampling.
#[must_use]
pub fn render_icon_rgba(size: u32) -> Vec<u8> {
    let scale = 64.0_f32 / (size.max(1) as f32);
    let mut rgba = vec![0u8; (size * size * 4) as usize];
    for y in 0..size {
        for x in 0..size {
            let mut acc = [0u32; 4];
            for (sx, sy) in [(0.25_f32, 0.25), (0.75, 0.25), (0.25, 0.75), (0.75, 0.75)] {
                let (r, g, b, a) = shader_64((x as f32 + sx) * scale, (y as f32 + sy) * scale);
                acc[0] += u32::from(r);
                acc[1] += u32::from(g);
                acc[2] += u32::from(b);
                acc[3] += u32::from(a);
            }
            let idx = ((y * size + x) * 4) as usize;
            rgba[idx] = (acc[0] / 4) as u8;
            rgba[idx + 1] = (acc[1] / 4) as u8;
            rgba[idx + 2] = (acc[2] / 4) as u8;
            rgba[idx + 3] = (acc[3] / 4) as u8;
        }
    }
    rgba
}

fn shader_64(x: f32, y: f32) -> (u8, u8, u8, u8) {
    // 1. Rounded squircle canvas
    let cx = 32.0_f32;
    let cy = 32.0_f32;
    let half = 28.0_f32;
    let rad = 11.0_f32;
    let dx = (x - cx).abs() - (half - rad);
    let dy = (y - cy).abs() - (half - rad);
    let sq_dist = dx.max(0.0).hypot(dy.max(0.0)) + dx.max(dy).min(0.0) - rad;
    if sq_dist > 0.8 {
        return (0, 0, 0, 0);
    }
    let edge_alpha = (0.8 - sq_dist).clamp(0.0, 1.0);

    // Deep slate-emerald vertical gradient (#132226 -> #0B1418)
    let t = (y / 64.0).clamp(0.0, 1.0);
    let mut r = (19.0 * (1.0 - t) + 11.0 * t) as u8;
    let mut g = (36.0 * (1.0 - t) + 20.0 * t) as u8;
    let mut b = (40.0 * (1.0 - t) + 25.0 * t) as u8;
    let a = (255.0 * edge_alpha) as u8;

    // Outer subtle emerald rim
    if (-1.3..=0.5).contains(&sq_dist) {
        r = 38;
        g = 112;
        b = 94;
    }

    // 2. Emerald Shield silhouette (y in 10..54)
    if (10.0..=54.0).contains(&y) {
        let ny = (y - 10.0) / 44.0;
        let half_shield_w = if ny < 0.45 {
            18.5
        } else {
            let k = (ny - 0.45) / 0.55;
            18.5 * (1.0 - k * k * 0.92)
        };
        let adx = (x - cx).abs();
        if adx <= half_shield_w {
            // Emerald gradient (#10B981 -> #047857)
            r = (20.0 * (1.0 - ny) + 5.0 * ny) as u8;
            g = (188.0 * (1.0 - ny) + 122.0 * ny) as u8;
            b = (132.0 * (1.0 - ny) + 88.0 * ny) as u8;

            // Left-half subtle specular highlight
            if x < cx && adx < half_shield_w - 1.5 {
                r = r.saturating_add(14);
                g = g.saturating_add(18);
                b = b.saturating_add(12);
            }
            // Shield border
            if (half_shield_w - adx) < 1.4 || y < 11.4 {
                r = 110;
                g = 231;
                b = 183;
            }
        }
    }

    // 3. Padlock shackle arch (center 32, 26, outer R=7.6, inner R=4.6)
    let sh_dx = x - cx;
    let sh_dy = y - 26.5;
    let sh_r = sh_dx.hypot(sh_dy);
    let in_arch = y <= 27.5 && (4.5..=7.7).contains(&sh_r);
    let in_pillars = (26.0..=31.0).contains(&y) && (4.5..=7.7).contains(&sh_dx.abs());
    if in_arch || in_pillars {
        r = 244;
        g = 247;
        b = 250;
    }

    // 4. Padlock body (warm amber-gold / rust accent #F59E0B -> #D97706)
    let bx = (x - cx).abs() - 9.0;
    let by = (y - 37.5).abs() - 7.0;
    let body_dist = bx.max(0.0).hypot(by.max(0.0)) + bx.max(by).min(0.0) - 2.4;
    if body_dist <= 0.3 {
        let bt = ((y - 28.0) / 18.0).clamp(0.0, 1.0);
        r = (251.0 * (1.0 - bt) + 217.0 * bt) as u8;
        g = (191.0 * (1.0 - bt) + 119.0 * bt) as u8;
        b = (36.0 * (1.0 - bt) + 12.0 * bt) as u8;

        // Dark keyhole inside padlock body
        let kh_circle = (x - cx).hypot(y - 35.8) <= 2.2;
        let kh_slot = (x - cx).abs() <= 1.15 && (35.8..=41.5).contains(&y);
        if kh_circle || kh_slot {
            r = 15;
            g = 24;
            b = 28;
        }
    }

    (r, g, b, a)
}
