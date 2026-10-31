//! Clean-room ISO/IEC 18004 QR Code symbol encoder (Byte mode, ECC Level L, Versions 1..=12)
//! for rendering scannable `otpauth://` TOTP QR codes in `egui` and SVG/ASCII exports without
//! external C dependencies (`libqrencode`).

use crate::error::{Result, RustPassError};

/// Version parameter row for ECC Level L (Versions 1..=12):
/// `(total_codewords, ec_codewords_per_block, num_blocks_group1, data_codewords_group1, num_blocks_group2, data_codewords_group2)`
const VERSION_TABLE_L: [(usize, usize, usize, usize, usize, usize); 12] = [
    (26, 7, 1, 19, 0, 0),    // v1:  up to 17 bytes
    (44, 10, 1, 34, 0, 0),   // v2:  up to 32 bytes
    (70, 15, 1, 55, 0, 0),   // v3:  up to 53 bytes
    (100, 20, 1, 80, 0, 0),  // v4:  up to 78 bytes
    (134, 26, 1, 108, 0, 0), // v5:  up to 106 bytes
    (172, 18, 2, 68, 0, 0),  // v6:  up to 134 bytes
    (196, 20, 2, 78, 0, 0),  // v7:  up to 154 bytes
    (242, 24, 2, 97, 0, 0),  // v8:  up to 192 bytes
    (292, 30, 2, 116, 0, 0), // v9:  up to 230 bytes
    (346, 18, 2, 68, 2, 69), // v10: up to 271 bytes
    (404, 20, 4, 81, 0, 0),  // v11: up to 321 bytes
    (466, 24, 2, 92, 2, 93), // v12: up to 367 bytes
];

/// Alignment pattern center coordinates for Versions 1..=12.
const ALIGNMENT_CENTERS: [&[usize]; 12] = [
    &[],
    &[6, 18],
    &[6, 22],
    &[6, 26],
    &[6, 30],
    &[6, 34],
    &[6, 22, 38],
    &[6, 24, 42],
    &[6, 26, 46],
    &[6, 28, 50],
    &[6, 30, 54],
    &[6, 32, 58],
];

/// Square QR Code grid of dark (`true`) and light (`false`) modules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QrMatrix {
    /// QR version (`1..=12`).
    pub version: usize,
    /// Matrix dimension (`17 + 4 * version`).
    pub size: usize,
    /// Row-major module grid (`size * size`).
    pub modules: Vec<bool>,
}

impl QrMatrix {
    /// Encodes `payload` (UTF-8 bytes) into the smallest fitting ISO/IEC 18004 QR Code matrix.
    pub fn encode(payload: &[u8]) -> Result<Self> {
        let version = select_version(payload.len())?;
        let (total_cw, ec_cw, g1_blocks, g1_data, g2_blocks, g2_data) =
            VERSION_TABLE_L[version - 1];
        let total_data_cw = g1_blocks * g1_data + g2_blocks * g2_data;

        // 1. Build Byte-mode bit stream: mode=0100 (4 bits) + count (8 or 16 bits) + payload + terminator + pad
        let mut bits = Vec::with_capacity(total_data_cw * 8);
        push_bits(&mut bits, 0b0100, 4);
        let count_bits = if version <= 9 { 8 } else { 16 };
        push_bits(&mut bits, payload.len() as u32, count_bits);
        for &b in payload {
            push_bits(&mut bits, u32::from(b), 8);
        }
        let max_bits = total_data_cw * 8;
        let term = (max_bits - bits.len()).min(4);
        push_bits(&mut bits, 0, term);
        while bits.len() % 8 != 0 {
            bits.push(false);
        }

        let mut data_codewords = Vec::with_capacity(total_data_cw);
        for chunk in bits.as_chunks::<8>().0 {
            let mut byte = 0u8;
            for &bit in chunk {
                byte = (byte << 1) | u8::from(bit);
            }
            data_codewords.push(byte);
        }
        let pad_bytes = [0xECu8, 0x11u8];
        let mut pad_idx = 0;
        while data_codewords.len() < total_data_cw {
            data_codewords.push(pad_bytes[pad_idx % 2]);
            pad_idx += 1;
        }

        // 2. Split into Reed-Solomon blocks and compute ECC codewords
        let rs_gen = rs_generator_poly(ec_cw);
        let mut blocks_data = Vec::with_capacity(g1_blocks + g2_blocks);
        let mut blocks_ec = Vec::with_capacity(g1_blocks + g2_blocks);
        let mut offset = 0usize;
        for _ in 0..g1_blocks {
            let slice = data_codewords[offset..offset + g1_data].to_vec();
            blocks_ec.push(rs_remainder(&slice, &rs_gen));
            blocks_data.push(slice);
            offset += g1_data;
        }
        for _ in 0..g2_blocks {
            let slice = data_codewords[offset..offset + g2_data].to_vec();
            blocks_ec.push(rs_remainder(&slice, &rs_gen));
            blocks_data.push(slice);
            offset += g2_data;
        }

        // 3. Interleave data and EC codewords
        let mut interleaved = Vec::with_capacity(total_cw);
        let max_data_len = g1_data.max(g2_data);
        for col in 0..max_data_len {
            for b in &blocks_data {
                if let Some(&cw) = b.get(col) {
                    interleaved.push(cw);
                }
            }
        }
        for col in 0..ec_cw {
            for b in &blocks_ec {
                if let Some(&cw) = b.get(col) {
                    interleaved.push(cw);
                }
            }
        }

        // 4. Construct module grid and reserve function patterns
        let size = 17 + 4 * version;
        let mut modules = vec![false; size * size];
        let mut is_function = vec![false; size * size];
        draw_function_patterns(version, size, &mut modules, &mut is_function);

        // 5. Place interleaved data + remainder bits in zigzag columns
        place_codewords(size, &interleaved, &mut modules, &is_function);

        // 6. Choose lowest-penalty mask (0..8)
        let mut best_mask = 0u8;
        let mut best_penalty = u32::MAX;
        let mut best_modules = modules.clone();

        for mask in 0u8..8 {
            let mut trial = modules.clone();
            apply_mask(size, mask, &mut trial, &is_function);
            draw_format_bits(size, mask, &mut trial);
            let pen = compute_penalty(size, &trial);
            if pen < best_penalty {
                best_penalty = pen;
                best_mask = mask;
                best_modules = trial;
            }
        }
        let _ = best_mask;

        Ok(Self {
            version,
            size,
            modules: best_modules,
        })
    }

    /// Queries whether module `(x, y)` is dark (`true`).
    #[must_use]
    pub fn get(&self, x: usize, y: usize) -> bool {
        if x < self.size && y < self.size {
            self.modules[y * self.size + x]
        } else {
            false
        }
    }

    /// Renders a compact UTF-8 half-block terminal string (`▀`, `▄`, `█`, ` `) for CLI preview.
    #[must_use]
    pub fn to_unicode_blocks(&self) -> String {
        let quiet = 2isize;
        let total = self.size as isize + quiet * 2;
        let mut out = String::new();
        let mut y = -quiet;
        while y < total - quiet {
            for x in -quiet..(self.size as isize + quiet) {
                let top = x >= 0
                    && y >= 0
                    && (x as usize) < self.size
                    && (y as usize) < self.size
                    && self.get(x as usize, y as usize);
                let bot = x >= 0
                    && (y + 1) >= 0
                    && (x as usize) < self.size
                    && ((y + 1) as usize) < self.size
                    && self.get(x as usize, (y + 1) as usize);
                // Invert for dark-terminal legibility (light quiet zone = full block, dark = space)
                let ch = match (top, bot) {
                    (false, false) => '█',
                    (false, true) => '▀',
                    (true, false) => '▄',
                    (true, true) => ' ',
                };
                out.push(ch);
            }
            out.push('\n');
            y += 2;
        }
        out
    }
}

fn select_version(payload_len: usize) -> Result<usize> {
    for (idx, &(_, _, g1_b, g1_d, g2_b, g2_d)) in VERSION_TABLE_L.iter().enumerate() {
        let ver = idx + 1;
        let data_cw = g1_b * g1_d + g2_b * g2_d;
        let header_bits = if ver <= 9 { 4 + 8 } else { 4 + 16 };
        let capacity = (data_cw * 8 - header_bits) / 8;
        if payload_len <= capacity {
            return Ok(ver);
        }
    }
    Err(RustPassError::Totp(format!(
        "QR payload too long ({payload_len} bytes; maximum supported is 367 bytes)"
    )))
}

fn push_bits(out: &mut Vec<bool>, val: u32, len: usize) {
    for i in (0..len).rev() {
        out.push(((val >> i) & 1) != 0);
    }
}

fn gf_mul(mut x: u8, mut y: u8) -> u8 {
    let mut z = 0u8;
    for _ in 0..8 {
        if (y & 1) != 0 {
            z ^= x;
        }
        let hi = (x & 0x80) != 0;
        x <<= 1;
        if hi {
            x ^= 0x1D; // x^8 + x^4 + x^3 + x^2 + 1 (0x11D)
        }
        y >>= 1;
    }
    z
}

fn rs_generator_poly(degree: usize) -> Vec<u8> {
    let mut result = vec![0u8; degree];
    result[degree - 1] = 1;
    let mut root = 1u8;
    for _ in 0..degree {
        for j in 0..degree {
            result[j] = gf_mul(result[j], root);
            if j + 1 < degree {
                result[j] ^= result[j + 1];
            }
        }
        root = gf_mul(root, 0x02);
    }
    result
}

fn rs_remainder(data: &[u8], divisor: &[u8]) -> Vec<u8> {
    let mut result = vec![0u8; divisor.len()];
    for &b in data {
        let factor = b ^ result[0];
        result.remove(0);
        result.push(0);
        for (r, &d) in result.iter_mut().zip(divisor.iter()) {
            *r ^= gf_mul(d, factor);
        }
    }
    result
}

fn set_func(
    size: usize,
    x: usize,
    y: usize,
    dark: bool,
    modules: &mut [bool],
    is_func: &mut [bool],
) {
    modules[y * size + x] = dark;
    is_func[y * size + x] = true;
}

fn draw_finder(size: usize, cx: isize, cy: isize, modules: &mut [bool], is_func: &mut [bool]) {
    for dy in -4..=4 {
        for dx in -4..=4 {
            let x = cx + dx;
            let y = cy + dy;
            if x >= 0 && y >= 0 && (x as usize) < size && (y as usize) < size {
                let dist = dx.abs().max(dy.abs());
                let dark = dist != 2 && dist != 4;
                set_func(size, x as usize, y as usize, dark, modules, is_func);
            }
        }
    }
}

fn draw_alignment(size: usize, cx: usize, cy: usize, modules: &mut [bool], is_func: &mut [bool]) {
    for dy in -2isize..=2 {
        for dx in -2isize..=2 {
            let x = (cx as isize + dx) as usize;
            let y = (cy as isize + dy) as usize;
            let dist = dx.abs().max(dy.abs());
            set_func(size, x, y, dist != 1, modules, is_func);
        }
    }
}

fn draw_function_patterns(version: usize, size: usize, modules: &mut [bool], is_func: &mut [bool]) {
    // Timing lines
    for i in 0..size {
        set_func(size, 6, i, i % 2 == 0, modules, is_func);
        set_func(size, i, 6, i % 2 == 0, modules, is_func);
    }

    // 3 Finder patterns + separators
    draw_finder(size, 3, 3, modules, is_func);
    draw_finder(size, size as isize - 4, 3, modules, is_func);
    draw_finder(size, 3, size as isize - 4, modules, is_func);

    // Alignment patterns
    let centers = ALIGNMENT_CENTERS[version - 1];
    for (i, &cy) in centers.iter().enumerate() {
        for (j, &cx) in centers.iter().enumerate() {
            let is_corner = (i == 0 && j == 0)
                || (i == 0 && j == centers.len() - 1)
                || (i == centers.len() - 1 && j == 0);
            if !is_corner {
                draw_alignment(size, cx, cy, modules, is_func);
            }
        }
    }

    // Reserve format info slots + dark module
    for i in 0..=8 {
        if i != 6 {
            is_func[8 * size + i] = true;
            is_func[i * size + 8] = true;
        }
    }
    for i in 0..8 {
        is_func[8 * size + (size - 1 - i)] = true;
        is_func[(size - 1 - i) * size + 8] = true;
    }
    set_func(size, 8, size - 8, true, modules, is_func);

    // Version info (v7+)
    if version >= 7 {
        let mut rem = version as u32;
        for _ in 0..12 {
            rem = (rem << 1) ^ (((rem >> 11) & 1) * 0x1F25);
        }
        let bits = ((version as u32) << 12) | rem;
        for i in 0..18 {
            let dark = ((bits >> i) & 1) != 0;
            let a = size - 11 + (i % 3);
            let b = i / 3;
            set_func(size, a, b, dark, modules, is_func);
            set_func(size, b, a, dark, modules, is_func);
        }
    }
}

fn place_codewords(size: usize, codewords: &[u8], modules: &mut [bool], is_func: &[bool]) {
    let mut bit_idx = 0usize;
    let total_bits = codewords.len() * 8;
    let mut right = (size - 1) as isize;
    let mut upward = true;

    while right >= 1 {
        if right == 6 {
            right -= 1;
        }
        for step in 0..size {
            let y = if upward { size - 1 - step } else { step };
            for j in 0..2 {
                let x = (right - j) as usize;
                if !is_func[y * size + x] {
                    let dark = if bit_idx < total_bits {
                        ((codewords[bit_idx / 8] >> (7 - (bit_idx % 8))) & 1) != 0
                    } else {
                        false
                    };
                    modules[y * size + x] = dark;
                    bit_idx += 1;
                }
            }
        }
        upward = !upward;
        right -= 2;
    }
}

fn apply_mask(size: usize, mask: u8, modules: &mut [bool], is_func: &[bool]) {
    for y in 0..size {
        for x in 0..size {
            if is_func[y * size + x] {
                continue;
            }
            let invert = match mask {
                0 => (x + y) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (x + y) % 3 == 0,
                4 => (y / 2 + x / 3) % 2 == 0,
                5 => (x * y) % 2 + (x * y) % 3 == 0,
                6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                _ => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
            };
            if invert {
                modules[y * size + x] = !modules[y * size + x];
            }
        }
    }
}

fn draw_format_bits(size: usize, mask: u8, modules: &mut [bool]) {
    // ECC Level L format bits = 01
    let data = (0b01u32 << 3) | u32::from(mask);
    let mut rem = data;
    for _ in 0..10 {
        rem = (rem << 1) ^ (((rem >> 9) & 1) * 0x537);
    }
    let bits = ((data << 10) | rem) ^ 0x5412;

    let bit = |i: usize| ((bits >> i) & 1) != 0;

    // Top-left copy
    for i in 0..=5 {
        modules[i * size + 8] = bit(i);
    }
    modules[7 * size + 8] = bit(6);
    modules[8 * size + 8] = bit(7);
    modules[8 * size + 7] = bit(8);
    for i in 9..15 {
        modules[8 * size + (14 - i)] = bit(i);
    }

    // Split top-right & bottom-left copy
    for i in 0..8 {
        modules[8 * size + (size - 1 - i)] = bit(i);
    }
    for i in 8..15 {
        modules[(size - 15 + i) * size + 8] = bit(i);
    }
    modules[(size - 8) * size + 8] = true;
}

fn compute_penalty(size: usize, modules: &[bool]) -> u32 {
    let mut penalty = 0u32;

    // N1: runs of >= 5 identical modules in rows and columns
    for y in 0..size {
        let mut run_color = modules[y * size];
        let mut run_len = 1u32;
        for x in 1..size {
            let c = modules[y * size + x];
            if c == run_color {
                run_len += 1;
                if run_len == 5 {
                    penalty += 3;
                } else if run_len > 5 {
                    penalty += 1;
                }
            } else {
                run_color = c;
                run_len = 1;
            }
        }
    }
    for x in 0..size {
        let mut run_color = modules[x];
        let mut run_len = 1u32;
        for y in 1..size {
            let c = modules[y * size + x];
            if c == run_color {
                run_len += 1;
                if run_len == 5 {
                    penalty += 3;
                } else if run_len > 5 {
                    penalty += 1;
                }
            } else {
                run_color = c;
                run_len = 1;
            }
        }
    }

    // N2: 2x2 blocks of identical modules
    for y in 0..size - 1 {
        for x in 0..size - 1 {
            let c = modules[y * size + x];
            if c == modules[y * size + x + 1]
                && c == modules[(y + 1) * size + x]
                && c == modules[(y + 1) * size + x + 1]
            {
                penalty += 3;
            }
        }
    }
    penalty
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_otpauth_uri_into_valid_qr_matrix() {
        let uri = b"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub";
        let qr = QrMatrix::encode(uri).expect("encode qr");
        assert!(qr.version >= 4);
        assert_eq!(qr.size, 17 + 4 * qr.version);
        // Finder pattern top-left corners must be dark
        assert!(qr.get(0, 0));
        assert!(qr.get(6, 0));
        assert!(qr.get(0, 6));
        assert!(!qr.get(1, 1));
        assert!(qr.get(3, 3));
        assert!(!qr.to_unicode_blocks().is_empty());
    }
}
