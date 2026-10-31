//! Generates `assets/icon.ico` (256/64/48/32/16 px BGRA BMP-in-ICO) from the procedural SDF shader.
//!
//! Run with: `cargo run --example gen_icon`

use rustpass::ui::icon::render_icon_rgba;
use std::io::Write;
use std::path::Path;

fn ico_entry(size: u32, rgba: &[u8]) -> Vec<u8> {
    let w = size;
    let h = size;
    let and_stride = (w as usize).div_ceil(32) * 4;
    let mut data = Vec::with_capacity(40 + (w * h * 4) as usize + and_stride * h as usize);

    data.extend_from_slice(&40u32.to_le_bytes());
    data.extend_from_slice(&w.to_le_bytes());
    data.extend_from_slice(&(h * 2).to_le_bytes());
    data.extend_from_slice(&1u16.to_le_bytes());
    data.extend_from_slice(&32u16.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());
    data.extend_from_slice(&0u32.to_le_bytes());

    for y in (0..h).rev() {
        for x in 0..w {
            let idx = (((y * w) + x) * 4) as usize;
            data.push(rgba[idx + 2]);
            data.push(rgba[idx + 1]);
            data.push(rgba[idx]);
            data.push(rgba[idx + 3]);
        }
    }
    data.resize(data.len() + and_stride * h as usize, 0);
    data
}

fn write_ico(path: &Path, sizes: &[u32]) -> std::io::Result<()> {
    let entries: Vec<(u32, Vec<u8>)> = sizes
        .iter()
        .map(|&s| (s, ico_entry(s, &render_icon_rgba(s))))
        .collect();

    let mut ico = Vec::new();
    ico.extend_from_slice(&0u16.to_le_bytes());
    ico.extend_from_slice(&1u16.to_le_bytes());
    ico.extend_from_slice(&(entries.len() as u16).to_le_bytes());

    let mut offset = 6 + 16 * entries.len();
    for &(size, ref data) in &entries {
        let dim = u8::try_from(size).unwrap_or(0);
        ico.push(dim);
        ico.push(dim);
        ico.push(0);
        ico.push(0);
        ico.extend_from_slice(&1u16.to_le_bytes());
        ico.extend_from_slice(&32u16.to_le_bytes());
        ico.extend_from_slice(&(data.len() as u32).to_le_bytes());
        ico.extend_from_slice(&(offset as u32).to_le_bytes());
        offset += data.len();
    }
    for (_, data) in &entries {
        ico.extend_from_slice(data);
    }

    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut f = std::fs::File::create(path)?;
    f.write_all(&ico)?;
    Ok(())
}

fn main() {
    let out = Path::new("assets/icon.ico");
    if let Err(e) = write_ico(out, &[256, 64, 48, 32, 16]) {
        eprintln!("Failed to generate {}: {e}", out.display());
        std::process::exit(1);
    }
    println!("Generated {}", out.display());
}
