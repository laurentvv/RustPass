#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

//! `rustpass` — Native `egui`/`eframe` desktop password manager entrypoint.

use clap::Parser;
use eframe::egui;
use rustpass::app::RustPassApp;
use rustpass::cli::GuiCliArgs;
use rustpass::ui::icon::generate_app_icon;
use std::sync::Arc;

fn main() -> eframe::Result<()> {
    let cli_args = GuiCliArgs::parse();

    let viewport = egui::ViewportBuilder::default()
        .with_title("RustPass — KDBX 4.0 & 3.1 Password Manager")
        .with_inner_size([1240.0, 760.0])
        .with_min_inner_size([920.0, 560.0])
        .with_icon(Arc::new(generate_app_icon()));

    let native_options = eframe::NativeOptions {
        viewport,
        ..eframe::NativeOptions::default()
    };

    eframe::run_native(
        "RustPass",
        native_options,
        Box::new(move |cc| Ok(Box::new(RustPassApp::new(cc, cli_args)))),
    )
}
