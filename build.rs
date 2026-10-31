//! Build script: embed the procedural application icon and Windows DPI manifest into the executables.

fn main() {
    println!("cargo:rerun-if-changed=assets/icon.ico");
    println!("cargo:rerun-if-changed=assets/app.manifest");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if !std::path::Path::new("assets/icon.ico").exists() {
        println!(
            "cargo:warning=assets/icon.ico missing - run `cargo run --example gen_icon` to generate it"
        );
        return;
    }

    let mut res = winres::WindowsResource::new();
    res.set_icon("assets/icon.ico");
    res.set_manifest_file("assets/app.manifest");
    if let Err(e) = res.compile() {
        println!("cargo:warning=resource compilation failed ({e}); icon/manifest not embedded");
    }
}
