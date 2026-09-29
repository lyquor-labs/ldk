use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const UI_FILES: &[&str] = &["index.html", "app.js", "styles.css"];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    for file in UI_FILES {
        println!("cargo:rerun-if-changed=ui/{file}");
    }

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set"));
    rebuild_assets(&manifest_dir.join("ui"), &manifest_dir.join("assets"))
        .unwrap_or_else(|error| panic!("failed to build shopping-assistant assets: {error}"));
}

fn rebuild_assets(ui_dir: &Path, assets_dir: &Path) -> io::Result<()> {
    fs::create_dir_all(assets_dir)?;
    for file in UI_FILES {
        fs::copy(ui_dir.join(file), assets_dir.join(file))?;
    }
    Ok(())
}
