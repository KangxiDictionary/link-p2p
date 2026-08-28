//! Compiles `.po` translation catalogs into `.mo` at build time.
//!
//! Source: `locales/<lang>/LC_MESSAGES/link-p2p.po`
//! Output: `$OUT_DIR/locales/<lang>/LC_MESSAGES/link-p2p.mo`
//!
//! The runtime locates these via `env!("OUT_DIR")/locales` (see
//! `src/i18n.rs`). If `msgfmt` isn't installed, translation is skipped and
//! the program falls back to the English msgids at runtime — the build
//! still succeeds.

use std::path::Path;
use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=locales");

    let locales_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("locales");
    if !locales_dir.is_dir() {
        return;
    }

    let out_locales = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("locales");

    for lang in std::fs::read_dir(&locales_dir).expect("read locales/") {
        let lang = lang.expect("read locale dir entry");
        if !lang.path().is_dir() {
            continue;
        }
        let lang_name = lang.file_name().to_string_lossy().into_owned();
        let messages_dir = lang.path().join("LC_MESSAGES");
        if !messages_dir.is_dir() {
            continue;
        }
        for po in std::fs::read_dir(&messages_dir).expect("read LC_MESSAGES dir") {
            let po = po.expect("read .po entry");
            if po.path().extension().and_then(|e| e.to_str()) != Some("po") {
                continue;
            }
            let stem = po
                .path()
                .file_stem()
                .expect("po file stem")
                .to_string_lossy()
                .into_owned();
            let out_mo_dir = out_locales.join(&lang_name).join("LC_MESSAGES");
            std::fs::create_dir_all(&out_mo_dir).expect("create .mo output dir");
            let out_mo = out_mo_dir.join(format!("{stem}.mo"));

            let status = Command::new("msgfmt")
                .arg("--check")
                .arg("-o")
                .arg(&out_mo)
                .arg(po.path())
                .status();
            match status {
                Ok(s) if s.success() => {}
                Ok(s) => println!(
                    "cargo:warning=msgfmt failed for {}: {s}",
                    po.path().display()
                ),
                Err(_) => {
                    println!(
                        "cargo:warning=msgfmt not found; skipping .mo compilation (translations will fall back to English)"
                    );
                    break;
                }
            }
        }
    }
}
