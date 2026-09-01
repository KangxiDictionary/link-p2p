//! `config` — read or write `~/.config/link-p2p/config.toml` defaults.

use anyhow::{anyhow, Result};

use crate::cli::ConfigCommand;
use crate::config;
use crate::exit;
use crate::i18n::tr_fmt;
use crate::runtime::Ui;
use crate::style::Styler;

pub(crate) fn run_config(command: ConfigCommand, ui: Ui, styler: Styler) -> Result<()> {
    match command {
        ConfigCommand::Path => {
            // Machine-readable path for scripts — always stdout.
            println!("{}", config::config_path().display());
            Ok(())
        }
        ConfigCommand::Init { force } => {
            let path = config::config_path();
            if path.exists() && !force {
                return Err(exit::coded(
                    exit::USAGE,
                    anyhow!(tr_fmt!(
                        "config already exists at {0} (use --force to overwrite)",
                        path.display()
                    )),
                ));
            }
            let cfg = config::UserConfig::default();
            config::save(&path, &cfg)?;
            ui.line(styler.ok(&tr_fmt!("wrote {0}", path.display())));
            Ok(())
        }
    }
}
