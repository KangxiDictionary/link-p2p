//! `contact` — local contact book (add/remove/list/code).

use anyhow::{bail, Result};
use iroh::SecretKey;

use crate::cli::ContactCommand;
use crate::contacts;
use crate::i18n::{tr, tr_fmt};
use crate::runtime::Ui;
use crate::style::Styler;

pub(crate) fn run_contact(
    command: ContactCommand,
    secret_key: SecretKey,
    ui: Ui,
    styler: Styler,
) -> Result<()> {
    match command {
        ContactCommand::Add { name, id } => {
            let path = contacts::contacts_path();
            let mut book = contacts::load(&path)?;
            let eid = contacts::parse_endpoint_token(&id)?;
            book.contacts.insert(
                name.clone(),
                contacts::Contact {
                    id: eid.to_string(),
                    relays: Vec::new(),
                    addrs: Vec::new(),
                },
            );
            contacts::save(&path, &book)?;
            let code = contacts::encode_short_code(eid);
            ui.line(styler.ok(&tr_fmt!(
                "saved contact {0} → {1}",
                name,
                code
            )));
            ui.line(styler.dim(&tr_fmt!(
                "next: on this machine `call up --listen …`; peer runs `call {0} --listen …`",
                name
            )));
            Ok(())
        }
        ContactCommand::Remove { name } => {
            let path = contacts::contacts_path();
            let mut book = contacts::load(&path)?;
            if book.contacts.remove(&name).is_none() {
                bail!(tr_fmt!("no contact named '{0}'", name));
            }
            contacts::save(&path, &book)?;
            ui.line(styler.ok(&tr_fmt!("removed contact {0}", name)));
            Ok(())
        }
        ContactCommand::List => {
            let book = contacts::load(&contacts::contacts_path())?;
            if book.contacts.is_empty() {
                ui.line(styler.dim(&tr!(
                    "no contacts yet — use `contact add` or pair a short code"
                )));
            } else {
                // Machine-readable TSV for scripts (`name\tid`), like
                // `contact code` / `ping --format json`: always stdout,
                // not via `ui.line` — quiet must not suppress data output.
                for (name, c) in &book.contacts {
                    println!("{name}\t{}", c.id);
                }
            }
            Ok(())
        }
        ContactCommand::Code => {
            // Machine-readable identity lines for scripts / pairing —
            // always stdout, even under `-q` (same rule as ENDPOINT_ID=).
            let id = secret_key.public();
            println!("ENDPOINT_ID={id}");
            println!("SHORT_CODE={}", contacts::encode_short_code(id));
            Ok(())
        }
    }
}
