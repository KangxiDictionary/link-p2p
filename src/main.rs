use link_p2p::{exit, init, lookup, real_main, style};

fn main() {
    // Language selection + catalog load first, before any output; falls
    // back to English when the language/catalog isn't available.
    init();

    // Scan argv for --color before clap parses, so help/error output is
    // styled correctly even on the first run.
    let color_mode = style::detect_color_mode();
    let styler = style::apply_color_mode(color_mode);

    // Windows SCM must own the process main thread via
    // StartServiceCtrlDispatcher — do not nest that under #[tokio::main].
    #[cfg(windows)]
    if std::env::args_os().any(|a| a == "--windows-service") {
        if let Err(e) = link_p2p::run_windows_service_dispatcher() {
            // SCM may have no console; also write Application Event Log.
            let msg = format!("StartServiceCtrlDispatcher / service startup failed: {e:#}");
            if let Err(log_err) = link_p2p::win_eventlog_error(&msg) {
                eprintln!(
                    "{}: failed to write event log: {log_err}",
                    styler.warn("warning")
                );
            }
            eprintln!("{}: {e:#}", styler.err(&lookup("error")));
            std::process::exit(exit::code_from(&e));
        }
        return;
    }

    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime")
        .block_on(real_main(color_mode));
    if let Err(e) = result {
        eprintln!("{}: {e:#}", styler.err(&lookup("error")));
        std::process::exit(exit::code_from(&e));
    }
}
