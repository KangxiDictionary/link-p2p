//! Terminal styling for our own output (banner, highlights, errors).
//!
//! Uses `console` for ANSI SGR styling. Color decision:
//!   - `--color always` / `never` force the global console setting
//!   - `--color auto` (default) follows console's detection: on iff stdout
//!     is a real TTY, and `NO_COLOR` is respected.
//!
//! clap styles `--help` itself (anstream); `--color` is forwarded to clap's
//! own `ColorChoice` too (see `localized_command()` in main.rs).

use console::Style;

/// CLI value for `--color`. `Default` = `Auto` (used by clap's
/// `default_value_t`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorMode {
    #[default]
    Auto,
    Always,
    Never,
}

impl ColorMode {
    /// The matching clap color choice, for `--help` styling.
    pub fn to_clap(self) -> clap::ColorChoice {
        match self {
            ColorMode::Auto => clap::ColorChoice::Auto,
            ColorMode::Always => clap::ColorChoice::Always,
            ColorMode::Never => clap::ColorChoice::Never,
        }
    }
}

/// Parses the raw `--color` value from argv (used before clap parses, so the
/// help/error output is styled correctly on the first pass).
pub fn detect_color_mode() -> ColorMode {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        if let Some(value) = arg.strip_prefix("--color=") {
            if let Some(mode) = parse(value) {
                return mode;
            }
        } else if arg == "--color" {
            if let Some(value) = args.next() {
                if let Some(mode) = parse(&value) {
                    return mode;
                }
            }
        }
    }
    ColorMode::Auto
}

fn parse(s: &str) -> Option<ColorMode> {
    match s {
        "auto" => Some(ColorMode::Auto),
        "always" => Some(ColorMode::Always),
        "never" => Some(ColorMode::Never),
        _ => None,
    }
}

/// Applies a `ColorMode` to the global `console` setting and returns a
/// `Styler` that renders accordingly.
pub fn apply_color_mode(mode: ColorMode) -> Styler {
    let enabled = match mode {
        ColorMode::Always => {
            console::set_colors_enabled(true);
            true
        }
        ColorMode::Never => {
            console::set_colors_enabled(false);
            false
        }
        ColorMode::Auto => console::colors_enabled(),
    };
    Styler { enabled }
}

/// Small wrapper that applies a fixed style when colors are enabled, and
/// passes text through unchanged otherwise.
#[derive(Clone, Copy, Debug)]
pub struct Styler {
    enabled: bool,
}

impl Styler {
    fn apply(&self, text: &str, style: Style) -> String {
        if self.enabled {
            style.apply_to(text).to_string()
        } else {
            text.to_string()
        }
    }

    /// Section headers / program banner (bold cyan).
    pub fn banner(&self, text: &str) -> String {
        self.apply(text, Style::new().bold().cyan())
    }

    /// Important values, e.g. the EndpointId (bold, extra bright).
    pub fn highlight(&self, text: &str) -> String {
        self.apply(text, Style::new().bold().bright().white())
    }

    /// Success messages (bold green).
    pub fn ok(&self, text: &str) -> String {
        self.apply(text, Style::new().bold().green())
    }

    /// Warnings (yellow).
    pub fn warn(&self, text: &str) -> String {
        self.apply(text, Style::new().yellow())
    }

    /// Errors (bold red).
    pub fn err(&self, text: &str) -> String {
        self.apply(text, Style::new().bold().red())
    }

    /// Neutral status (cyan).
    pub fn info(&self, text: &str) -> String {
        self.apply(text, Style::new().cyan())
    }

    /// Secondary / hints (dim).
    pub fn dim(&self, text: &str) -> String {
        self.apply(text, Style::new().dim())
    }
}
