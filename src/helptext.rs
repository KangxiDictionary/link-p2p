//! Clap help formatting: short `-h` vs long `--help`, and hard-wrapped text.
//!
//! Soft wrap (terminal auto-break at the window edge) is hard to read because
//! break points are width-dependent and unsemantic. We insert `\n` at sentence
//! / clause boundaries so `--help` stays legible at any terminal width.
//!
//! `-h` hides per-option blurbs ([`Arg::hide_short_help`]) and shows about,
//! usage, subcommands, and the quick-start `after_help` only.

/// Preferred maximum display width of one help line (after clap's option indent).
const HELP_LINE_WIDTH: usize = 72;

/// First sentence of `full` (ASCII `.!?` and CJK `。！？`).
///
/// Skips dots inside versions / IPs (`1.0`, `127.0.0.1`) and common
/// abbreviations (`e.g.`, `i.e.`).
pub(crate) fn brief_help(full: &str) -> String {
    let s = full.trim();
    if s.is_empty() {
        return String::new();
    }
    if let Some((first, _)) = split_sentences(s).split_first() {
        return first.to_string();
    }
    s.to_string()
}

/// Insert hard newlines after sentences; further split overlong clauses.
///
/// Existing `\n` in `full` are kept as paragraph breaks. Catalogs stay a
/// single msgid — wrapping happens at runtime on the translated string.
pub(crate) fn hard_wrap_help(full: &str) -> String {
    let s = full.trim();
    if s.is_empty() {
        return String::new();
    }
    let mut out = Vec::new();
    for para in s.split('\n') {
        let para = para.trim();
        if para.is_empty() {
            out.push(String::new());
            continue;
        }
        for sentence in split_sentences(para) {
            out.extend(wrap_clause(sentence, HELP_LINE_WIDTH));
        }
    }
    // Trim trailing empty lines from the split, keep internal blanks.
    while out.last().is_some_and(|l| l.is_empty()) {
        out.pop();
    }
    out.join("\n")
}

/// Attach long help with hard wraps; hide the option from `-h` listings.
pub(crate) fn set_help(arg: clap::Arg, full: &str) -> clap::Arg {
    let brief = brief_help(full);
    let wrapped = hard_wrap_help(full);
    arg.help(brief)
        .long_help(wrapped)
        .hide_short_help(true)
}

fn split_sentences(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < s.len() {
        let ch = s[i..].chars().next().expect("i in range");
        let len = ch.len_utf8();
        match ch {
            '。' | '！' | '？' => {
                let end = i + len;
                let piece = s[start..end].trim();
                if !piece.is_empty() {
                    out.push(piece);
                }
                start = end;
                i = end;
                continue;
            }
            '.' | '!' | '?' => {
                let after = i + len;
                let rest = s.get(after..).unwrap_or("");
                if ch == '.' && rest.starts_with(|c: char| c.is_ascii_digit()) {
                    i = after;
                    continue;
                }
                if ch == '.' {
                    let before = s[..i].chars().last();
                    let next_word = rest.trim_start().chars().next();
                    if before.is_some_and(|c| c.is_ascii_lowercase())
                        && next_word.is_some_and(|c| c.is_ascii_lowercase())
                    {
                        i = after;
                        continue;
                    }
                }
                if rest.is_empty() || rest.starts_with(char::is_whitespace) {
                    let piece = s[start..after].trim();
                    if !piece.is_empty() {
                        out.push(piece);
                    }
                    start = after;
                    i = after;
                    continue;
                }
            }
            _ => {}
        }
        i += len;
    }
    let tail = s[start..].trim();
    if !tail.is_empty() {
        out.push(tail);
    }
    out
}

/// Break an overlong sentence at the last soft break before `width`.
fn wrap_clause(sentence: &str, width: usize) -> Vec<String> {
    if display_width(sentence) <= width {
        return vec![sentence.to_string()];
    }
    let mut lines = Vec::new();
    let mut rest = sentence;
    while display_width(rest) > width {
        let Some(break_at) = find_soft_break(rest, width) else {
            break;
        };
        let (head, tail) = rest.split_at(break_at);
        let head = head.trim_end().to_string();
        let tail = tail.trim_start();
        if !head.is_empty() {
            lines.push(head);
        }
        rest = tail;
        if rest.is_empty() {
            return lines;
        }
    }
    if !rest.is_empty() {
        lines.push(rest.to_string());
    }
    lines
}

/// Byte index of the best soft-break at or before `width` display columns.
fn find_soft_break(s: &str, width: usize) -> Option<usize> {
    let mut col = 0;
    let mut last_break: Option<usize> = None;
    let mut i = 0;
    while i < s.len() {
        let ch = s[i..].chars().next().expect("i in range");
        let len = ch.len_utf8();
        let w = char_width(ch);
        if col + w > width {
            break;
        }
        col += w;
        i += len;
        if is_soft_break_char(ch) {
            last_break = Some(i);
        }
    }
    last_break.filter(|&b| b > 0 && b < s.len())
}

fn is_soft_break_char(ch: char) -> bool {
    matches!(ch, ',' | '，' | ';' | '；' | '/' | '、' | ' ' | '\t')
}

fn char_width(ch: char) -> usize {
    // East Asian wide / fullwidth ≈ 2; everything else 1. Good enough for help.
    match ch {
        '\u{1100}'..='\u{115F}'
        | '\u{2329}'..='\u{232A}'
        | '\u{2E80}'..='\u{303E}'
        | '\u{3040}'..='\u{A4CF}'
        | '\u{AC00}'..='\u{D7A3}'
        | '\u{F900}'..='\u{FAFF}'
        | '\u{FE10}'..='\u{FE19}'
        | '\u{FE30}'..='\u{FE6F}'
        | '\u{FF00}'..='\u{FF60}'
        | '\u{FFE0}'..='\u{FFE6}'
        | '\u{1F300}'..='\u{1F64F}'
        | '\u{1F900}'..='\u{1F9FF}'
        | '\u{20000}'..='\u{2FFFD}'
        | '\u{30000}'..='\u{3FFFD}' => 2,
        _ => 1,
    }
}

fn display_width(s: &str) -> usize {
    s.chars().map(char_width).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brief_takes_first_sentence() {
        assert_eq!(
            brief_help("One sentence. Two sentence."),
            "One sentence."
        );
        assert_eq!(
            brief_help("路径不存在时会新建。默认写到 XDG 配置目录。"),
            "路径不存在时会新建。"
        );
    }

    #[test]
    fn brief_skips_version_and_eg() {
        assert_eq!(
            brief_help("Uses iroh 1.0 over QUIC. See README."),
            "Uses iroh 1.0 over QUIC."
        );
        assert_eq!(
            brief_help("Relay URL, e.g. http://127.0.0.1:3340. Skips discovery."),
            "Relay URL, e.g. http://127.0.0.1:3340."
        );
    }

    #[test]
    fn hard_wrap_breaks_on_sentences() {
        let out = hard_wrap_help(
            "QUIC max idle timeout in seconds (default 30). After this long without traffic the peer is declared dead and the connection re-dialed. Raise it for lossy / high-latency links so a brief outage doesn't tear the connection down.",
        );
        let lines: Vec<_> = out.lines().collect();
        assert!(lines.len() >= 3, "expected sentence breaks, got:\n{out}");
        assert!(lines[0].contains("default 30"));
        assert!(lines.iter().any(|l| l.contains("re-dialed") || l.contains("declared dead")));
        assert!(lines.iter().any(|l| l.contains("Raise it") || l.contains("lossy")));
        // No soft-wrap reliance: each line should be a hard-broken chunk.
        assert!(!out.contains('\r'));
    }

    #[test]
    fn hard_wrap_chinese_sentences() {
        let out = hard_wrap_help(
            "QUIC 最大空闲超时（秒，默认 30）。超过此时间没有流量即判定对端已断开并重新拨号。在丢包/高延迟链路上调大，避免短暂中断就拆掉连接。",
        );
        let lines: Vec<_> = out.lines().collect();
        assert!(lines.len() >= 3, "got:\n{out}");
        assert!(lines[0].ends_with('。') || lines[0].contains("30"));
    }
}
