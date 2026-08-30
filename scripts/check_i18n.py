#!/usr/bin/env python3
"""Extract all tr!/tr_fmt! msgids from src/, and verify every one exists in
each locales/*/LC_MESSAGES/link-p2p.po. Exits non-zero on any gap."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
LOCALES = ROOT / "locales"


def strip_comments(text: str) -> str:
    """Blank out whole-line comments so doc-comment examples like `tr!("Hello")`
    are not extracted as real msgids."""
    lines = []
    for ln in text.splitlines():
        stripped = ln.lstrip()
        if stripped.startswith("//"):
            lines.append("")
        else:
            lines.append(ln)
    return "\n".join(lines)


# Rust string literal: "..." with backslash escapes, possibly spanning lines,
# and `\`-newline continuations that swallow the newline + following indentation.
def rust_str(raw: str) -> str:
    # Step 1: `\` + newline + leading whitespace of next line => nothing.
    s = re.sub(r"\\\n[ \t]*", "", raw)
    # Step 2: decode common Rust escapes. Do NOT use codecs unicode_escape on
    # the whole string — it re-interprets UTF-8 bytes of non-ASCII (µ, —, …)
    # as latin-1 escapes and mangles msgids.
    out = []
    i = 0
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            n = s[i + 1]
            if n in "ntr\\\"'":
                out.append({"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'" }[n])
                i += 2
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


def extract_msgids(src_dir: Path):
    ids = []
    for f in sorted(src_dir.glob("*.rs")):
        text = strip_comments(f.read_text())
        for m in re.finditer(r'\btr(?:_fmt)?!\s*\(\s*"((?:[^"\\\\]|\\.)*)"', text, re.S):
            ids.append(rust_str(m.group(1)))
    return ids


def po_msgids(po: Path):
    text = po.read_text()
    ids = []
    for block in re.finditer(r'^msgid (.*?)(?=^msg(?:id|str)\b|\Z)', text, re.M | re.S):
        body = block.group(1)
        if body.strip() == '""':
            continue  # header
        parts = re.findall(r'"((?:[^"\\\\]|\\.)*)"', body)
        ids.append("".join(rust_str(p) for p in parts))
    return ids


def main():
    code_ids = extract_msgids(SRC)
    ok = True
    for po in sorted(LOCALES.glob("*/LC_MESSAGES/link-p2p.po")):
        translated = set(po_msgids(po))
        missing = [i for i in code_ids if i not in translated]
        # extra entries in the po that no longer exist in code (harmless, but report)
        stale = [i for i in translated if i not in code_ids]
        print(f"{po.parent.parent.name}: {len(translated)} msgids, "
              f"{len(missing)} missing from code, {len(stale)} stale")
        for i in missing:
            ok = False
            print(f"  MISSING: {i!r}")
        for i in stale:
            print(f"  (stale in po): {i!r}")
    print(f"code msgids: {len(code_ids)}")
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
