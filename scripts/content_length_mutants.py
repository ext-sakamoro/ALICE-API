#!/usr/bin/env python3
"""Breaks find_content_length one way at a time; tests/content_length.rs must go red for each.

usage: python3 scripts/content_length_mutants.py [--release]
exit 0 if every mutant applied, compiled and made a test report FAILED; exit 1 otherwise.

Run by hand when src/http.rs changes: each mutant rebuilds the crate. A mutant that does not compile
or no longer applies counts against the result, since it tested nothing. The file is restored after
each mutant, and at the end even after an interrupt.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src" / "http.rs"
COMMAND = ["cargo", "test", "--test", "content_length"]
FAILED = re.compile(r"^test .* \.\.\. .*FAILED", re.M)

NAME_CHECK = "if name.eq_ignore_ascii_case(CONTENT_LENGTH) {"
# (what breaks, old text, new text)
MUTANTS = [
    (
        "checked_mul to wrapping",
        ".checked_mul(10)\n            .and_then(|n| n.checked_add(usize::from(digit - b'0')))",
        ".wrapping_mul(10)\n            .checked_add(usize::from(digit - b'0'))",
    ),
    (
        "checked_add to wrapping",
        ".and_then(|n| n.checked_add(usize::from(digit - b'0')))",
        ".map(|n| n.wrapping_add(usize::from(digit - b'0')))",
    ),
    ("digits not checked", "|| !value.iter().all(u8::is_ascii_digit)", ""),
    ("empty value allowed", "value.is_empty() || ", ""),
    (
        "name as a suffix",
        NAME_CHECK,
        "if name.len() >= 14 && name[name.len() - 14..].eq_ignore_ascii_case(CONTENT_LENGTH) {",
    ),
    (
        "name anywhere in the line",
        NAME_CHECK,
        "if line.windows(15).any(|w| w[..14].eq_ignore_ascii_case(CONTENT_LENGTH) && w[14] == b':') {",
    ),
    ("name case-sensitive", NAME_CHECK, 'if name == b"Content-Length" {'),
    ("reads past the empty line", "            return Ok(found);\n", "            continue;\n"),
    (
        "a leading empty line is skipped",
        "                return Err(ContentLengthError::Invalid);\n            }\n            return Ok(found);",
        "                continue;\n            }\n            return Ok(found);",
    ),
    ("duplicates allowed", "if found.is_some() {", "if false {"),
    ("no CRLF needed", '.strip_suffix(b"\\r")\n            .ok_or(ContentLengthError::Invalid)?', '.strip_suffix(b"\\r")\n            .unwrap_or(&rest[..lf])'),
    (
        "bare CR allowed",
        "if line.contains(&b'\\r') {",
        "if false {",
    ),
    ("name need not be a token", "if !is_token(name) {", "if false {"),
    ("empty name is a token", "!name.is_empty()\n        && name", "name"),
    (
        "a line with no colon is skipped",
        "let colon = colon.ok_or(ContentLengthError::Invalid)?;",
        "let Some(colon) = colon else { continue };",
    ),
    (
        "a fold of this field allowed",
        "if previous != Previous::Field || reads_as_this_field {",
        "if previous == Previous::Nothing || reads_as_this_field {",
    ),
    (
        "a fold after no field allowed",
        "if previous != Previous::Field || reads_as_this_field {",
        "if previous == Previous::ContentLength || reads_as_this_field {",
    ),
    (
        "an indented field allowed",
        "if previous != Previous::Field || reads_as_this_field {",
        "if previous != Previous::Field {",
    ),
    (
        "a fold of another field after this one rejected",
        "        previous = Previous::Field;\n        if name",
        "        if name",
    ),
    ("a head needs no CR", 'head[..lf].strip_suffix(b"\\r").ok_or(HeadError::Invalid)?', 'head[..lf].strip_suffix(b"\\r").unwrap_or(&head[..lf])'),
    ("method need not be a token", "!is_token(method) || ", ""),
    ("target not checked", "!is_request_target(path) || ", ""),
    ("target may be empty", "!t.is_empty() && t.iter()", "t.iter()"),
    ("target may hold a control", "b > b' ' && b != 0x7f", "b != b' '"),
    ("version not checked", " || !is_http_version(version)", ""),
    ("version may be two digits", "major.is_ascii_digit() && minor.is_ascii_digit()", "major.is_ascii_digit()"),
    ("a fourth word allowed", "(parts.next(), parts.next(), parts.next(), parts.next())", "(parts.next(), parts.next(), parts.next(), None::<&[u8]>)"),
    ("fields start at the line feed", "&head[lf + 1..],", "&head[lf..],"),
    ("no OWS trimmed", "parse_digits(trim_ows(value))", "parse_digits(value)"),
    ("only leading OWS trimmed", "while let [rest @ .., last] = v {", "while let [rest @ .., last] = &v[..0] {"),
]


def main() -> int:
    extra = sys.argv[1:]
    if extra not in ([], ["--release"]):
        print(__doc__, file=sys.stderr)
        return 2
    original = SOURCE.read_text(encoding="utf-8")
    bad = []
    try:
        for name, old, new in MUTANTS:
            if original.count(old) != 1:
                bad.append(name)
                print(f"NOT APPLIED  {name}", flush=True)
                continue
            SOURCE.write_text(original.replace(old, new), encoding="utf-8")
            done = subprocess.run(
                COMMAND + extra, cwd=ROOT, capture_output=True, text=True, check=False
            )
            output = done.stdout + done.stderr
            if "could not compile" in output:
                bad.append(name)
                print(f"BROKEN       {name}", flush=True)
            elif done.returncode != 0 and FAILED.search(output):
                print(f"red          {name}", flush=True)
            else:
                bad.append(name)
                print(f"SURVIVED     {name} (rc {done.returncode})", flush=True)
    finally:
        SOURCE.write_text(original, encoding="utf-8")
    print(f"{len(MUTANTS) - len(bad)} of {len(MUTANTS)} red")
    return 1 if bad or not MUTANTS else 0


if __name__ == "__main__":
    sys.exit(main())
