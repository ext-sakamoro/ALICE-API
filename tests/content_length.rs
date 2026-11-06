//! `find_content_length` and `split_message_head` against the grammar of RFC 9110 / RFC 9112.
//!
//! oracle: the expected column is written from the RFCs, not from the code. References:
//! - RFC 9110 §8.6: `Content-Length = 1*DIGIT`; a list or repeated field MAY be rejected
//! - RFC 9112 §5: `field-line = field-name ":" OWS field-value OWS`, `OWS = *( SP / HTAB )`
//! - RFC 9112 §5.1: no whitespace between the field name and the colon
//! - RFC 9112 §5.2: a line folded with leading whitespace is obsolete and may be rejected
//! - RFC 9112 §2.2: lines end in CRLF; a bare CR is invalid; a bare LF MAY be recognised, and is not
//!   here (`find_header_end` looks for CRLF CRLF only); whitespace before the first field is rejected
//! - RFC 9112 §3: `request-line = method SP request-target SP HTTP-version`;
//!   `HTTP-version = "HTTP/" DIGIT "." DIGIT`; RFC 9110 §9.1: `method = token`
//! - RFC 9110 §5.1: `field-name = token`; RFC 9112 §5: a field line has a colon
//! - RFC 9112 §6.3: an invalid Content-Length is an unrecoverable framing error
//! - RFC 9110 §5.1: field names are case-insensitive
//!
//! `find_content_length` takes one input: a field section, from its first field line through the
//! empty line that ends it. It does not guess whether a request line comes first, so a request line
//! there is a line that is not a field line. `\r\n` is the empty section; anything else that starts
//! with CRLF is rejected, since what follows an empty line is a body or the next message. RFC 9112
//! §2.2 says a server SHOULD ignore an empty line before a request line; `split_message_head` does
//! not, since a parser that skips one can be made to read past the end of a section. A caller
//! holding a whole head uses `split_message_head` to get the field section.
//!
//! `usize` is the limit of the value: `usize::MAX` parses and one more is an overflow. On a
//! 64-bit target those are 2^64-1 and 2^64 (written out in `limit_of_a_64_bit_usize`).
//!
//! The bug this pins differed by profile (a panic with overflow checks, a wrapped length without
//! them), so CI runs this file in debug and in release.

use alice_api::http::{
    find_content_length, find_header_end, split_message_head, ContentLengthError, HeadError,
    HttpMethod,
};
use ContentLengthError::{Duplicate, Incomplete, Invalid, Overflow};

type Expected = Result<Option<usize>, ContentLengthError>;

const TABLE: &[(&str, &[u8], Expected)] = &[
    // absent
    ("no field", b"Host: a\r\n\r\n", Ok(None)),
    ("no field at all", b"\r\n", Ok(None)),
    (
        "request line, no field",
        b"POST / HTTP/1.1\r\nHost: a\r\n\r\n",
        Err(Invalid),
    ),
    // valid
    ("plain", b"Content-Length: 42\r\n\r\n", Ok(Some(42))),
    ("zero", b"Content-Length: 0\r\n\r\n", Ok(Some(0))),
    (
        "among others",
        b"Host: a\r\nContent-Length: 42\r\nAccept: b\r\n\r\n",
        Ok(Some(42)),
    ),
    (
        "after a request line",
        b"POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n",
        Err(Invalid),
    ),
    (
        "leading zeros are 1*DIGIT",
        b"Content-Length: 007\r\n\r\n",
        Ok(Some(7)),
    ),
    // OWS around the value
    ("no whitespace", b"Content-Length:42\r\n\r\n", Ok(Some(42))),
    (
        "many spaces before",
        b"Content-Length:   42\r\n\r\n",
        Ok(Some(42)),
    ),
    ("tab before", b"Content-Length:\t42\r\n\r\n", Ok(Some(42))),
    (
        "spaces after",
        b"Content-Length: 42  \r\n\r\n",
        Ok(Some(42)),
    ),
    ("tab after", b"Content-Length: 42\t\r\n\r\n", Ok(Some(42))),
    // whitespace the grammar does not allow
    (
        "space before the colon",
        b"Content-Length : 42\r\n\r\n",
        Err(Invalid),
    ),
    (
        "tab before the colon",
        b"Content-Length\t: 42\r\n\r\n",
        Err(Invalid),
    ),
    (
        "space inside the value",
        b"Content-Length: 4 2\r\n\r\n",
        Err(Invalid),
    ),
    (
        "vertical tab is not OWS",
        b"Content-Length:\x0b42\r\n\r\n",
        Err(Invalid),
    ),
    // value that is not 1*DIGIT
    (
        "digits then letters",
        b"Content-Length: 12abc\r\n\r\n",
        Err(Invalid),
    ),
    ("empty", b"Content-Length:\r\n\r\n", Err(Invalid)),
    (
        "only whitespace",
        b"Content-Length:   \r\n\r\n",
        Err(Invalid),
    ),
    ("minus", b"Content-Length: -5\r\n\r\n", Err(Invalid)),
    ("plus", b"Content-Length: +5\r\n\r\n", Err(Invalid)),
    ("hex", b"Content-Length: 0x10\r\n\r\n", Err(Invalid)),
    ("fraction", b"Content-Length: 1.5\r\n\r\n", Err(Invalid)),
    (
        "a list of the same value",
        b"Content-Length: 42, 42\r\n\r\n",
        Err(Invalid),
    ),
    // case of the name
    ("lower", b"content-length: 5\r\n\r\n", Ok(Some(5))),
    ("upper", b"CONTENT-LENGTH: 5\r\n\r\n", Ok(Some(5))),
    ("mixed", b"cOnTeNt-LeNgTh: 5\r\n\r\n", Ok(Some(5))),
    ("upper, invalid", b"CONTENT-LENGTH: x\r\n\r\n", Err(Invalid)),
    // repeated: rejected, equal or not (the RFC allows rejecting or merging equal values)
    (
        "duplicates equal",
        b"Content-Length: 5\r\nContent-Length: 5\r\n\r\n",
        Err(Duplicate),
    ),
    (
        "duplicates conflicting",
        b"Content-Length: 5\r\nContent-Length: 6\r\n\r\n",
        Err(Duplicate),
    ),
    (
        "duplicates, other case",
        b"Content-Length: 5\r\ncontent-length: 5\r\n\r\n",
        Err(Duplicate),
    ),
    (
        "duplicates apart",
        b"Content-Length: 5\r\nHost: a\r\nContent-Length: 6\r\n\r\n",
        Err(Duplicate),
    ),
    // the name where it is not a field name
    (
        "in another value",
        b"X-Note: Content-Length: 5\r\n\r\n",
        Ok(None),
    ),
    (
        "as a suffix of a name",
        b"X-Content-Length: 5\r\n\r\n",
        Ok(None),
    ),
    (
        "as a prefix of a name",
        b"Content-Length-X: 5\r\n\r\n",
        Ok(None),
    ),
    (
        "in a request target",
        b"GET /Content-Length:5 HTTP/1.1\r\n\r\n",
        Err(Invalid),
    ),
    (
        "in a value before the field",
        b"X-Note: Content-Length: 9\r\nContent-Length: 5\r\n\r\n",
        Ok(Some(5)),
    ),
    (
        "in the body",
        b"Host: a\r\n\r\nContent-Length: 5\r\n\r\n",
        Ok(None),
    ),
    (
        "in the body, after the field",
        b"Content-Length: 5\r\n\r\nContent-Length: 6\r\n\r\n",
        Ok(Some(5)),
    ),
    // a request line is not a field line: this function does not read a whole head
    (
        "a value that ends like a request line",
        b"Content-Length: 5 HTTP/1.1\r\n\r\n",
        Err(Invalid),
    ),
    (
        "a NUL in a request line",
        b"G\x00T / HTTP/1.1\r\n\r\n",
        Err(Invalid),
    ),
    (
        "a request line with no version",
        b"GET / HTTP/\r\n\r\n",
        Err(Invalid),
    ),
    // anything else that starts with CRLF: after an empty line comes a body or the next message
    (
        "whole message, next message follows",
        b"GET / HTTP/1.1\r\n\r\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "whole message, next request follows",
        b"GET / HTTP/1.1\r\n\r\nGET /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "from the end of the request line",
        b"\r\n\r\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "after the end of the request line",
        b"\r\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "next request after the end of the request line",
        b"\r\nGET /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    ("two empty lines", b"\r\n\r\n", Err(Invalid)),
    // malformed field lines
    (
        "a request line after a field",
        b"Host: a\r\nGET / HTTP/1.1\r\n\r\n",
        Err(Invalid),
    ),
    (
        "a second request line",
        b"GET / HTTP/1.1\r\nGET /x HTTP/1.1\r\n\r\n",
        Err(Invalid),
    ),
    (
        "the name and a value, first line",
        b"Content-Length 5\r\n\r\n",
        Err(Invalid),
    ),
    ("two words, first line", b"GET /\r\n\r\n", Err(Invalid)),
    (
        "the name with no colon",
        b"Content-Length\r\n\r\n",
        Err(Invalid),
    ),
    (
        "the name with no colon, later",
        b"Host: a\r\nContent-Length\r\n\r\n",
        Err(Invalid),
    ),
    (
        "the name and a value with no colon",
        b"Host: a\r\nContent-Length 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "other line with no colon",
        b"Host: a\r\nnot a field\r\n\r\n",
        Err(Invalid),
    ),
    (
        "vertical tab in the name",
        b"Content-Length\x0b: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "NUL in the name",
        b"Content\x00-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "NUL in the name, later",
        b"Host: a\r\nContent-Length\x00: 5\r\n\r\n",
        Err(Invalid),
    ),
    ("empty name", b"Host: a\r\n: 5\r\n\r\n", Err(Invalid)),
    (
        "space inside another name",
        b"Host: a\r\nX Y: 5\r\n\r\n",
        Err(Invalid),
    ),
    // no header terminator: the value or a later field may not have arrived
    ("empty input", b"", Err(Incomplete)),
    ("no terminator, no field", b"Host: a\r\n", Err(Incomplete)),
    (
        "no terminator after the field",
        b"Content-Length: 5\r\n",
        Err(Incomplete),
    ),
    (
        "cut inside the value",
        b"Content-Length: 5",
        Err(Incomplete),
    ),
    ("cut inside the name", b"Content-Le", Err(Incomplete)),
    (
        "cut before the last LF",
        b"Content-Length: 5\r\n\r",
        Err(Incomplete),
    ),
    // line endings other than CRLF
    (
        "bare LF after the field",
        b"Content-Length: 5\n\r\n",
        Err(Invalid),
    ),
    (
        "bare LF hides a field",
        b"X-Note: a\nContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "bare LF as the terminator",
        b"Content-Length: 5\r\n\n",
        Err(Invalid),
    ),
    (
        "bare CR hides a field",
        b"X-Note: a\rContent-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "bare CR after the value",
        b"Content-Length: 5\r\r\n\r\n",
        Err(Invalid),
    ),
    // a folded line
    (
        "value folded onto the next line",
        b"Content-Length: 5\r\n 6\r\n\r\n",
        Err(Invalid),
    ),
    (
        "value on the folded line",
        b"Content-Length:\r\n\t5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "indented field",
        b"Host: a\r\n Content-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "other field folded after this one",
        b"Content-Length: 5\r\nHost: a\r\n b\r\n\r\n",
        Ok(Some(5)),
    ),
    (
        "whitespace before the first line",
        b" Content-Length: 5\r\n\r\n",
        Err(Invalid),
    ),
    (
        "whitespace before another first line",
        b" Host: a\r\n\r\n",
        Err(Invalid),
    ),
    (
        "whitespace after the request line",
        b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
        Err(Invalid),
    ),
    (
        "other field folded",
        b"Host: a\r\n b\r\nContent-Length: 5\r\n\r\n",
        Ok(Some(5)),
    ),
];

#[test]
fn every_row_of_the_table() {
    assert!(TABLE.len() >= 50, "compared {}", TABLE.len());
    let mut wrong = 0;
    for (name, input, expected) in TABLE {
        let got = find_content_length(input);
        if got != *expected {
            wrong += 1;
            eprintln!(
                "{name}: {:?}: got {got:?}, expected {expected:?}",
                String::from_utf8_lossy(input)
            );
        }
    }
    assert_eq!(wrong, 0, "{wrong} of {} rows differ", TABLE.len());
}

fn field(value: &str) -> Vec<u8> {
    format!("Content-Length: {value}\r\n\r\n").into_bytes()
}

#[test]
fn the_limit_of_usize() {
    let max = usize::MAX as u128;
    assert_eq!(
        find_content_length(&field(&max.to_string())),
        Ok(Some(usize::MAX))
    );
    assert_eq!(
        find_content_length(&field(&(max + 1).to_string())),
        Err(Overflow)
    );
    // the multiplication stays in range and the addition leaves it
    let top = max / 10 * 10 + 9;
    assert!(top > max, "usize::MAX does not end below 9");
    assert_eq!(find_content_length(&field(&top.to_string())), Err(Overflow));
    // the multiplication leaves the range
    assert_eq!(
        find_content_length(&field(&format!("{max}0"))),
        Err(Overflow)
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn limit_of_a_64_bit_usize() {
    let parse = |v: &str| find_content_length(&field(v));
    assert_eq!(parse("18446744073709551615"), Ok(Some(usize::MAX)));
    assert_eq!(parse("18446744073709551616"), Err(Overflow));
    // 2^64 + 1 is the value that used to read as 1 without overflow checks
    assert_eq!(parse("18446744073709551617"), Err(Overflow));
}

#[test]
fn the_input_of_the_fuzz_crash() {
    // the scheduled fuzz run's input: a stray byte, the name, 72 digits, a letter
    let mut input = b"\xf6Content-Length:".to_vec();
    input.extend_from_slice(&[b'1'; 72]);
    input.push(b'X');
    assert_eq!(input.len(), 89);
    // the name is not at the start of a line and there is no line end
    assert_eq!(find_content_length(&input), Err(Incomplete));
    // the same digits as a field
    assert_eq!(find_content_length(&field(&"1".repeat(72))), Err(Overflow));
}

#[test]
fn leading_zeros_do_not_overflow() {
    let many = format!("{}5", "0".repeat(100));
    assert_eq!(find_content_length(&field(&many)), Ok(Some(5)));
}

/// Method, target and version of a head, and the field section after it.
type Head = (HttpMethod, &'static [u8], &'static [u8], &'static [u8]);

fn split(head: &'static [u8]) -> Result<Head, HeadError> {
    split_message_head(head).map(|(line, fields)| (line.method, line.path, line.version, fields))
}

const GET: HttpMethod = HttpMethod::Get;

#[test]
fn splitting_a_head() {
    let good: &[(&[u8], Head)] = &[
        (b"GET / HTTP/1.1\r\n\r\n", (GET, b"/", b"HTTP/1.1", b"\r\n")),
        (
            b"GET /a:b?c=d HTTP/1.0\r\nHost: a\r\n\r\n",
            (GET, b"/a:b?c=d", b"HTTP/1.0", b"Host: a\r\n\r\n"),
        ),
        (
            b"BREW / HTTP/9.9\r\n",
            (HttpMethod::Unknown, b"/", b"HTTP/9.9", b""),
        ),
        (
            b"POST * HTTP/1.1\r\nbody",
            (HttpMethod::Post, b"*", b"HTTP/1.1", b"body"),
        ),
    ];
    for (head, expected) in good {
        assert_eq!(
            split(head).as_ref(),
            Ok(expected),
            "{}",
            String::from_utf8_lossy(head)
        );
    }
    let bad: &[(&[u8], HeadError)] = &[
        (b"", HeadError::Incomplete),
        (b"GET / HTTP/1.1", HeadError::Incomplete),
        (b"GET / HTTP/1.1\r", HeadError::Incomplete),
        (b"\r\nGET / HTTP/1.1\r\n", HeadError::Invalid),
        (b"\r\n", HeadError::Invalid),
        (b"GET / HTTP/1.1\n", HeadError::Invalid),
        (b"GET / HTTP/1.1\r\r\n", HeadError::Invalid),
        (b"Content-Length: 5 HTTP/1.1\r\n", HeadError::Invalid),
        (b"G\x00T / HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET / HTTP/\r\n", HeadError::Invalid),
        (b"GET / HTTP/1\r\n", HeadError::Invalid),
        (b"GET / HTTP/1.\r\n", HeadError::Invalid),
        (b"GET / HTTP/1.1.1\r\n", HeadError::Invalid),
        (b"GET / HTTP/a.b\r\n", HeadError::Invalid),
        (b"GET / http/1.1\r\n", HeadError::Invalid),
        (b"GET /\r\n", HeadError::Invalid),
        (b"GET\r\n", HeadError::Invalid),
        (b"GET  / HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET /  HTTP/1.1\r\n", HeadError::Invalid),
        (b" GET / HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET / HTTP/1.1 \r\n", HeadError::Invalid),
        (b"GET / x HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET /\x00 HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET /\t HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET\t/ HTTP/1.1\r\n", HeadError::Invalid),
        (b" / HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET  HTTP/1.1\r\n", HeadError::Invalid),
        (b"GET / HTTP/1.a\r\n", HeadError::Invalid),
        (b"GET / HTTP/a.1\r\n", HeadError::Invalid),
    ];
    assert!(bad.len() >= 25, "compared {}", bad.len());
    for (head, expected) in bad {
        assert_eq!(
            split(head).err(),
            Some(*expected),
            "{}",
            String::from_utf8_lossy(head)
        );
    }
}

/// A whole buffer, the way a caller holds it: cut at the end of the head, then split, then read.
fn through_the_head(buf: &[u8]) -> Expected {
    let end = find_header_end(buf).ok_or(Incomplete)?;
    let (_, fields) = split_message_head(&buf[..end]).map_err(|_| Invalid)?;
    find_content_length(fields)
}

#[test]
fn a_whole_buffer_through_the_head() {
    let rows: &[(&str, &[u8], Expected)] = &[
        ("no field", b"GET / HTTP/1.1\r\n\r\n", Ok(None)),
        (
            "field",
            b"POST / HTTP/1.1\r\nContent-Length: 42\r\n\r\n",
            Ok(Some(42)),
        ),
        (
            "next message is not read",
            b"GET / HTTP/1.1\r\n\r\nContent-Length: 5\r\n\r\n",
            Ok(None),
        ),
        (
            "next request is not read",
            b"GET / HTTP/1.1\r\n\r\nGET /x HTTP/1.1\r\nContent-Length: 5\r\n\r\n",
            Ok(None),
        ),
        (
            "body is not read",
            b"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nContent-Length: 6\r\n\r\n",
            Ok(Some(5)),
        ),
        (
            "a value that ends like a request line",
            b"POST / HTTP/1.1\r\nContent-Length: 5 HTTP/1.1\r\n\r\n",
            Err(Invalid),
        ),
        (
            "not a head",
            b"Content-Length: 5 HTTP/1.1\r\n\r\n",
            Err(Invalid),
        ),
        (
            "a second request line among the fields",
            b"GET / HTTP/1.1\r\nGET /x HTTP/1.1\r\n\r\n",
            Err(Invalid),
        ),
        (
            "folded onto the request line",
            b"GET / HTTP/1.1\r\n Host: a\r\n\r\n",
            Err(Invalid),
        ),
        (
            "no end of the head",
            b"GET / HTTP/1.1\r\nHost: a\r\n",
            Err(Incomplete),
        ),
    ];
    for (name, buf, expected) in rows {
        assert_eq!(through_the_head(buf), *expected, "{name}");
    }
    // a slice cut after the request line is a field section
    let buf = b"POST / HTTP/1.1\r\nContent-Length: 5 HTTP/1.1\r\n\r\n";
    let (_, fields) = split_message_head(buf).unwrap();
    assert_eq!(find_content_length(fields), Err(Invalid));
}
