//! Minimal HTTP/1.x header parser (method / target / Content-Length / header end)
//!
//! Pure byte-slice parsing with no OS dependency, so it is available in `no_std`
//! builds. The zero-copy forwarding layer (`splice` / `sendfile`, `std` + libc)
//! lives in [`crate::routing`] and re-exports these types for compatibility.

// ============================================================================
// Header Parser (minimal, for routing decisions)
// ============================================================================

/// HTTP method
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Patch,
    Head,
    Options,
    Connect,
    Trace,
    Unknown,
}

impl HttpMethod {
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"GET" => Self::Get,
            b"POST" => Self::Post,
            b"PUT" => Self::Put,
            b"DELETE" => Self::Delete,
            b"PATCH" => Self::Patch,
            b"HEAD" => Self::Head,
            b"OPTIONS" => Self::Options,
            b"CONNECT" => Self::Connect,
            b"TRACE" => Self::Trace,
            _ => Self::Unknown,
        }
    }
}

/// Parsed HTTP request line (minimal parsing for routing)
#[derive(Debug)]
pub struct RequestLine<'a> {
    pub method: HttpMethod,
    pub path: &'a [u8],
    pub version: &'a [u8],
}

/// Parse just the request line for routing (no body parsing)
///
/// Returns (`RequestLine`, `header_end_offset`) or None if incomplete
#[must_use]
pub fn parse_request_line(buf: &[u8]) -> Option<(RequestLine<'_>, usize)> {
    // Find first line ending
    let line_end = buf.iter().position(|&b| b == b'\r' || b == b'\n')?;
    let line = &buf[..line_end];

    // Split by spaces: METHOD PATH VERSION
    let mut parts = line.splitn(3, |&b| b == b' ');

    let method_bytes = parts.next()?;
    let path = parts.next()?;
    let version = parts.next()?;

    Some((
        RequestLine {
            method: HttpMethod::from_bytes(method_bytes),
            path,
            version,
        },
        line_end,
    ))
}

/// Why a header section has no usable `Content-Length`
///
/// Every variant means the message framing is unknown, so a caller must not read a body by
/// guessing a length: RFC 9112 §6.3 makes an invalid `Content-Length` an unrecoverable error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ContentLengthError {
    /// The value is not `1*DIGIT`, or the line it is on breaks the field-line grammar
    Invalid,
    /// The value is `1*DIGIT` and larger than `usize::MAX`
    Overflow,
    /// The field appears more than once
    Duplicate,
    /// The input ends before the empty line that ends the header section
    Incomplete,
}

impl core::fmt::Display for ContentLengthError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid Content-Length or field line",
            Self::Overflow => "Content-Length larger than usize::MAX",
            Self::Duplicate => "more than one Content-Length",
            Self::Incomplete => "header section has no end",
        })
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ContentLengthError {}

/// The field name, compared without regard to case (RFC 9110 §5.1)
const CONTENT_LENGTH: &[u8] = b"content-length";

const fn is_ows(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

fn trim_ows(mut v: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = v {
        if !is_ows(*first) {
            break;
        }
        v = rest;
    }
    while let [rest @ .., last] = v {
        if !is_ows(*last) {
            break;
        }
        v = rest;
    }
    v
}

/// `1*DIGIT` as a `usize`
fn parse_digits(value: &[u8]) -> Result<usize, ContentLengthError> {
    if value.is_empty() || !value.iter().all(u8::is_ascii_digit) {
        return Err(ContentLengthError::Invalid);
    }
    let mut n = 0usize;
    for &digit in value {
        n = n
            .checked_mul(10)
            .and_then(|n| n.checked_add(usize::from(digit - b'0')))
            .ok_or(ContentLengthError::Overflow)?;
    }
    Ok(n)
}

/// The value of the `Content-Length` field of a header section
///
/// `headers` holds the section with or without its request line, through the empty line that ends
/// it: `&buf[..find_header_end(buf)?]`, or a longer slice, since nothing after that line is read.
///
/// `Ok(None)` means the section is complete and has no such field; `Err` means the framing cannot be
/// known from this input. The grammar is RFC 9112 §5 with `Content-Length = 1*DIGIT` (RFC 9110 §8.6):
///
/// - the name is matched at the start of a line, in any case, and only as a whole field name
/// - the value may have spaces and tabs around it, and is otherwise only digits, up to `usize::MAX`
/// - a repeated field is rejected even when the values are equal. RFC 9110 §8.6 allows merging
///   equal values or rejecting; rejecting leaves no case in which two readers of one message differ
/// - lines end in CRLF: a bare CR or LF is rejected, like `find_header_end`, which looks for CRLF
///   only (RFC 9112 §2.2 lets a recipient accept a bare LF, and does not require it)
/// - whitespace before the colon, or a folded line that continues or looks like this field, is rejected
///
/// This is one part of message framing. A caller must still handle `Transfer-Encoding`, which
/// overrides `Content-Length` (RFC 9112 §6.3); this function does not read it.
///
/// # Errors
///
/// See [`ContentLengthError`].
pub fn find_content_length(headers: &[u8]) -> Result<Option<usize>, ContentLengthError> {
    let mut found = None;
    let mut rest = headers;
    let mut at_start = true;
    let mut after_content_length = false;
    loop {
        let lf = rest
            .iter()
            .position(|&b| b == b'\n')
            .ok_or(ContentLengthError::Incomplete)?;
        let (line, next) = (&rest[..lf], &rest[lf + 1..]);
        rest = next;
        let line = line
            .strip_suffix(b"\r")
            .ok_or(ContentLengthError::Invalid)?;
        if line.contains(&b'\r') {
            return Err(ContentLengthError::Invalid);
        }
        if line.is_empty() {
            // an empty line before the request line is ignored (RFC 9112 §2.2)
            if at_start && !rest.is_empty() {
                continue;
            }
            return Ok(found);
        }
        at_start = false;

        let name_end = line.iter().position(|&b| b == b':');
        let (name, value) = match name_end {
            Some(colon) => (&line[..colon], &line[colon + 1..]),
            None => (line, &line[line.len()..]),
        };
        let bare_name = trim_ows(name);

        if is_ows(line[0]) {
            // a folded line (RFC 9112 §5.2): part of the field before it, unless that is this
            // field or the line reads as this field
            if after_content_length || bare_name.eq_ignore_ascii_case(CONTENT_LENGTH) {
                return Err(ContentLengthError::Invalid);
            }
            continue;
        }
        after_content_length = false;

        if name_end.is_some() && bare_name.eq_ignore_ascii_case(CONTENT_LENGTH) {
            if name.len() != bare_name.len() {
                return Err(ContentLengthError::Invalid);
            }
            if found.is_some() {
                return Err(ContentLengthError::Duplicate);
            }
            found = Some(parse_digits(trim_ows(value))?);
            after_content_length = true;
        }
    }
}

/// Find header end (double CRLF)
#[must_use]
pub fn find_header_end(buf: &[u8]) -> Option<usize> {
    for i in 0..buf.len().saturating_sub(3) {
        if &buf[i..i + 4] == b"\r\n\r\n" {
            return Some(i + 4);
        }
    }
    None
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_request_line() {
        let buf = b"GET /api/users HTTP/1.1\r\nHost: example.com\r\n\r\n";

        let (req, offset) = parse_request_line(buf).unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, b"/api/users");
        assert_eq!(req.version, b"HTTP/1.1");
        assert_eq!(offset, 23);
    }

    #[test]
    fn test_find_content_length() {
        let headers = b"Host: example.com\r\nContent-Length: 42\r\nAccept: */*\r\n\r\n";
        assert_eq!(find_content_length(headers), Ok(Some(42)));

        let no_cl = b"Host: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(find_content_length(no_cl), Ok(None));
    }

    #[test]
    fn test_find_header_end() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nbody";
        assert_eq!(find_header_end(buf), Some(27));

        let incomplete = b"GET / HTTP/1.1\r\nHost: x\r\n";
        assert_eq!(find_header_end(incomplete), None);
    }

    #[test]
    fn test_http_methods() {
        assert_eq!(HttpMethod::from_bytes(b"GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_bytes(b"POST"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_bytes(b"INVALID"), HttpMethod::Unknown);
    }

    #[test]
    fn test_all_http_methods() {
        assert_eq!(HttpMethod::from_bytes(b"GET"), HttpMethod::Get);
        assert_eq!(HttpMethod::from_bytes(b"POST"), HttpMethod::Post);
        assert_eq!(HttpMethod::from_bytes(b"PUT"), HttpMethod::Put);
        assert_eq!(HttpMethod::from_bytes(b"DELETE"), HttpMethod::Delete);
        assert_eq!(HttpMethod::from_bytes(b"PATCH"), HttpMethod::Patch);
        assert_eq!(HttpMethod::from_bytes(b"HEAD"), HttpMethod::Head);
        assert_eq!(HttpMethod::from_bytes(b"OPTIONS"), HttpMethod::Options);
        assert_eq!(HttpMethod::from_bytes(b"CONNECT"), HttpMethod::Connect);
        assert_eq!(HttpMethod::from_bytes(b"TRACE"), HttpMethod::Trace);
        assert_eq!(HttpMethod::from_bytes(b""), HttpMethod::Unknown);
        assert_eq!(HttpMethod::from_bytes(b"get"), HttpMethod::Unknown); // case-sensitive
    }

    #[test]
    fn test_http_method_equality() {
        assert_eq!(HttpMethod::Get, HttpMethod::Get);
        assert_ne!(HttpMethod::Get, HttpMethod::Post);
        assert_ne!(HttpMethod::Post, HttpMethod::Put);
    }

    #[test]
    fn test_parse_request_line_post() {
        let buf = b"POST /submit HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        let (req, offset) = parse_request_line(buf).unwrap();
        assert_eq!(req.method, HttpMethod::Post);
        assert_eq!(req.path, b"/submit");
        assert_eq!(req.version, b"HTTP/1.1");
        assert_eq!(offset, 21); // "POST /submit HTTP/1.1" length
    }

    #[test]
    fn test_parse_request_line_root_path() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        let (req, _) = parse_request_line(buf).unwrap();
        assert_eq!(req.method, HttpMethod::Get);
        assert_eq!(req.path, b"/");
    }

    #[test]
    fn test_parse_request_line_incomplete() {
        // No newline — incomplete request
        let buf = b"GET /path";
        let result = parse_request_line(buf);
        // No \r or \n in the path portion — parse_request_line looks for \r or \n
        // It should still parse if there's any \r/\n in the buffer
        // Actually, "GET /path" has no \r or \n so it returns None
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_request_line_lf_only() {
        // LF without CR is also valid for line_end detection
        let buf = b"DELETE /resource HTTP/1.1\nHost: x\r\n\r\n";
        let (req, offset) = parse_request_line(buf).unwrap();
        assert_eq!(req.method, HttpMethod::Delete);
        assert_eq!(req.path, b"/resource");
        assert_eq!(req.version, b"HTTP/1.1");
        assert_eq!(offset, 25); // "DELETE /resource HTTP/1.1" length
    }

    #[test]
    fn test_find_content_length_large_value() {
        let headers = b"Content-Length: 1048576\r\n\r\n";
        assert_eq!(find_content_length(headers), Ok(Some(1_048_576)));
    }

    #[test]
    fn test_find_content_length_zero() {
        let headers = b"Content-Length: 0\r\n\r\n";
        assert_eq!(find_content_length(headers), Ok(Some(0)));
    }

    #[test]
    fn test_find_content_length_lowercase() {
        let headers = b"content-length: 512\r\n\r\n";
        assert_eq!(find_content_length(headers), Ok(Some(512)));
    }

    #[test]
    fn test_find_content_length_with_spaces() {
        // Leading space after colon
        let headers = b"Content-Length:   100\r\n\r\n";
        assert_eq!(find_content_length(headers), Ok(Some(100)));
    }

    #[test]
    fn test_find_header_end_body_preserved() {
        let buf = b"GET / HTTP/1.1\r\nHost: x\r\n\r\nHELLO BODY";
        let end = find_header_end(buf).unwrap();
        // Body starts at end
        assert_eq!(&buf[end..], b"HELLO BODY");
    }

    #[test]
    fn test_find_header_end_empty_headers() {
        // Minimal: just \r\n\r\n
        let buf = b"\r\n\r\n";
        assert_eq!(find_header_end(buf), Some(4));
    }

    #[test]
    fn test_find_header_end_not_found() {
        let buf = b"GET / HTTP/1.1\r\n";
        assert_eq!(find_header_end(buf), None);

        let buf2 = b"";
        assert_eq!(find_header_end(buf2), None);
    }
}
