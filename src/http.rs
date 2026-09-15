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

/// Find Content-Length header value
#[must_use]
pub fn find_content_length(headers: &[u8]) -> Option<usize> {
    // Simple linear search for "Content-Length: "
    const NEEDLE: &[u8] = b"Content-Length:";

    let mut i = 0;
    while i + NEEDLE.len() < headers.len() {
        if headers[i..].starts_with(NEEDLE) || headers[i..].starts_with(b"content-length:") {
            // Find value start (skip whitespace)
            let value_start = i + NEEDLE.len();
            let mut j = value_start;
            while j < headers.len() && headers[j] == b' ' {
                j += 1;
            }

            // Parse number
            let mut value = 0usize;
            while j < headers.len() && headers[j].is_ascii_digit() {
                value = value * 10 + (headers[j] - b'0') as usize;
                j += 1;
            }

            return Some(value);
        }
        i += 1;
    }

    None
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
        assert_eq!(find_content_length(headers), Some(42));

        let no_cl = b"Host: example.com\r\nAccept: */*\r\n\r\n";
        assert_eq!(find_content_length(no_cl), None);
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
        assert_eq!(find_content_length(headers), Some(1_048_576));
    }

    #[test]
    fn test_find_content_length_zero() {
        let headers = b"Content-Length: 0\r\n\r\n";
        assert_eq!(find_content_length(headers), Some(0));
    }

    #[test]
    fn test_find_content_length_lowercase() {
        // The implementation also checks lowercase "content-length:"
        let headers = b"content-length: 512\r\n\r\n";
        assert_eq!(find_content_length(headers), Some(512));
    }

    #[test]
    fn test_find_content_length_with_spaces() {
        // Leading space after colon
        let headers = b"Content-Length:   100\r\n\r\n";
        assert_eq!(find_content_length(headers), Some(100));
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
