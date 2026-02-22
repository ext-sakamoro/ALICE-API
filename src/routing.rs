//! Zero-Copy Routing
//!
//! Efficient request forwarding using Linux splice(2) and sendfile(2) syscalls
//! to avoid copying data through userspace.
//!
//! ## Why Zero-Copy?
//!
//! Traditional forwarding: Client → Kernel → Userspace → Kernel → Backend
//! Zero-copy forwarding:   Client → Kernel ─────────────→ Backend
//!
//! Eliminates:
//! - Memory copies (2 per request)
//! - Context switches
//! - CPU cache pollution
//!
//! ## Syscalls Used
//!
//! - `splice(2)`: Move data between file descriptors via pipe (socket→socket)
//! - `sendfile(2)`: Send file to socket (useful for static content)
//! - `tee(2)`: Duplicate pipe data (for logging/inspection without copy)

use core::ffi::c_int;
use core::ptr;

// Re-export libc types for users
pub use libc::{c_void, off_t, size_t, ssize_t};

/// Maximum pipe buffer size (Linux default is 16 pages = 64KB)
pub const PIPE_BUF_SIZE: usize = 65536;

/// Splice flags
pub mod splice_flags {
    use libc::c_uint;

    /// Move pages instead of copying (hint to kernel)
    pub const SPLICE_F_MOVE: c_uint = 1;
    /// Don't block on I/O
    pub const SPLICE_F_NONBLOCK: c_uint = 2;
    /// Expect more data
    pub const SPLICE_F_MORE: c_uint = 4;
    /// Gift pages to destination (advanced)
    pub const SPLICE_F_GIFT: c_uint = 8;
}

// ============================================================================
// Raw Syscall Wrappers
// ============================================================================

/// Result type for splice operations
pub type SpliceResult = Result<usize, SpliceError>;

/// Errors from splice operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpliceError {
    /// Would block (EAGAIN/EWOULDBLOCK)
    WouldBlock,
    /// Bad file descriptor
    BadFd,
    /// Invalid argument
    InvalidArg,
    /// Out of memory
    NoMem,
    /// Broken pipe
    BrokenPipe,
    /// Connection reset
    ConnectionReset,
    /// Generic I/O error
    Io(i32),
}

impl SpliceError {
    #[allow(unreachable_patterns)] // EAGAIN == EWOULDBLOCK on some platforms
    fn from_errno(errno: i32) -> Self {
        match errno {
            libc::EAGAIN | libc::EWOULDBLOCK => SpliceError::WouldBlock,
            libc::EBADF => SpliceError::BadFd,
            libc::EINVAL => SpliceError::InvalidArg,
            libc::ENOMEM => SpliceError::NoMem,
            libc::EPIPE => SpliceError::BrokenPipe,
            libc::ECONNRESET => SpliceError::ConnectionReset,
            e => SpliceError::Io(e),
        }
    }
}

/// Create a pipe for splice operations
///
/// Returns (read_fd, write_fd)
pub fn create_pipe() -> Result<(c_int, c_int), SpliceError> {
    let mut fds: [c_int; 2] = [0; 2];
    let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
    if ret < 0 {
        Err(SpliceError::from_errno(unsafe { *libc::__error() }))
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// Create a pipe with flags (O_NONBLOCK, O_CLOEXEC)
#[cfg(target_os = "linux")]
pub fn create_pipe2(flags: c_int) -> Result<(c_int, c_int), SpliceError> {
    let mut fds: [c_int; 2] = [0; 2];
    let ret = unsafe { libc::pipe2(fds.as_mut_ptr(), flags) };
    if ret < 0 {
        Err(SpliceError::from_errno(unsafe { *libc::__error() }))
    } else {
        Ok((fds[0], fds[1]))
    }
}

/// Close a file descriptor
pub fn close_fd(fd: c_int) {
    unsafe { libc::close(fd) };
}

/// Splice data from one fd to another through a pipe
///
/// # Arguments
/// * `fd_in` - Source file descriptor
/// * `fd_out` - Destination file descriptor
/// * `len` - Maximum bytes to transfer
/// * `flags` - Splice flags
///
/// # Returns
/// Number of bytes transferred, or error
///
/// # Safety
/// Uses raw file descriptors. Caller must ensure fds are valid.
#[cfg(target_os = "linux")]
pub fn splice(
    fd_in: c_int,
    off_in: Option<&mut off_t>,
    fd_out: c_int,
    off_out: Option<&mut off_t>,
    len: size_t,
    flags: libc::c_uint,
) -> SpliceResult {
    let off_in_ptr = off_in.map_or(ptr::null_mut(), |o| o as *mut _);
    let off_out_ptr = off_out.map_or(ptr::null_mut(), |o| o as *mut _);

    let ret = unsafe { libc::splice(fd_in, off_in_ptr, fd_out, off_out_ptr, len, flags) };

    if ret < 0 {
        Err(SpliceError::from_errno(unsafe { *libc::__error() }))
    } else {
        Ok(ret as usize)
    }
}

/// Fallback splice for non-Linux (uses read/write)
#[cfg(not(target_os = "linux"))]
pub fn splice(
    fd_in: c_int,
    _off_in: Option<&mut off_t>,
    fd_out: c_int,
    _off_out: Option<&mut off_t>,
    len: size_t,
    _flags: libc::c_uint,
) -> SpliceResult {
    // Fallback: use a small buffer
    let mut buf = [0u8; 8192];
    let to_read = len.min(buf.len());

    let n_read = unsafe { libc::read(fd_in, buf.as_mut_ptr() as *mut c_void, to_read) };
    if n_read < 0 {
        return Err(SpliceError::from_errno(unsafe { *libc::__error() }));
    }
    if n_read == 0 {
        return Ok(0);
    }

    let n_write = unsafe { libc::write(fd_out, buf.as_ptr() as *const c_void, n_read as usize) };
    if n_write < 0 {
        return Err(SpliceError::from_errno(unsafe { *libc::__error() }));
    }

    Ok(n_write as usize)
}

/// Send file contents directly to a socket
///
/// # Arguments
/// * `out_fd` - Destination socket
/// * `in_fd` - Source file descriptor
/// * `offset` - Starting offset in file (updated after call)
/// * `count` - Bytes to send
pub fn sendfile(
    out_fd: c_int,
    in_fd: c_int,
    offset: Option<&mut off_t>,
    count: size_t,
) -> SpliceResult {
    #[cfg(target_os = "linux")]
    let ret = {
        let off_ptr = offset.map_or(ptr::null_mut(), |o| o as *mut _);
        unsafe { libc::sendfile(out_fd, in_fd, off_ptr, count) }
    };

    #[cfg(target_os = "macos")]
    let ret = {
        // macOS sendfile has different signature
        let mut len = count as off_t;
        let off_val = offset.map_or(0, |o| *o);
        let result =
            unsafe { libc::sendfile(in_fd, out_fd, off_val, &mut len, ptr::null_mut(), 0) };
        if result == 0 || (result == -1 && len > 0) {
            len as ssize_t
        } else {
            -1
        }
    };

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let ret: ssize_t = {
        // Fallback for other platforms
        let _ = (out_fd, in_fd, offset, count); // suppress unused warnings
        -1
    };

    if ret < 0 {
        Err(SpliceError::from_errno(unsafe { *libc::__error() }))
    } else {
        Ok(ret as usize)
    }
}

// ============================================================================
// High-Level Zero-Copy Forwarder
// ============================================================================

/// A reusable pipe pair for zero-copy forwarding
pub struct SplicePipe {
    /// Read end of pipe
    read_fd: c_int,
    /// Write end of pipe
    write_fd: c_int,
}

impl SplicePipe {
    /// Create a new splice pipe
    pub fn new() -> Result<Self, SpliceError> {
        let (read_fd, write_fd) = create_pipe()?;
        Ok(Self { read_fd, write_fd })
    }

    /// Get read fd
    #[inline(always)]
    pub fn read_fd(&self) -> c_int {
        self.read_fd
    }

    /// Get write fd
    #[inline(always)]
    pub fn write_fd(&self) -> c_int {
        self.write_fd
    }
}

impl Drop for SplicePipe {
    fn drop(&mut self) {
        close_fd(self.read_fd);
        close_fd(self.write_fd);
    }
}

impl Default for SplicePipe {
    fn default() -> Self {
        Self::new().expect("Failed to create pipe")
    }
}

/// Zero-copy forwarder for socket-to-socket transfer
pub struct ZeroCopyForwarder {
    /// Pipe for splice operations
    pipe: SplicePipe,
    /// Total bytes forwarded
    bytes_forwarded: u64,
    /// Number of forward operations
    forward_count: u64,
}

impl ZeroCopyForwarder {
    /// Create a new forwarder
    pub fn new() -> Result<Self, SpliceError> {
        Ok(Self {
            pipe: SplicePipe::new()?,
            bytes_forwarded: 0,
            forward_count: 0,
        })
    }

    /// Forward data from client to backend using splice
    ///
    /// # Arguments
    /// * `client_fd` - Client socket file descriptor
    /// * `backend_fd` - Backend socket file descriptor
    /// * `len` - Number of bytes to forward
    ///
    /// # Returns
    /// Number of bytes actually forwarded
    pub fn forward(&mut self, client_fd: c_int, backend_fd: c_int, len: usize) -> SpliceResult {
        let mut total = 0usize;
        let mut remaining = len;

        while remaining > 0 {
            let chunk = remaining.min(PIPE_BUF_SIZE);

            // Client → Pipe
            let n = splice(
                client_fd,
                None,
                self.pipe.write_fd,
                None,
                chunk,
                splice_flags::SPLICE_F_MOVE | splice_flags::SPLICE_F_MORE,
            )?;

            if n == 0 {
                break; // EOF
            }

            // Pipe → Backend
            let mut written = 0;
            while written < n {
                let w = splice(
                    self.pipe.read_fd,
                    None,
                    backend_fd,
                    None,
                    n - written,
                    splice_flags::SPLICE_F_MOVE | splice_flags::SPLICE_F_MORE,
                )?;
                written += w;
            }

            total += n;
            remaining -= n;
        }

        self.bytes_forwarded += total as u64;
        self.forward_count += 1;

        Ok(total)
    }

    /// Forward response from backend to client
    pub fn forward_response(
        &mut self,
        backend_fd: c_int,
        client_fd: c_int,
        len: usize,
    ) -> SpliceResult {
        // Same as forward, but opposite direction
        self.forward(backend_fd, client_fd, len)
    }

    /// Get statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.bytes_forwarded, self.forward_count)
    }
}

impl Default for ZeroCopyForwarder {
    fn default() -> Self {
        Self::new().expect("Failed to create forwarder")
    }
}

// ============================================================================
// Batched Splice Operations
// ============================================================================

/// A pending splice operation for batch execution
#[derive(Debug, Clone, Copy)]
pub struct SpliceOp {
    /// Source file descriptor
    pub fd_in: c_int,
    /// Destination file descriptor
    pub fd_out: c_int,
    /// Bytes to transfer
    pub len: usize,
}

impl SpliceOp {
    pub fn new(fd_in: c_int, fd_out: c_int, len: usize) -> Self {
        Self { fd_in, fd_out, len }
    }
}

/// Result of a batched splice operation
#[derive(Debug, Clone, Copy)]
pub struct SpliceBatchResult {
    /// Total bytes transferred
    pub bytes_transferred: usize,
    /// Number of operations completed
    pub ops_completed: usize,
    /// First error encountered (if any)
    pub error: Option<SpliceError>,
}

/// Batched zero-copy forwarder
///
/// Accumulates splice operations and executes them in a batch to reduce
/// syscall overhead. Falls back to sequential execution on non-Linux.
///
/// # Example
/// ```ignore
/// use alice_api::routing::{BatchedForwarder, SpliceOp};
///
/// let mut batch = BatchedForwarder::new(16).unwrap();
///
/// // Queue operations
/// batch.push(SpliceOp::new(client1_fd, backend1_fd, 1024));
/// batch.push(SpliceOp::new(client2_fd, backend2_fd, 2048));
///
/// // Execute all at once
/// let result = batch.execute();
/// ```
pub struct BatchedForwarder<const MAX_OPS: usize> {
    /// Pending operations
    ops: [Option<SpliceOp>; MAX_OPS],
    /// Number of pending operations
    count: usize,
    /// Shared pipe for transfers
    pipe: SplicePipe,
    /// Statistics
    total_bytes: u64,
    total_ops: u64,
}

impl<const MAX_OPS: usize> BatchedForwarder<MAX_OPS> {
    /// Create a new batched forwarder
    pub fn new() -> Result<Self, SpliceError> {
        const NONE: Option<SpliceOp> = None;
        Ok(Self {
            ops: [NONE; MAX_OPS],
            count: 0,
            pipe: SplicePipe::new()?,
            total_bytes: 0,
            total_ops: 0,
        })
    }

    /// Queue a splice operation
    ///
    /// Returns false if batch is full
    #[inline(always)]
    pub fn push(&mut self, op: SpliceOp) -> bool {
        if self.count >= MAX_OPS {
            return false;
        }
        self.ops[self.count] = Some(op);
        self.count += 1;
        true
    }

    /// Get number of pending operations
    #[inline(always)]
    pub fn pending(&self) -> usize {
        self.count
    }

    /// Check if batch is full
    #[inline(always)]
    pub fn is_full(&self) -> bool {
        self.count >= MAX_OPS
    }

    /// Execute all pending operations
    ///
    /// Clears the batch after execution.
    pub fn execute(&mut self) -> SpliceBatchResult {
        let mut result = SpliceBatchResult {
            bytes_transferred: 0,
            ops_completed: 0,
            error: None,
        };

        for i in 0..self.count {
            if let Some(op) = self.ops[i].take() {
                match self.execute_single(&op) {
                    Ok(n) => {
                        result.bytes_transferred += n;
                        result.ops_completed += 1;
                    }
                    Err(e) => {
                        if result.error.is_none() {
                            result.error = Some(e);
                        }
                        // Continue with remaining ops
                    }
                }
            }
        }

        self.total_bytes += result.bytes_transferred as u64;
        self.total_ops += result.ops_completed as u64;
        self.count = 0;

        result
    }

    /// Execute a single splice operation through the pipe
    fn execute_single(&self, op: &SpliceOp) -> SpliceResult {
        let mut total = 0usize;
        let mut remaining = op.len;

        while remaining > 0 {
            let chunk = remaining.min(PIPE_BUF_SIZE);

            // Source → Pipe
            let n = splice(
                op.fd_in,
                None,
                self.pipe.write_fd,
                None,
                chunk,
                splice_flags::SPLICE_F_MOVE | splice_flags::SPLICE_F_MORE,
            )?;

            if n == 0 {
                break;
            }

            // Pipe → Destination
            let mut written = 0;
            while written < n {
                let w = splice(
                    self.pipe.read_fd,
                    None,
                    op.fd_out,
                    None,
                    n - written,
                    splice_flags::SPLICE_F_MOVE | splice_flags::SPLICE_F_MORE,
                )?;
                written += w;
            }

            total += n;
            remaining -= n;
        }

        Ok(total)
    }

    /// Clear pending operations without executing
    pub fn clear(&mut self) {
        for i in 0..self.count {
            self.ops[i] = None;
        }
        self.count = 0;
    }

    /// Get lifetime statistics
    pub fn stats(&self) -> (u64, u64) {
        (self.total_bytes, self.total_ops)
    }
}

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
    pub fn from_bytes(bytes: &[u8]) -> Self {
        match bytes {
            b"GET" => HttpMethod::Get,
            b"POST" => HttpMethod::Post,
            b"PUT" => HttpMethod::Put,
            b"DELETE" => HttpMethod::Delete,
            b"PATCH" => HttpMethod::Patch,
            b"HEAD" => HttpMethod::Head,
            b"OPTIONS" => HttpMethod::Options,
            b"CONNECT" => HttpMethod::Connect,
            b"TRACE" => HttpMethod::Trace,
            _ => HttpMethod::Unknown,
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
/// Returns (RequestLine, header_end_offset) or None if incomplete
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
    fn test_pipe_creation() {
        let pipe = SplicePipe::new();
        assert!(pipe.is_ok());
        // Pipe is automatically closed on drop
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
        assert_eq!(find_content_length(headers), Some(1048576));
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

    #[test]
    fn test_splice_op_new() {
        let op = SpliceOp::new(3, 7, 4096);
        assert_eq!(op.fd_in, 3);
        assert_eq!(op.fd_out, 7);
        assert_eq!(op.len, 4096);
    }

    #[test]
    fn test_splice_batch_result_fields() {
        let result = SpliceBatchResult {
            bytes_transferred: 8192,
            ops_completed: 4,
            error: None,
        };
        assert_eq!(result.bytes_transferred, 8192);
        assert_eq!(result.ops_completed, 4);
        assert!(result.error.is_none());
    }

    #[test]
    fn test_splice_error_variants() {
        // Verify SpliceError variants are distinct and Copy
        let e1 = SpliceError::WouldBlock;
        let e2 = SpliceError::BadFd;
        let e3 = SpliceError::InvalidArg;
        let e4 = SpliceError::NoMem;
        let e5 = SpliceError::BrokenPipe;
        let e6 = SpliceError::ConnectionReset;
        let e7 = SpliceError::Io(42);

        assert_eq!(e1, SpliceError::WouldBlock);
        assert_eq!(e7, SpliceError::Io(42));
        assert_ne!(e1, e2);
        assert_ne!(e2, e3);
        assert_ne!(e3, e4);
        assert_ne!(e4, e5);
        assert_ne!(e5, e6);
    }

    #[test]
    fn test_pipe_buf_size() {
        // Verify the constant is correct
        assert_eq!(PIPE_BUF_SIZE, 65536);
    }

    #[test]
    fn test_splice_flags_constants() {
        assert_eq!(splice_flags::SPLICE_F_MOVE, 1);
        assert_eq!(splice_flags::SPLICE_F_NONBLOCK, 2);
        assert_eq!(splice_flags::SPLICE_F_MORE, 4);
        assert_eq!(splice_flags::SPLICE_F_GIFT, 8);
    }

    #[test]
    fn test_batched_forwarder_push_and_pending() {
        let mut batch = BatchedForwarder::<4>::new().expect("failed to create BatchedForwarder");

        assert_eq!(batch.pending(), 0);
        assert!(!batch.is_full());

        assert!(batch.push(SpliceOp::new(0, 1, 100)));
        assert!(batch.push(SpliceOp::new(2, 3, 200)));
        assert_eq!(batch.pending(), 2);

        assert!(batch.push(SpliceOp::new(4, 5, 300)));
        assert!(batch.push(SpliceOp::new(6, 7, 400)));
        assert!(batch.is_full());

        // 5th push should fail
        assert!(!batch.push(SpliceOp::new(8, 9, 500)));
    }

    #[test]
    fn test_batched_forwarder_clear() {
        let mut batch = BatchedForwarder::<4>::new().expect("failed to create BatchedForwarder");

        batch.push(SpliceOp::new(0, 1, 100));
        batch.push(SpliceOp::new(2, 3, 200));
        assert_eq!(batch.pending(), 2);

        batch.clear();
        assert_eq!(batch.pending(), 0);
        assert!(!batch.is_full());
    }
}
