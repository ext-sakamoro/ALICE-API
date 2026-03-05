//! C FFI bindings for ALICE-API
//!
//! 20 `extern "C"` functions for cross-language integration.
//!
//! # Safety
//!
//! All functions that take raw pointers perform null checks.
//! Opaque handles must be freed with the corresponding `_destroy` function.

use crate::gateway::{Backend, GatewayConfig, GatewayDecision, GatewayRequest, Route, TestGateway};
use crate::gcra::{GcraCell, GcraDecision};
use crate::routing::HttpMethod;
use crate::sfq::{QueuedRequest, StochasticFairQueue};
use std::ffi::c_char;

/// FFI-safe gateway stats
#[repr(C)]
pub struct FfiGatewayStats {
    pub requests_total: u64,
    pub requests_forwarded: u64,
    pub requests_rate_limited: u64,
    pub requests_queued: u64,
    pub requests_not_found: u64,
    pub bytes_forwarded: u64,
}

/// FFI-safe SFQ stats
#[repr(C)]
pub struct FfiSfqStats {
    pub enqueued: u64,
    pub dequeued: u64,
    pub drops: u64,
    pub current_len: u32,
}

/// FFI-safe gateway decision
#[repr(C)]
pub struct FfiGatewayDecision {
    /// 0=Forward, 1=Queued, 2=RateLimited, 3=NotFound,
    /// 4=MethodNotAllowed, 5=PayloadTooLarge, 6=Unauthorized,
    /// 7=DecryptFailed, 8=InternalError
    pub kind: u8,
    /// backend_id (Forward) or retry_after_ns (RateLimited)
    pub value: u64,
}

impl From<GatewayDecision> for FfiGatewayDecision {
    fn from(d: GatewayDecision) -> Self {
        match d {
            GatewayDecision::Forward { backend_id } => Self {
                kind: 0,
                value: backend_id as u64,
            },
            GatewayDecision::Queued => Self { kind: 1, value: 0 },
            GatewayDecision::RateLimited { retry_after_ns } => Self {
                kind: 2,
                value: retry_after_ns,
            },
            GatewayDecision::NotFound => Self { kind: 3, value: 0 },
            GatewayDecision::MethodNotAllowed => Self { kind: 4, value: 0 },
            GatewayDecision::PayloadTooLarge => Self { kind: 5, value: 0 },
            GatewayDecision::Unauthorized => Self { kind: 6, value: 0 },
            GatewayDecision::DecryptFailed => Self { kind: 7, value: 0 },
            GatewayDecision::InternalError => Self { kind: 8, value: 0 },
        }
    }
}

// SFQ type alias for FFI (8 queues, depth 32)
type FfiSfq = StochasticFairQueue<8, 32>;

// ============================================
// 1. alice_api_gcra_create
// ============================================

/// Create a GCRA rate limiter cell.
///
/// `rate`: requests per second, `burst`: burst size.
#[no_mangle]
pub extern "C" fn alice_api_gcra_create(rate: f64, burst: u32) -> *mut GcraCell {
    Box::into_raw(Box::new(GcraCell::new(rate, burst)))
}

// ============================================
// 2. alice_api_gcra_destroy
// ============================================

/// Destroy a GCRA cell.
///
/// # Safety
///
/// `cell` must be from `alice_api_gcra_create`.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_destroy(cell: *mut GcraCell) {
    if !cell.is_null() {
        drop(Box::from_raw(cell));
    }
}

// ============================================
// 3. alice_api_gcra_check
// ============================================

/// Check rate limit. Returns 1 if allowed, 0 if denied.
///
/// `out_ns`: on Allow → reset_after_ns, on Deny → retry_after_ns.
///
/// # Safety
///
/// `cell` must be valid. `out_ns` may be null.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_check(
    cell: *const GcraCell,
    now_ns: u64,
    out_ns: *mut u64,
) -> u8 {
    if cell.is_null() {
        return 0;
    }
    match (*cell).check(now_ns) {
        GcraDecision::Allow { reset_after_ns } => {
            if !out_ns.is_null() {
                *out_ns = reset_after_ns;
            }
            1
        }
        GcraDecision::Deny { retry_after_ns } => {
            if !out_ns.is_null() {
                *out_ns = retry_after_ns;
            }
            0
        }
    }
}

// ============================================
// 4. alice_api_gcra_would_allow
// ============================================

/// Check without updating state. Returns 1 if would allow.
///
/// # Safety
///
/// `cell` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_would_allow(cell: *const GcraCell, now_ns: u64) -> u8 {
    if cell.is_null() {
        return 0;
    }
    u8::from((*cell).would_allow(now_ns))
}

// ============================================
// 5. alice_api_gcra_tat
// ============================================

/// Get current TAT (Theoretical Arrival Time).
///
/// # Safety
///
/// `cell` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_tat(cell: *const GcraCell) -> u64 {
    if cell.is_null() {
        return 0;
    }
    (*cell).tat()
}

// ============================================
// 6. alice_api_gcra_merge
// ============================================

/// CRDT merge: cell.TAT = max(cell.TAT, other_tat).
///
/// # Safety
///
/// `cell` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_merge(cell: *const GcraCell, other_tat: u64) {
    if !cell.is_null() {
        (*cell).merge(other_tat);
    }
}

// ============================================
// 7. alice_api_gcra_reset
// ============================================

/// Reset the GCRA cell (allow burst again).
///
/// # Safety
///
/// `cell` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gcra_reset(cell: *const GcraCell) {
    if !cell.is_null() {
        (*cell).reset();
    }
}

// ============================================
// 8. alice_api_gateway_create
// ============================================

/// Create a TestGateway with default config.
#[no_mangle]
pub extern "C" fn alice_api_gateway_create() -> *mut TestGateway {
    Box::into_raw(Box::new(TestGateway::new(GatewayConfig::default())))
}

// ============================================
// 9. alice_api_gateway_destroy
// ============================================

/// Destroy a gateway.
///
/// # Safety
///
/// `gw` must be from `alice_api_gateway_create`.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_destroy(gw: *mut TestGateway) {
    if !gw.is_null() {
        drop(Box::from_raw(gw));
    }
}

// ============================================
// 10. alice_api_gateway_add_backend
// ============================================

/// Add a backend to the gateway. Returns backend_id or 0 on failure.
///
/// # Safety
///
/// `gw` must be valid. `host` must point to `host_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_add_backend(
    gw: *mut TestGateway,
    backend_id: u32,
    host: *const u8,
    host_len: u32,
    port: u16,
) -> u32 {
    if gw.is_null() || host.is_null() {
        return 0;
    }
    let host_slice = std::slice::from_raw_parts(host, host_len as usize);
    let backend = Backend::new(backend_id, host_slice, port);
    (*gw).add_backend(backend).unwrap_or(0)
}

// ============================================
// 11. alice_api_gateway_add_route
// ============================================

/// Add a route with a path prefix. Returns 1 on success, 0 on failure.
///
/// # Safety
///
/// `gw` must be valid. `prefix` must point to `prefix_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_add_route(
    gw: *mut TestGateway,
    prefix: *const u8,
    prefix_len: u32,
    backend_id: u32,
) -> u8 {
    if gw.is_null() || prefix.is_null() {
        return 0;
    }
    let prefix_slice = std::slice::from_raw_parts(prefix, prefix_len as usize);
    let mut route = Route::new(prefix_slice);
    route.add_backend(backend_id);
    u8::from((*gw).add_route(route))
}

// ============================================
// 12. alice_api_gateway_process
// ============================================

/// Process a request through the gateway.
///
/// Returns an `FfiGatewayDecision`.
///
/// # Safety
///
/// `gw` must be valid. `path` must point to `path_len` bytes.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_process(
    gw: *mut TestGateway,
    client_hash: u64,
    method: u8,
    path: *const u8,
    path_len: u32,
    content_length: u32,
    timestamp_ns: u64,
) -> FfiGatewayDecision {
    if gw.is_null() || path.is_null() {
        return FfiGatewayDecision { kind: 8, value: 0 };
    }
    let gw = &mut *gw;
    let path_slice = std::slice::from_raw_parts(path, (path_len as usize).min(256));

    let http_method = match method {
        0 => HttpMethod::Get,
        1 => HttpMethod::Post,
        2 => HttpMethod::Put,
        3 => HttpMethod::Delete,
        4 => HttpMethod::Patch,
        5 => HttpMethod::Head,
        6 => HttpMethod::Options,
        _ => HttpMethod::Get,
    };

    let mut path_buf = [0u8; 256];
    let copy_len = path_slice.len().min(256);
    path_buf[..copy_len].copy_from_slice(&path_slice[..copy_len]);

    let request = GatewayRequest {
        client_hash,
        request_id: gw.next_request_id(),
        method: http_method,
        path: path_buf,
        path_len: copy_len,
        content_length: content_length as usize,
        header_size: 0,
        timestamp_ns,
    };

    gw.process(&request).into()
}

// ============================================
// 13. alice_api_gateway_stats
// ============================================

/// Get gateway statistics.
///
/// # Safety
///
/// `gw` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_stats(gw: *const TestGateway) -> FfiGatewayStats {
    if gw.is_null() {
        return FfiGatewayStats {
            requests_total: 0,
            requests_forwarded: 0,
            requests_rate_limited: 0,
            requests_queued: 0,
            requests_not_found: 0,
            bytes_forwarded: 0,
        };
    }
    let stats = (*gw).stats();
    FfiGatewayStats {
        requests_total: stats.requests_total,
        requests_forwarded: stats.requests_forwarded,
        requests_rate_limited: stats.requests_rate_limited,
        requests_queued: stats.requests_queued,
        requests_not_found: stats.requests_not_found,
        bytes_forwarded: stats.bytes_forwarded,
    }
}

// ============================================
// 14. alice_api_gateway_hash_client
// ============================================

/// Hash a client identifier (IP, API key, etc.).
///
/// # Safety
///
/// `data` must point to `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn alice_api_gateway_hash_client(data: *const u8, len: u32) -> u64 {
    if data.is_null() || len == 0 {
        return 0;
    }
    let slice = std::slice::from_raw_parts(data, len as usize);
    TestGateway::hash_client(slice)
}

// ============================================
// 15. alice_api_sfq_create
// ============================================

/// Create a Stochastic Fair Queue (8 queues, depth 32).
///
/// `quantum`: bytes per DRR round (e.g. 1500 for MTU).
#[no_mangle]
pub extern "C" fn alice_api_sfq_create(quantum: u32) -> *mut FfiSfq {
    Box::into_raw(Box::new(FfiSfq::new(quantum as usize)))
}

// ============================================
// 16. alice_api_sfq_destroy
// ============================================

/// Destroy an SFQ.
///
/// # Safety
///
/// `sfq` must be from `alice_api_sfq_create`.
#[no_mangle]
pub unsafe extern "C" fn alice_api_sfq_destroy(sfq: *mut FfiSfq) {
    if !sfq.is_null() {
        drop(Box::from_raw(sfq));
    }
}

// ============================================
// 17. alice_api_sfq_enqueue
// ============================================

/// Enqueue a request. Returns 1 if enqueued, 0 if dropped.
///
/// # Safety
///
/// `sfq` must be valid.
#[no_mangle]
pub unsafe extern "C" fn alice_api_sfq_enqueue(
    sfq: *mut FfiSfq,
    flow_hash: u64,
    size: u32,
    id: u64,
    enqueue_time: u64,
) -> u8 {
    if sfq.is_null() {
        return 0;
    }
    let req = QueuedRequest::new(flow_hash, size as usize, id, enqueue_time);
    u8::from((*sfq).enqueue(req))
}

// ============================================
// 18. alice_api_sfq_dequeue
// ============================================

/// Dequeue next request. Returns request id, or 0 if empty.
///
/// # Safety
///
/// `sfq` must be valid. Output pointers may be null.
#[no_mangle]
pub unsafe extern "C" fn alice_api_sfq_dequeue(
    sfq: *mut FfiSfq,
    out_flow_hash: *mut u64,
    out_size: *mut u32,
) -> u64 {
    if sfq.is_null() {
        return 0;
    }
    match (*sfq).dequeue() {
        Some(req) => {
            if !out_flow_hash.is_null() {
                *out_flow_hash = req.flow_hash;
            }
            if !out_size.is_null() {
                *out_size = req.size as u32;
            }
            req.id
        }
        None => 0,
    }
}

// ============================================
// 19. alice_api_string_free
// ============================================

/// Free a C string returned by `alice_api_version`.
///
/// # Safety
///
/// `s` must be a valid C string from this library.
#[no_mangle]
pub unsafe extern "C" fn alice_api_string_free(s: *mut c_char) {
    if !s.is_null() {
        drop(std::ffi::CString::from_raw(s));
    }
}

// ============================================
// 20. alice_api_version
// ============================================

/// Return the library version as a C string.
///
/// Free with `alice_api_string_free`.
#[no_mangle]
pub extern "C" fn alice_api_version() -> *mut c_char {
    let version = std::ffi::CString::new(crate::VERSION).unwrap_or_default();
    version.into_raw()
}

// ============================================
// Tests
// ============================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CStr;

    #[test]
    fn test_gcra_create_destroy() {
        let cell = alice_api_gcra_create(100.0, 10);
        assert!(!cell.is_null());
        unsafe { alice_api_gcra_destroy(cell) };
    }

    #[test]
    fn test_gcra_check_allow_deny() {
        let cell = alice_api_gcra_create(2.0, 2);
        unsafe {
            let mut ns: u64 = 0;

            // Burst of 2 allowed
            assert_eq!(alice_api_gcra_check(cell, 0, &mut ns), 1);
            assert_eq!(alice_api_gcra_check(cell, 0, &mut ns), 1);

            // 3rd denied
            assert_eq!(alice_api_gcra_check(cell, 0, &mut ns), 0);
            assert!(ns > 0);

            alice_api_gcra_destroy(cell);
        }
    }

    #[test]
    fn test_gcra_would_allow_and_tat() {
        let cell = alice_api_gcra_create(10.0, 2);
        unsafe {
            assert_eq!(alice_api_gcra_would_allow(cell, 0), 1);
            alice_api_gcra_check(cell, 0, ptr::null_mut());
            alice_api_gcra_check(cell, 0, ptr::null_mut());
            assert_eq!(alice_api_gcra_would_allow(cell, 0), 0);
            assert!(alice_api_gcra_tat(cell) > 0);
            alice_api_gcra_destroy(cell);
        }
    }

    #[test]
    fn test_gcra_merge_and_reset() {
        let cell = alice_api_gcra_create(10.0, 5);
        unsafe {
            alice_api_gcra_check(cell, 0, ptr::null_mut());
            let tat = alice_api_gcra_tat(cell);

            let high_tat = tat + 5_000_000_000;
            alice_api_gcra_merge(cell, high_tat);
            assert_eq!(alice_api_gcra_tat(cell), high_tat);

            alice_api_gcra_reset(cell);
            assert_eq!(alice_api_gcra_tat(cell), 0);

            alice_api_gcra_destroy(cell);
        }
    }

    #[test]
    fn test_gateway_create_destroy() {
        let gw = alice_api_gateway_create();
        assert!(!gw.is_null());
        unsafe { alice_api_gateway_destroy(gw) };
    }

    #[test]
    fn test_gateway_add_backend_route_process() {
        let gw = alice_api_gateway_create();
        unsafe {
            let host = b"localhost";
            assert_ne!(
                alice_api_gateway_add_backend(gw, 1, host.as_ptr(), host.len() as u32, 8080),
                0
            );

            let prefix = b"/api/";
            assert_eq!(
                alice_api_gateway_add_route(gw, prefix.as_ptr(), prefix.len() as u32, 1),
                1
            );

            let path = b"/api/users";
            let decision = alice_api_gateway_process(
                gw,
                12345,
                0, // GET
                path.as_ptr(),
                path.len() as u32,
                0,
                0,
            );
            assert_eq!(decision.kind, 0); // Forward
            assert_eq!(decision.value, 1); // backend_id = 1

            let stats = alice_api_gateway_stats(gw);
            assert_eq!(stats.requests_total, 1);
            assert_eq!(stats.requests_forwarded, 1);

            alice_api_gateway_destroy(gw);
        }
    }

    #[test]
    fn test_gateway_hash_client() {
        unsafe {
            let ip = b"192.168.1.1";
            let h1 = alice_api_gateway_hash_client(ip.as_ptr(), ip.len() as u32);
            let h2 = alice_api_gateway_hash_client(ip.as_ptr(), ip.len() as u32);
            assert_eq!(h1, h2);
            assert_ne!(h1, 0);
        }
    }

    #[test]
    fn test_sfq_create_destroy() {
        let sfq = alice_api_sfq_create(1500);
        assert!(!sfq.is_null());
        unsafe { alice_api_sfq_destroy(sfq) };
    }

    #[test]
    fn test_sfq_enqueue_dequeue() {
        let sfq = alice_api_sfq_create(1024);
        unsafe {
            assert_eq!(alice_api_sfq_enqueue(sfq, 0xAAAA, 512, 1, 0), 1);
            assert_eq!(alice_api_sfq_enqueue(sfq, 0xBBBB, 512, 2, 0), 1);

            let mut flow: u64 = 0;
            let mut size: u32 = 0;
            let id = alice_api_sfq_dequeue(sfq, &mut flow, &mut size);
            assert!(id > 0);
            assert!(size > 0);

            alice_api_sfq_destroy(sfq);
        }
    }

    #[test]
    fn test_version() {
        let ver = alice_api_version();
        assert!(!ver.is_null());
        unsafe {
            let s = CStr::from_ptr(ver);
            assert!(s.to_str().unwrap().starts_with("0."));
            alice_api_string_free(ver);
        }
    }

    #[test]
    fn test_null_safety() {
        unsafe {
            alice_api_gcra_destroy(ptr::null_mut());
            alice_api_gateway_destroy(ptr::null_mut());
            alice_api_sfq_destroy(ptr::null_mut());
            alice_api_string_free(ptr::null_mut());

            assert_eq!(alice_api_gcra_check(ptr::null(), 0, ptr::null_mut()), 0);
            assert_eq!(alice_api_gcra_would_allow(ptr::null(), 0), 0);
            assert_eq!(alice_api_gcra_tat(ptr::null()), 0);
            assert_eq!(alice_api_gateway_hash_client(ptr::null(), 0), 0);
            assert_eq!(alice_api_sfq_enqueue(ptr::null_mut(), 0, 0, 0, 0), 0);
            assert_eq!(
                alice_api_sfq_dequeue(ptr::null_mut(), ptr::null_mut(), ptr::null_mut()),
                0
            );
        }
    }
}
