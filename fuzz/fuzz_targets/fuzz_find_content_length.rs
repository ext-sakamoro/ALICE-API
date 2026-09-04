#![no_main]
use alice_api::routing::{find_content_length, find_header_end};
use libfuzzer_sys::fuzz_target;

// Fuzz HTTP header parsers (Content-Length + header-end detection) with
// arbitrary byte input — must never panic on any input.
fuzz_target!(|data: &[u8]| {
    // Bound input size to keep fuzzing fast
    if data.len() > 16384 {
        return;
    }

    // find_content_length must never panic
    if let Some(len) = find_content_length(data) {
        // Sanity: returned length should be a reasonable value
        // (no assertion on max — we just want to catch panics)
        let _ = len;
    }

    // find_header_end must never panic
    if let Some(end) = find_header_end(data) {
        // Must return an index within the input
        assert!(end <= data.len(), "header end exceeds input length");
    }
});
