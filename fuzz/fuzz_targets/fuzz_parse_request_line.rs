#![no_main]
use alice_api::routing::parse_request_line;
use libfuzzer_sys::fuzz_target;

// Fuzz HTTP request line parser with arbitrary byte input — must never panic.
// Malformed input must return None; well-formed input must return a valid slice.
fuzz_target!(|data: &[u8]| {
    // Bound input size to keep fuzzing fast and focused on parser edge cases
    if data.len() > 8192 {
        return;
    }

    // Parser must never panic on arbitrary input
    if let Some((line, consumed)) = parse_request_line(data) {
        // If parse succeeded, consumed bytes must not exceed input
        assert!(consumed <= data.len(), "consumed exceeds input length");
        // path slice must be within input bounds
        assert!(line.path.len() <= data.len(), "path exceeds input length");
    }
});
