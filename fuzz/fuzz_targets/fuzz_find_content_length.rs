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

    // find_content_length has a defined result for every input; a slice cut after the header end
    // has the same result as the whole input, since nothing after that line is read
    let whole = find_content_length(data);
    if let Some(end) = find_header_end(data) {
        // only when the section has one blank line, not an ignored leading one
        if !data.starts_with(b"\r\n") {
            assert_eq!(find_content_length(&data[..end]), whole);
        }
    }

    // find_header_end must never panic
    if let Some(end) = find_header_end(data) {
        // Must return an index within the input
        assert!(end <= data.len(), "header end exceeds input length");
    }
});
