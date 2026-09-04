#![no_main]
use alice_api::gateway::Route;
use alice_api::routing::HttpMethod;
use libfuzzer_sys::fuzz_target;

// Fuzz Route matching with arbitrary path prefix + arbitrary request path — must never panic.
// Splits input: first byte selects method, next byte is prefix length, rest is prefix + path.
fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }

    // Bound input size
    if data.len() > 4096 {
        return;
    }

    // Select HTTP method from first byte
    let method = match data[0] % 6 {
        0 => HttpMethod::Get,
        1 => HttpMethod::Post,
        2 => HttpMethod::Put,
        3 => HttpMethod::Delete,
        4 => HttpMethod::Patch,
        _ => HttpMethod::Head,
    };

    // Second byte: split point between prefix and request path
    let split = usize::from(data[1]) % (data.len() - 1) + 1;
    let split = split.min(data.len() - 1);

    let prefix = &data[2..2 + (split - 1).min(data.len() - 2)];
    let path = &data[2 + prefix.len()..];

    let route = Route::new(prefix);

    // matches() must never panic on arbitrary input
    let _ = route.matches(path, method);
});
