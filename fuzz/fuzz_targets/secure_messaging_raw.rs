#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = rdnie::fuzzing::secure_messaging_raw(data);
});
