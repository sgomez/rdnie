#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let Some((status, plain)) = data.split_first_chunk::<2>() else {
        return;
    };
    let response =
        rdnie::fuzzing::secure_messaging(data).expect("a response the card protected unprotects");
    assert_eq!(response.status.0, u16::from_be_bytes(*status));
    assert!(plain.starts_with(&response.data));
});
