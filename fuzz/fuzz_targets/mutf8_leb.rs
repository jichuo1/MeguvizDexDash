#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    mdd_parser_fuzz::run("mutf8_leb", data);
});
