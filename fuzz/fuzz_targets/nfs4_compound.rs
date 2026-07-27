#![no_main]

use libfuzzer_sys::fuzz_target;
use nfsembed::nfs4::{
    decode_compound_args, decode_compound_res, encode_compound_args, encode_compound_res, DecodeLimits,
};

fuzz_target!(|data: &[u8]| {
    let limits = DecodeLimits {
        max_operations: 128,
        max_bitmap_words: 64,
        max_attribute_bytes: 64 * 1024,
        max_io_bytes: 64 * 1024,
        ..DecodeLimits::default()
    };

    if let Ok(arguments) = decode_compound_args(data, limits) {
        let encoded = encode_compound_args(&arguments).expect("decoded COMPOUND arguments must re-encode");
        let decoded = decode_compound_args(&encoded, limits).expect("re-encoded COMPOUND arguments must decode");
        assert_eq!(decoded, arguments);
    }

    if let Ok(result) = decode_compound_res(data, limits) {
        let encoded = encode_compound_res(&result).expect("decoded COMPOUND result must re-encode");
        let decoded = decode_compound_res(&encoded, limits).expect("re-encoded COMPOUND result must decode");
        assert_eq!(decoded, result);
    }
});
