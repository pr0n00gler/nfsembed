#![no_main]

use libfuzzer_sys::fuzz_target;
use nfsembed::nfs4::{
    decode_callback_compound_args, decode_callback_compound_res, encode_callback_compound_args,
    encode_callback_compound_res, DecodeLimits,
};

fuzz_target!(|data: &[u8]| {
    let limits = DecodeLimits {
        max_operations: 64,
        max_bitmap_words: 64,
        max_attribute_bytes: 64 * 1024,
        max_io_bytes: 64 * 1024,
        ..DecodeLimits::default()
    };

    if let Ok(arguments) = decode_callback_compound_args(data, limits) {
        let encoded = encode_callback_compound_args(&arguments).expect("decoded callback arguments must re-encode");
        let decoded =
            decode_callback_compound_args(&encoded, limits).expect("re-encoded callback arguments must decode");
        assert_eq!(decoded, arguments);
    }

    if let Ok(result) = decode_callback_compound_res(data, limits) {
        let encoded = encode_callback_compound_res(&result).expect("decoded callback result must re-encode");
        let decoded = decode_callback_compound_res(&encoded, limits).expect("re-encoded callback result must decode");
        assert_eq!(decoded, result);
    }
});
