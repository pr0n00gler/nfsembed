#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nfsembed::handles::HandleCodec;

fuzz_target!(|data: &[u8]| {
    static CODEC: OnceLock<HandleCodec> = OnceLock::new();
    let codec = CODEC.get_or_init(HandleCodec::random);
    let _ = codec.decode_any(data);
});
