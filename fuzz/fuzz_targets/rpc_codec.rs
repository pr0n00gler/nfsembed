#![no_main]

use libfuzzer_sys::fuzz_target;
use nfsembed::rpc::codec::Decoder;

fuzz_target!(|data: &[u8]| {
    let limit = data.first().copied().map_or(0, usize::from);
    let mut decoder = Decoder::new(data.get(1..).unwrap_or_default());
    let _ = decoder.read_u32();
    let _ = decoder.read_u64();
    let _ = decoder.read_bool();
    let _ = decoder.read_opaque("fuzz opaque", limit);
    let _ = decoder.read_array("fuzz array", limit.min(32), Decoder::read_u32);
    let _ = decoder.finish();
});
