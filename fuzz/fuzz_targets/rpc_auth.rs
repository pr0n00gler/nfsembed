#![no_main]

use libfuzzer_sys::fuzz_target;
use nfsembed::rpc::auth::decode_principal;

fuzz_target!(|data: &[u8]| {
    let (flavor, body) = if let Some(prefix) = data.get(..4) {
        (u32::from_be_bytes(prefix.try_into().unwrap()), &data[4..])
    } else {
        (0, data)
    };
    let _ = decode_principal(flavor, body);
});
