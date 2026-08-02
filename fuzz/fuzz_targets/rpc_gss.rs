#![no_main]

use libfuzzer_sys::fuzz_target;
use nfsembed::rpc::gss::{
    ChannelBindingVerifierArgs, ChannelBindingVerifierResult, Credential, GssLimits, InitArgs, InitResult,
    IntegrityBody, PrivacyBody,
};

fuzz_target!(|data: &[u8]| {
    let limits = GssLimits {
        max_handle_bytes: 4 * 1024,
        max_token_bytes: 64 * 1024,
        max_mic_bytes: 64 * 1024,
        max_protected_body_bytes: 64 * 1024,
        max_channel_binding_bytes: 64 * 1024,
        max_channel_prefix_bytes: 256,
        max_oid_bytes: 256,
        max_preference_count: 32,
    };

    let _ = Credential::decode(data, limits);
    let _ = InitArgs::decode(data, limits);
    let _ = InitResult::decode(data, limits);
    let _ = IntegrityBody::decode(data, limits).and_then(|body| body.embedded_sequence().map(|_| body));
    let _ = PrivacyBody::decode(data, limits);
    let _ = ChannelBindingVerifierArgs::decode(data, limits);
    let _ = ChannelBindingVerifierResult::decode(data, limits);
});
