#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nfsembed::handles::HandleCodec;
use nfsembed::nfs3::codec::EncodeNfsResult;
use nfsembed::nfs3::procedures::{NfsArguments, WriteResult};
use nfsembed::nfs3::types::{NfsStatus, WccData, WriteStability};
use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::vfs::{ExportId, ObjectKey};

fuzz_target!(|data: &[u8]| {
    const MAX_WRITE: usize = 4096;
    static HANDLES: OnceLock<HandleCodec> = OnceLock::new();
    let handles = HANDLES.get_or_init(HandleCodec::random);
    if let Ok(NfsArguments::Write(arguments)) = NfsArguments::decode(7, data, MAX_WRITE) {
        let _ = handles.decode(ExportId(1), &arguments.object);
        let _ = arguments.validate();
    }

    // Every iteration also constructs one complete request from fuzzed
    // fields, guaranteeing coverage past all XDR length prefixes.
    let handle = handles.encode(
        ExportId(1),
        ObjectKey {
            file_id: u64::from(data.first().copied().unwrap_or_default()),
            generation: 1,
        },
    );
    let payload = data;
    let payload = &payload[..payload.len().min(MAX_WRITE)];
    let requested_count = if data.first().is_some_and(|byte| byte & 1 != 0) {
        payload.len().saturating_add(1)
    } else {
        payload.len()
    };
    let mut encoded = Encoder::new();
    encoded.write_opaque(&handle).unwrap();
    encoded.write_u64(u64::from_be_bytes(data.get(..8).unwrap_or(&[]).try_into().unwrap_or([0; 8])));
    encoded.write_u32(u32::try_from(requested_count).unwrap_or(u32::MAX));
    encoded.write_u32(u32::from(data.get(1).copied().unwrap_or_default() % 3));
    encoded.write_opaque(payload).unwrap();

    if let Ok(NfsArguments::Write(arguments)) = NfsArguments::decode(7, &encoded.into_bytes(), MAX_WRITE) {
        let _ = handles.decode(ExportId(1), &arguments.object);
        let result = if arguments.validate().is_ok() {
            WriteResult::Ok {
                file_wcc: WccData::default(),
                count: arguments.count,
                committed: WriteStability::FileSync,
                verifier: [0; 8],
            }
        } else {
            WriteResult::Err {
                status: NfsStatus::Invalid,
                file_wcc: WccData::default(),
            }
        };
        let mut reply = Encoder::new();
        result.encode_result(&mut reply).unwrap();
        let reply = reply.into_bytes();
        let mut decoder = Decoder::new(&reply);
        let status = decoder.read_u32().unwrap();
        assert!(!decoder.read_bool().unwrap());
        assert!(!decoder.read_bool().unwrap());
        if arguments.validate().is_ok() {
            assert_eq!(status, 0);
            assert_eq!(decoder.read_u32().unwrap(), arguments.count);
            assert_eq!(decoder.read_u32().unwrap(), 2);
            assert_eq!(decoder.read_fixed::<8>().unwrap(), [0; 8]);
        } else {
            assert_eq!(status, NfsStatus::Invalid as u32);
        }
        decoder.finish().unwrap();
    }
});
