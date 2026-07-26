#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nfsembed::handles::HandleCodec;
use nfsembed::nfs3::codec::{truncate_readdir_result, EncodeNfsResult};
use nfsembed::nfs3::procedures::{NfsArguments, ReadDirEntry, ReadDirEntryExtension, ReadDirResult};
use nfsembed::rpc::codec::{Decoder, Encoder};
use nfsembed::vfs::{ExportId, ObjectKey};

fuzz_target!(|data: &[u8]| {
    static HANDLES: OnceLock<HandleCodec> = OnceLock::new();
    let handles = HANDLES.get_or_init(HandleCodec::random);
    for procedure in [16, 17] {
        if let Ok(arguments) = NfsArguments::decode(procedure, data, 4096) {
            let handle = match arguments {
                NfsArguments::ReadDir(arguments) => arguments.directory,
                NfsArguments::ReadDirPlus(arguments) => arguments.directory,
                _ => Vec::new(),
            };
            let _ = handles.decode(ExportId(1), &handle);
        }

        let handle = handles.encode(
            ExportId(1),
            ObjectKey {
                file_id: u64::from(data.first().copied().unwrap_or_default()),
                generation: 1,
            },
        );
        let count = u32::from(data.first().copied().unwrap_or(64)).saturating_add(24);
        let mut encoded = Encoder::new();
        encoded.write_opaque(&handle).unwrap();
        encoded.write_u64(u64::from(data.get(1).copied().unwrap_or_default()));
        encoded.write_fixed(&[data.get(2).copied().unwrap_or_default(); 8]);
        encoded.write_u32(count);
        if procedure == 17 {
            encoded.write_u32(count.saturating_mul(2));
        }
        if let Ok(arguments) = NfsArguments::decode(procedure, &encoded.into_bytes(), 4096) {
            let decoded_handle = match arguments {
                NfsArguments::ReadDir(arguments) => arguments.directory,
                NfsArguments::ReadDirPlus(arguments) => arguments.directory,
                _ => Vec::new(),
            };
            let _ = handles.decode(ExportId(1), &decoded_handle);
        }

        let entries = data
            .chunks(8)
            .take(32)
            .enumerate()
            .map(|(index, chunk)| ReadDirEntry {
                file_id: index as u64 + 1,
                name: if chunk.is_empty() { vec![b'x'] } else { chunk.to_vec() },
                cookie: index as u64 + 1,
                extension: if procedure == 17 {
                    ReadDirEntryExtension::Plus {
                        attributes: None,
                        handle: Some(handle.to_vec()),
                    }
                } else {
                    ReadDirEntryExtension::Basic
                },
            })
            .collect();
        let mut result = ReadDirResult::Ok {
            directory_attributes: None,
            verifier: [0; 8],
            entries,
            eof: true,
        };
        let limit = if procedure == 17 {
            count.saturating_mul(2) as usize
        } else {
            count as usize
        };
        if truncate_readdir_result(&mut result, limit).unwrap_or(false) {
            let mut reply = Encoder::new();
            result.encode_result(&mut reply).unwrap();
            let reply = reply.into_bytes();
            assert!(reply.len().saturating_sub(4) <= limit);

            let mut decoder = Decoder::new(&reply);
            assert_eq!(decoder.read_u32().unwrap(), 0);
            assert!(!decoder.read_bool().unwrap());
            assert_eq!(decoder.read_fixed::<8>().unwrap(), [0; 8]);
            while decoder.read_bool().unwrap() {
                let _file_id = decoder.read_u64().unwrap();
                let _name = decoder.read_opaque("fuzz READDIR name", 8).unwrap();
                let _cookie = decoder.read_u64().unwrap();
                if procedure == 17 {
                    assert!(!decoder.read_bool().unwrap());
                    assert!(decoder.read_bool().unwrap());
                    let decoded_handle = decoder.read_opaque("fuzz READDIR handle", 64).unwrap();
                    assert_eq!(decoded_handle, handle);
                }
            }
            let _eof = decoder.read_bool().unwrap();
            decoder.finish().unwrap();
        }
    }
});
