#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use nfsserver::rpc::record::{read_record, RecordLimits};
use tokio::io::AsyncWriteExt;
use tokio::runtime::{Builder, Runtime};

fuzz_target!(|data: &[u8]| {
    static RUNTIME: OnceLock<Runtime> = OnceLock::new();
    let runtime = RUNTIME.get_or_init(|| Builder::new_current_thread().build().unwrap());
    let capacity = data.len().max(1);
    runtime.block_on(async {
        let (mut writer, mut reader) = tokio::io::duplex(capacity);
        let write = async {
            let _ = writer.write_all(data).await;
            drop(writer);
        };
        let read = read_record(
            &mut reader,
            RecordLimits {
                max_record_size: 64 * 1024,
                max_fragment_size: 16 * 1024,
                max_fragments: 16,
            },
        );
        let (_, result) = tokio::join!(write, read);
        let _ = result;
    });
});
