use std::hint::black_box;
use std::io::{self, IoSlice};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use nfsserver::handles::HandleCodec;
use nfsserver::nfs3::codec::{truncate_readdir_result, EncodeNfsResult, Encoder};
use nfsserver::nfs3::procedures::{NfsArguments, ReadDirEntry, ReadDirEntryExtension, ReadDirResult, WriteRequest};
use nfsserver::replay::{ReplayCache, ReplayDecision, ReplayKey, RequestFingerprint};
use nfsserver::rpc::codec::Decoder;
use nfsserver::rpc::record::{read_record, write_record_limited, write_record_segments_limited, RecordLimits};
use nfsserver::rpc::reply::EncodedReply;
use nfsserver::vfs::{ExportId, ObjectKey};
use tokio::io::AsyncWrite;

const MIB: usize = 1024 * 1024;

// This synthetic writer advertises vectored support and can cap each accepted
// prefix. The assertions ensure benchmarks exercise the intended vectored and
// partial-write branches instead of silently falling back to scalar writes.
struct VectoredSink {
    bytes_written: usize,
    scalar_writes: usize,
    vectored_writes: usize,
    max_write: usize,
}

impl VectoredSink {
    fn with_max_write(max_write: usize) -> Self {
        assert!(max_write > 0);
        Self {
            bytes_written: 0,
            scalar_writes: 0,
            vectored_writes: 0,
            max_write,
        }
    }

    fn verify_record(&self, record_bytes: usize, fragments: usize) {
        assert_eq!(self.bytes_written, record_bytes + fragments * 4);
        assert_eq!(self.scalar_writes, 0);
        assert_eq!(self.vectored_writes, fragments);
    }

    fn verify_partial_record(&self, record_bytes: usize, fragments: usize) {
        assert_eq!(self.bytes_written, record_bytes + fragments * 4);
        assert_eq!(self.scalar_writes, 0);
        assert!(self.vectored_writes > fragments);
    }
}

impl Default for VectoredSink {
    fn default() -> Self {
        Self::with_max_write(usize::MAX)
    }
}

impl AsyncWrite for VectoredSink {
    fn poll_write(mut self: Pin<&mut Self>, _context: &mut Context<'_>, buffer: &[u8]) -> Poll<io::Result<usize>> {
        let written = buffer.len().min(self.max_write);
        self.bytes_written += written;
        self.scalar_writes += 1;
        Poll::Ready(Ok(written))
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let written = buffers.iter().map(|buffer| buffer.len()).sum::<usize>().min(self.max_write);
        self.bytes_written += written;
        self.vectored_writes += 1;
        Poll::Ready(Ok(written))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread().build().unwrap()
}

fn codec_benchmarks(c: &mut Criterion) {
    let payload = vec![0x5a; MIB];
    let mut encoded = Encoder::new();
    encoded.write_opaque(&payload).unwrap();
    let encoded = encoded.into_bytes();

    let mut group = c.benchmark_group("rpc_codec");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("encode_opaque_1mib", |b| {
        b.iter(|| {
            let mut encoder = Encoder::new();
            encoder.write_opaque(black_box(&payload)).unwrap();
            black_box(encoder.into_bytes())
        })
    });
    group.bench_function("decode_opaque_1mib", |b| {
        b.iter(|| {
            let mut decoder = Decoder::new(black_box(&encoded));
            let value = decoder.read_opaque("benchmark", MIB).unwrap();
            decoder.finish().unwrap();
            black_box(value)
        })
    });

    let mut write_arguments = Encoder::new();
    write_arguments.write_opaque(&[0x11; 45]).unwrap();
    write_arguments.write_u64(4096);
    write_arguments.write_u32(MIB as u32);
    write_arguments.write_u32(2);
    write_arguments.write_opaque(&payload).unwrap();
    let write_arguments = write_arguments.into_bytes();
    group.bench_function("decode_nfs_write_1mib", |b| {
        b.iter(|| black_box(NfsArguments::decode(7, black_box(&write_arguments), MIB).unwrap()))
    });
    let write_request = Bytes::from(write_arguments.clone());
    group.bench_function("decode_nfs_write_1mib_zero_copy", |b| {
        b.iter(|| black_box(WriteRequest::decode(black_box(write_request.clone()), MIB).unwrap()))
    });
    group.finish();
}

fn record_benchmarks(c: &mut Criterion) {
    let rt = runtime();
    let payload = vec![0x33; MIB];
    let limits = RecordLimits {
        max_record_size: MIB,
        max_fragment_size: 64 * 1024,
        max_fragments: 16,
    };
    let mut framed = Vec::with_capacity(MIB + 16 * 4);
    for (index, fragment) in payload.chunks(limits.max_fragment_size).enumerate() {
        let last = index == limits.max_fragments - 1;
        let header = fragment.len() as u32 | if last { 0x8000_0000 } else { 0 };
        framed.extend_from_slice(&header.to_be_bytes());
        framed.extend_from_slice(fragment);
    }

    let mut group = c.benchmark_group("rpc_record");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("read_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut input = black_box(framed.as_slice());
            black_box(read_record(&mut input, limits).await.unwrap())
        })
    });
    group.bench_function("write_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::default();
            write_record_limited(&mut output, black_box(&payload), limits).await.unwrap();
            output.verify_record(MIB, 16);
            black_box(output)
        })
    });
    let prefix = vec![0x22; 128];
    group.bench_function("write_segmented_1mib_16_fragments", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::default();
            write_record_segments_limited(
                &mut output,
                [
                    black_box(prefix.as_slice()),
                    black_box(&payload[..MIB - prefix.len()]),
                    &[],
                ],
                limits,
            )
            .await
            .unwrap();
            output.verify_record(MIB, 16);
            black_box(output)
        })
    });
    group.bench_function("write_segmented_1mib_16_fragments_partial_4k", |b| {
        b.to_async(&rt).iter(|| async {
            let mut output = VectoredSink::with_max_write(4 * 1024);
            write_record_segments_limited(
                &mut output,
                [
                    black_box(prefix.as_slice()),
                    black_box(&payload[..MIB - prefix.len()]),
                    &[],
                ],
                limits,
            )
            .await
            .unwrap();
            output.verify_partial_record(MIB, 16);
            black_box(output)
        })
    });
    group.finish();
}

fn read_reply_benchmarks(c: &mut Criterion) {
    let prefix = Bytes::from(vec![0x22; 128]);
    let payload = Bytes::from(vec![0x33; MIB]);
    let reply = EncodedReply::segmented(prefix.clone(), payload.clone(), 0);

    let mut group = c.benchmark_group("read_reply");
    group.throughput(Throughput::Bytes(MIB as u64));
    group.bench_function("assemble_segmented_1mib", |b| {
        b.iter(|| black_box(EncodedReply::segmented(black_box(prefix.clone()), black_box(payload.clone()), 0)))
    });
    group.bench_function("clone_for_replay_1mib", |b| b.iter(|| black_box(EncodedReply::clone(black_box(&reply)))));
    group.finish();
}

fn readdir_result(entry_count: usize) -> ReadDirResult {
    ReadDirResult::Ok {
        directory_attributes: None,
        verifier: [7; 8],
        entries: (0..entry_count)
            .map(|index| ReadDirEntry {
                file_id: index as u64,
                name: format!("entry-{index:08}").into_bytes(),
                cookie: index as u64 + 1,
                extension: ReadDirEntryExtension::Basic,
            })
            .collect(),
        eof: true,
    }
}

fn readdir_benchmarks(c: &mut Criterion) {
    const ENTRY_COUNT: usize = 4096;
    let template = readdir_result(ENTRY_COUNT);
    let mut fully_encoded = Encoder::new();
    template.encode_result(&mut fully_encoded).unwrap();
    let half_size = fully_encoded.len() / 2;

    let mut group = c.benchmark_group("readdir");
    group.throughput(Throughput::Elements(ENTRY_COUNT as u64));
    group.bench_function("truncate_4096_entries_to_half", |b| {
        b.iter_batched(
            || template.clone(),
            |mut result| {
                black_box(truncate_readdir_result(&mut result, half_size).unwrap());
                black_box(result)
            },
            criterion::BatchSize::SmallInput,
        )
    });
    group.finish();
}

fn replay_key(xid: u32) -> ReplayKey {
    ReplayKey {
        client_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        export_id: ExportId(1),
        xid,
    }
}

fn replay_benchmarks(c: &mut Criterion) {
    const ENTRIES: u32 = 4096;
    let rt = runtime();
    let cache = Arc::new(ReplayCache::new(ENTRIES as usize, ENTRIES as usize * 64, Duration::from_secs(3600)));
    rt.block_on(async {
        for xid in 0..ENTRIES {
            let fingerprint = RequestFingerprint([xid as u8; 32]);
            let ReplayDecision::Execute(lease) = cache.begin(replay_key(xid), fingerprint).await.unwrap() else {
                unreachable!();
            };
            lease.complete(Bytes::from_static(b"cached reply"));
        }
    });
    let hit_key = replay_key(ENTRIES - 1);
    let hit_fingerprint = RequestFingerprint([(ENTRIES - 1) as u8; 32]);

    let mut group = c.benchmark_group("replay_cache");
    group.throughput(Throughput::Elements(1));
    group.bench_function(BenchmarkId::new("hit_at_capacity", ENTRIES), |b| {
        b.to_async(&rt).iter(|| async {
            match cache.begin(black_box(hit_key.clone()), hit_fingerprint).await.unwrap() {
                ReplayDecision::Replay(reply) => black_box(reply),
                _ => unreachable!(),
            }
        })
    });
    group.finish();
}

fn handle_benchmarks(c: &mut Criterion) {
    let codec = HandleCodec::random();
    let export = ExportId(17);
    let object = ObjectKey {
        file_id: 0x1234_5678,
        generation: 9,
    };
    let encoded = codec.encode(export, object);

    let mut group = c.benchmark_group("file_handle");
    group.bench_function("encode", |b| b.iter(|| black_box(codec.encode(export, black_box(object)))));
    group.bench_function("decode_and_verify", |b| {
        b.iter(|| black_box(codec.decode(export, black_box(&encoded)).unwrap()))
    });
    group.finish();
}

criterion_group!(
    benches,
    codec_benchmarks,
    record_benchmarks,
    read_reply_benchmarks,
    readdir_benchmarks,
    replay_benchmarks,
    handle_benchmarks
);
criterion_main!(benches);
