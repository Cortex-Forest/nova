//! Hash benchmarks（STEP 2 — hash only）。
//!
//! 方法说明见 `benches/README.md`（采样 / warmup / percentile）。

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use nova_crypto::hash::{content_hash, protocol_hash};

const SIZES: [usize; 4] = [32, 1024, 64 * 1024, 1024 * 1024];

fn bench_protocol_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("protocol_hash_sha256");
    for size in SIZES {
        let data = vec![0xabu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| protocol_hash(black_box(data)));
        });
    }
    group.finish();
}

fn bench_content_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("content_hash_blake3");
    for size in SIZES {
        let data = vec![0xabu8; size];
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::from_parameter(size), &data, |b, data| {
            b.iter(|| content_hash(black_box(data)));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_protocol_hash, bench_content_hash);
criterion_main!(benches);
