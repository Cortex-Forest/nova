# Hash Benchmarks（STEP 2）

## 范围

仅测量 `nova_crypto::hash`：
- `protocol_hash`（SHA-256，协议承诺）
- `content_hash`（BLAKE3，链下内容哈希）

## 运行

```bash
cargo bench -p nova-crypto --bench hash_bench
```

## 采样方法（评审 §13 明确要求）

| 项 | 说明 |
|----|------|
| warmup | criterion 默认 warm-up（约 3s） |
| sample_size | criterion 默认 100 个采样点（可通过 `--sample-size` 覆盖） |
| iterations | criterion 自动决定（`--nresamples` 等可调） |
| 输入尺寸 | 32 B / 1 KiB / 64 KiB / 1 MiB（`Throughput::Bytes`） |
| 单位 | **吞吐（bytes/sec）与耗时（ns）**；**不输出 TPS** |

## Percentile（p50 / p95 / p99）

- criterion 默认输出 mean / median 与置信区间，**不直接给出自定义 p50/p95/p99**。
- 因此 percentile 由**独立统计脚本**对原始样本计算：
  `scripts/bench_percentiles.ps1 -Path <每行一个耗时的样本文件>`
- 采样方法：样本文件由测量程序收集（warmup 丢弃后，连续 N 次 `Instant` 计时）。
- **所有数字必须真实产生**；禁止虚构（Master Prompt §64）。

## 纪律

- 不输出"TPS"。
- benchmark 不参与共识/协议逻辑。
