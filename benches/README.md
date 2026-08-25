# Nova Chain Benchmarks

## 状态

- PHASE 1 — Project Foundation。
- benchmark 入口已预留；**本阶段不声称任何 TPS 数据**（Master Prompt §64）。

## 未来目标（禁止只跑单机 TPS）

| 场景 | 说明 |
|------|------|
| transaction validation | 交易校验延迟/吞吐 |
| hashing | 哈希吞吐 |
| state transition | 状态转换 |
| storage | RocksDB 读写 |
| consensus | 共识轮次/最终性时间 |
| serialization | 编码/解码 |

## 纪律

- 必须测试多节点规模：1 / 4 / 10 / 50 / 100 节点。
- 测量：throughput / latency / p50 / p95 / p99 / finality time / memory / storage growth / bandwidth。
- **所有数字必须真实产生**，禁止虚构。
