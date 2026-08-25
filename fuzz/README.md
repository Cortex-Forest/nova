# Nova Chain Fuzz 基础设施

## 状态

- PHASE 1 — Project Foundation。
- fuzz 目录结构已预留；**尚未实现任何 fuzz target**。

## 未来必须 fuzz 的目标（Master Prompt §59-62）

| 目标 | 说明 |
|------|------|
| transaction decoding | 随机 bytes / malformed encoding / extreme amount-nonce / chain mismatch |
| block decoding | 畸形区块 / 冲突 proof |
| network messages | malformed/giant packet / handshake abuse / gossip amplification |
| consensus messages | invalid/duplicate/delayed vote / malformed proof / malicious validator |
| WASM inputs | infinite loop / huge memory / malicious import / invalid bytecode |
| RPC inputs | 畸形请求 / 超大请求 / 分页边界 |

## 工具

- 优先 `cargo-fuzz`（libFuzzer）；property 测试用 `proptest`。
- fuzz target 应在 CI 中可运行（独立 job），并纳入安全审查流程。
