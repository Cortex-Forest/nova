# Nova Chain Fuzz（cargo-fuzz 项目，独立 crate）

## 状态

- **STEP 4 已准备 2 个 fuzz target**：`signature_decode`、`domain_message_decode`。
- **STEP 6A 已准备 1 个 fuzz target**：`genesis_canonicalize`（canonical 编码/哈希，bounded、no-panic）。
- 本 crate **不在 workspace members**——避免 libfuzzer-sys 影响 stable production build。
- 运行需 **nightly**（方案 B：CI 专门 fuzz job；主工程 production build toolchain 保持 **stable 1.96.1 不变**）。

## 运行

```bash
rustup toolchain install nightly   # 仅用于 fuzz（不改 rust-toolchain.toml）
cd fuzz
cargo +nightly fuzz run signature_decode
cargo +nightly fuzz run domain_message_decode
cargo +nightly fuzz run genesis_canonicalize
```

## 未来必须 fuzz 的目标（Master Prompt §59-62）

| 目标 | 说明 | 状态 |
|------|------|------|
| signature decode | malformed/truncated/oversized 签名、畸形公钥 | ✅ 已准备 |
| domain message decode | signed_bytes 构造、未知 domain/algorithm | ✅ 已准备 |
| genesis canonicalize | 随机 bytes 构造 Genesis → canonical 编码/哈希（no panic / bounded / deterministic） | ✅ 已准备（STEP 6A） |
| genesis decode | Genesis canonical bytes → 结构（STEP 6B decode 实现后添加） | 后续 STEP |
| transaction decoding | 随机 bytes / malformed encoding / extreme amount-nonce / chain mismatch | 后续 STEP |
| block decoding | 畸形区块 / 冲突 proof | 后续 STEP |
| network messages | malformed/giant packet / handshake abuse / gossip amplification | 后续 STEP |
| consensus messages | invalid/duplicate/delayed vote / malformed proof | 后续 STEP |
| WASM inputs | infinite loop / huge memory / malicious import | 后续 STEP |
| RPC inputs | 畸形请求 / 超大请求 / 分页边界 | 后续 STEP |

## 纪律

- 每个 target 必须：不 panic、不无限耗时、不产生未定义状态、对恶意输入安全失败。
- 未来 target（address/canonical serialization）在对应 STEP 添加：`address_decode`、`canonical_serialization`。
