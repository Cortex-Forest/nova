# PHASE 2 Implementation Plan（修订版 v2）

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **依据冻结规范**：ADR-0002~0013、crypto-serialization-v1.md、crypto-test-vectors-v1.md、genesis-v1.md、crypto-threat-model.md
- **代码边界**：仅改 `crates/crypto`、`crates/core`（最小）、`tests/vectors`、`fuzz/`、`benches/`、`docs/`；禁止 consensus/network/wallet/website/VM。

## 1. Updated Dependency Matrix（评审 §1）

**使用当前稳定、兼容 Rust 1.96.1、经过依赖审查的最新稳定版本；最终版本以实际 Cargo resolution 为准；Cargo.lock 提交。禁止为复制旧教程而用旧 API。**

| crate | 目标版本 | 用途 | license | 维护 | 安全历史 / CVE | 替代（否决） |
|-------|---------|------|--------|------|---------------|-------------|
| `ed25519-dalek` | **3.0.0**（`rand_core` feature） | Ed25519 | Apache-2.0/MIT | ZKcrypto 活跃 | 3.x 重构、严格验证、`verify_strict` 能力；无已知 CVE | ed25519-compact（审计少） |
| `rand_core` | **0.10.1**（ed25519-dalek 3.x re-export） | CSPRNG 接口 | Apache-2.0/MIT | RustCrypto | 成熟 | 自研 RNG（禁止） |
| `getrandom` | 最新（`SysRng`） | OS 熵源 | Apache-2.0/MIT | RustCrypto | 成熟、跨平台 | — |
| `sha2` | 最新（0.10.x） | 协议哈希 SHA-256 | Apache-2.0/MIT | RustCrypto | 无已知 CVE | sha3（无 SHA-NI） |
| `blake3` | 最新（1.x） | 内容哈希 | CC0/Apache-2.0 | 官方 | 广泛审查 | blake2 |
| `bech32` | **0.12.0** | Bech32m 编码/校验 | MIT | rust-bitcoin | 广泛使用；BIP-350 校验算法；**禁止重实现 checksum** | 自实现（禁止） |
| `zeroize` | 最新（1.x） | 密钥零化 | Apache-2.0/MIT | RustCrypto | 成熟 | 手动清零（不可靠） |
| `proptest`（dev） | 最新（1.x） | property tests | Apache-2.0/MIT | 活跃 | 成熟 | quickcheck |
| `criterion`（dev） | 最新（0.5.x） | benchmarks | Apache-2.0/MIT | 活跃 | 成熟 | std bench（nightly） |

- 全部经 `[workspace.dependencies]` 统一版本；`Cargo.lock` 提交。
- 工具 `cargo-audit`/`cargo-deny`/`cargo tree` 在依赖落地后**实际执行**；工具缺失/执行失败 ⇒ **如实报告 BLOCKED**（不得写成"安全"）。

## 2. RNG Architecture Decision（评审 §2）

- **OS-backed CSPRNG**：`getrandom::SysRng` + `rand_core::TryRng` + `UnwrapErr`（ed25519-dalek 3.x 官方推荐路径）。
- 密钥生成：`SigningKey::generate(&mut csprng)`。
- **无** custom RNG；**无** 确定性生产密钥生成；**无** entropy fallback（OS 失败即错误，不降级）。
- 以 ed25519-dalek 3.x 官方文档为准（已核实 docs.rs）。

## 3. Updated Signature Pipeline（评审 §3/§4/§6，冻结于 crypto-serialization-v1.md §10）

```
canonical_payload → signature context → signed_bytes → SHA-256 → message_hash[32B] → Ed25519 signing
```

- **Ed25519 签名的输入是 `SHA-256(signed_bytes)`**（`message_hash`），不是 raw tx / canonical payload / 任意消息。
- API：
  ```
  build_signed_bytes(...)      -> Vec<u8>
  hash_signing_message(...)    -> SigningMessageHash([u8;32])   // newtype
  sign_message_hash(...)       -> Signature
  verify_message_hash(...)     -> Result<(), CryptoError>
  ```
- **唯一验证路径**：`canonical payload → context → signed_bytes → SHA-256 → SigningMessageHash → verify_strict`。
- 禁止一处验证 hash、另一处验证 raw bytes。

## 4. Updated API Boundaries（评审 §5/§7/§9/§10，见 ADR-0013）

- 低层 Ed25519 原语仅**内部**存在；**不公开** `sign(arbitrary_bytes)`。
- `SigningMessageHash([u8;32])` newtype 强制：普通 `[u8;32]` 不能作为协议签名消息。
- **Strict Verification**：`verify_strict`；拒绝 malformed pubkey/signature、weak key、small-order point、非 canonical 编码。**禁用 legacy compatibility / hazmat**（除非单独 ADR）。
- **Crypto owns**：`AlgorithmId`、哈希、签名原语、密钥原语；**Protocol/Core owns（迁移目标）**：`DomainId`/`NetworkId`/`AddressType`/`ChainIdentity`/序列化规则。本阶段 crypto 暂存后者，建立 `CRYPTO → PROTOCOL` 迁移边界。
- **Hash 边界**：`protocol_hash()`（SHA-256）仅用于 ADR-0006 注册的共识协议位置（不公开通用 wrapper）；`content_hash()`（BLAKE3）**不得进入** tx/block hash、state root、validator vote、finality proof（除非未来 ADR）。

## 5. Fuzz Toolchain Plan（评审 §12）

**方案 B（采纳）**：CI 专门 fuzz job 使用 **nightly**（仅 fuzz job），主工程继续 stable 1.96.1（production build toolchain **不变**）。
- 本地可选方案 A 补充：独立 nightly 工具链（`rustup toolchain install nightly`）用于本地 fuzz，不改 `rust-toolchain.toml`（保持 stable）。
- Targets：`address_decode` / `signature_decode` / `domain_message_decode` / `canonical_serialization`。
- 要求：不 panic、不无限耗时、不产生未定义状态、恶意输入安全失败。

## 6. Benchmark Methodology（评审 §13）

- Harness：criterion。**明确采样方法**：warmup（默认约 3s）+ 采样 iterations + `sample_size` 配置。
- **percentile**：criterion 默认不直接给出自定义 p50/p95/p99（其输出为 mean/median + 置信区间）⇒ **额外建立统计脚本**收集原始样本并计算 p50/p95/p99。
- 度量项：hash throughput / sign / verify / address encode / address decode / domain hash。
- **不输出 TPS**。

## 7. Updated Test Vector Schema（评审 §16，冻结于 crypto-test-vectors-v1.md §3b）

每个签名向量包含：`algorithm_id`、`domain_id`、`chain_id`、`canonical_payload`、`signed_bytes`、`message_hash`、`public_key`、`signature`、`expected`；测试器独立重算 `signed_bytes`/`message_hash` 比对。

## 8. Final Files To Change

| 文件 | 操作 |
|------|------|
| `Cargo.toml`（workspace） | 改：`[workspace.dependencies]` 加依赖 |
| `crates/crypto/Cargo.toml` | 改：引用 workspace 依赖 + features（`rand_core`） |
| `crates/crypto/src/lib.rs` | 重写：模块组织 + re-export |
| `crates/crypto/src/error.rs` | 新建：`CryptoError` |
| `crates/crypto/src/hash.rs` | 新建：`protocol_hash`/`content_hash`（语义边界） |
| `crates/crypto/src/registry.rs` | 新建：`AlgorithmId`（crypto owns）+ 暂存 `DomainId/NetworkId/AddressType` + 校验 |
| `crates/crypto/src/domain.rs` | 新建：`build_signed_bytes`/`hash_signing_message`/`SigningMessageHash` |
| `crates/crypto/src/signature.rs` | 新建：`sign_message_hash`/`verify_message_hash`（verify_strict） |
| `crates/crypto/src/key.rs` | 新建：安全密钥处理（zeroize/ownership/无 Clone secret） |
| `crates/crypto/src/address.rs` | 新建：encode/decode（bech32 0.12） |
| `crates/crypto/src/identity.rs` | 新建：`ChainIdentity` + `genesis_hash` + `ValidateGenesis` 集成 |
| `crates/crypto/tests/` | 新建：集成测试 |
| `tests/vectors/` | 新建：JSON 向量 + 加载器 + 断言（含 §3b schema） |
| `fuzz/` | 新建：4 个 target（CI nightly job） |
| `benches/` | 新建：criterion 6 项 + percentile 统计脚本 |
| `docs/security/dependency-audit.md` | 新建：`cargo tree`/`audit`/`deny` 结果（BLOCKED 如实报告） |
| `docs/protocols/genesis-v1.md` | 不改（已冻结）；实现对照 |

**不修改**：consensus / network / wallet / website / VM / node（除非编译接口必需并说明）。

## 9. 子模块 Exit Criteria（同 §十七）

Hash / Domain / Ed25519 / Address / Integration 各自 vectors+property+fuzz+benchmark 通过后进入下一步；每子模块完成即 review。
