# Nova Chain

Nova Chain 是一条面向 **AI、数字创作、数字娱乐和开放应用生态**的模块化 Layer1 区块链。核心理念：Creator Economy、AI Applications、Digital Ownership、Open Developer Ecosystem、Mobile-first User Experience、Permissionless Network Participation。

> **⚠️ 当前状态：PHASE 2 — Protocol Design（协议冻结完成，进入实现阶段）**
>
> **完整可运行区块链尚未发布。**
> 本仓库已完成：Cargo Workspace 工程基础、代码质量工具、CI、文档体系、ADR 治理框架（ADR-0001~0040）、
> Crypto / Genesis / Consensus 协议规范冻结，以及 **Consensus 纯计算核心实现**（STEP 10，lib 108 tests，
> 含 BFT Round / Finality / Checkpoint / ForkChoice / Integration）。
> **端到端共识（网络接入 / 节点驱动 / 持久化恢复）与 WASM / 完整 P2P / Storage 持久化尚未完成。**
> 未实现的能力均标注为 `PLANNED` / `NOT IMPLEMENTED`，绝不虚报。当前不是 Devnet / Testnet / Mainnet。

## 1. 简介

Nova Chain 采用分层架构：

```
Application Layer
  ↓
API / SDK（统一接口契约）
  ↓
WASM Execution Layer
  ↓
State Transition
  ↓
Consensus（PoS + DAG 传播 + BFT 最终性）
  ↓
P2P Network（rust-libp2p）
  ↓
Storage（RocksDB + 状态树）
```

## 2. 当前版本

| 版本概念 | 值 | 说明 |
|----------|-----|------|
| Software | `0.1.0` | 软件版本 |
| Protocol | `0.1` | 协议版本 |
| Database | `1` | 数据库版本 |
| API | `v1` | RPC/API 版本 |

四者相互独立、分开定义（`workspace.metadata.nova` 统一登记）。

## 3. 状态

- **PHASE**: PHASE 2 — Protocol Design（完成）→ 实现阶段
- **Consensus**: 协议冻结完成 + **纯计算核心已实现**（STEP 10-1~10-14 COMPLETE / FINAL FROZEN）；
  端到端共识（网络接入 / 节点驱动 / 持久化恢复）`NOT IMPLEMENTED`
- **WASM Execution**: `NOT IMPLEMENTED`（state transition / block 执行纯计算已实现）
- **P2P Network**: 消息层骨架已实现（STEP 9-2~9-5）；完整传输 / libp2p `NOT IMPLEMENTED`
- **Storage**: SMT / StateStore 已实现（STEP 8B/8C）；持久化后端（8E）`DEFERRED`
- **Wallet / Explorer / Website**: `PLANNED`
- **当前不是 Devnet / Testnet / Mainnet**：本项目尚未进入任何网络阶段（见 Master Prompt §72）。
- 详见 [docs/architecture/overview.md](docs/architecture/overview.md) 与 [docs/adr/](docs/adr/)

## 4. Repository Structure

```
NovaChain/
├── Cargo.toml            # Cargo Workspace 根（统一版本/依赖/lints）
├── crates/
│   ├── core/             # nova-core：协议类型与规则（transaction/nonce/replay/gas/state，已实现）
│   ├── consensus/        # nova-consensus：PoS + DAG + BFT 纯计算核心（STEP 10 冻结，已实现）
│   ├── crypto/           # nova-crypto：哈希/签名/地址/domain/genesis（PHASE 2 完成）
│   ├── execution/        # nova-execution：state transition / block 执行纯计算（已实现；WASM 未实现）
│   ├── network/          # nova-network：P2P 消息层骨架（STEP 9-2~9-5；libp2p 未实现）
│   ├── node/             # nova-node：节点组装/配置骨架
│   ├── rpc/              # nova-rpc（占位）
│   ├── storage/          # nova-storage：SMT / StateStore（STEP 8B/8C 已实现；8E 持久化未完成）
│   └── wallet/           # nova-wallet（占位）
├── tests/                # 跨 crate 集成测试入口
├── benches/              # benchmark 入口
├── fuzz/                 # fuzz 基础设施
├── docs/                 # 架构 / ADR / 安全 / 测试 / 运维 / 协议
├── scripts/              # 开发运维脚本
└── .github/workflows/    # CI
```

## 5. Build

```bash
cargo build --workspace
```

## 6. Test

```bash
cargo test --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

## 7. Development

- **Rust**: stable toolchain，Edition 2024
- **依赖方向**: `Application → Services → Protocol → Infrastructure`（单向无环，见 ADR-0001）
- **错误处理**: 统一 `Result<T, E>`；生产代码禁止 `unwrap/expect/panic`
- **依赖管理**: 公共依赖统一经 `[workspace.dependencies]`；`Cargo.lock` 必须提交锁定
- **纪律**: 一次只实现一个模块；先 ADR → 接口契约 → 实现 → 测试 → 安全审查

## 8. Security

- 本仓库**不包含任何硬编码密钥 / 助记词 / token / API key**（`.gitignore` 已兜底）。
- 敏感信息一律使用环境变量 / Secret Manager，禁止入库。
- 生产代码默认禁止 `unsafe`（`[workspace.lints.rust] unsafe_code = "forbid"`）。
- 安全设计文档：[docs/security/](docs/security/)

## 9. Roadmap

见 [docs/architecture/overview.md](docs/architecture/overview.md)。开发顺序为 PHASE 1 → PHASE 24（Project Foundation → Crypto → Address → Transaction → State → Storage → Block/DAG → P2P → PoS → BFT → Node → WASM → RPC → Explorer → Wallet → Staking → Mobile → Website → Creator → Devnet → Public Testnet → Security/Chaos/Economic → Mainnet Candidate → Mainnet）。

**已推进**：PHASE 2 Protocol Design（Crypto / Genesis / 协议规范）完成；Consensus 协议与纯计算实现（PoS / BFT 阶段，STEP 10-1~10-14）COMPLETE / FINAL FROZEN。
**未推进**：端到端共识集成、完整 Storage 持久化、完整 P2P、WASM、Node、RPC、Wallet 等，均为 `PLANNED` / `NOT IMPLEMENTED`。

---

**License**: Apache-2.0
