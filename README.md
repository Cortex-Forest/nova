# Nova Chain

Nova Chain 是一条面向 **AI、数字创作、数字娱乐和开放应用生态**的模块化 Layer1 区块链。核心理念：Creator Economy、AI Applications、Digital Ownership、Open Developer Ecosystem、Mobile-first User Experience、Permissionless Network Participation。

> **⚠️ 当前状态：PHASE 1 — Project Foundation（工程基础搭建中）**
>
> **Core consensus is not implemented.**
> 本仓库当前仅包含 Cargo Workspace 工程基础、代码质量工具、CI、文档体系与 ADR。**不包含任何可运行的区块链核心功能。** 未实现的能力均标注为 `PLANNED` / `NOT IMPLEMENTED`，绝不虚报。

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

- **PHASE**: PHASE 1 — Project Foundation
- **Consensus**: `NOT IMPLEMENTED`
- **WASM Execution**: `NOT IMPLEMENTED`
- **P2P Network**: `NOT IMPLEMENTED`
- **Wallet / Explorer / Website**: `PLANNED`
- **当前不是 Devnet / Testnet / Mainnet**：本项目尚未进入任何网络阶段（见 Master Prompt §72）。
- 详见 [docs/architecture/overview.md](docs/architecture/overview.md) 与 [docs/adr/](docs/adr/)

## 4. Repository Structure

```
NovaChain/
├── Cargo.toml            # Cargo Workspace 根（统一版本/依赖/lints）
├── crates/
│   ├── core/             # nova-core：核心协议类型（占位）
│   ├── consensus/        # nova-consensus（占位）
│   ├── crypto/           # nova-crypto（占位）
│   ├── execution/        # nova-execution：WASM 执行（占位）
│   ├── network/          # nova-network：P2P（占位）
│   ├── node/             # nova-node：节点组装/配置骨架
│   ├── rpc/              # nova-rpc（占位）
│   ├── storage/          # nova-storage（占位）
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

见 [docs/architecture/overview.md](docs/architecture/overview.md)。开发顺序为 PHASE 1 → PHASE 24（Project Foundation → Crypto → Address → Transaction → State → Storage → Block/DAG → P2P → PoS → BFT → Node → WASM → RPC → Explorer → Wallet → Staking → Mobile → Website → Creator → Devnet → Public Testnet → Security/Chaos/Economic → Mainnet Candidate → Mainnet）。所有后续阶段均为 `PLANNED`。

---

**License**: Apache-2.0
