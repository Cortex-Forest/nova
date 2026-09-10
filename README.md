# YAZIMAO

YAZIMAO 是一条面向 **AI、数字创作、数字娱乐和开放应用生态**的模块化 Layer1 区块链。核心理念：Creator Economy、AI Applications、Digital Ownership、Open Developer Ecosystem、Mobile-first User Experience、Permissionless Network Participation。

> **⚠️ 当前状态：PHASE 2 — Protocol Design COMPLETE / FROZEN；Implementation & Integration In Progress**
>
> **完整可运行区块链尚未发布。**
> 本仓库已完成：Cargo Workspace 工程基础、代码质量工具、CI、文档体系、ADR 治理框架（ADR-0001~0063 tracked）、
> Crypto / Genesis / Consensus 协议规范冻结，以及 **Consensus 纯计算核心**（STEP 10-1~10-14 COMPLETE / FINAL FROZEN）。
> **实现已推进至节点运行时 / 集成层与持久化**：node-driven consensus + production consensus auto-drive + finality
> commit bridge + DAG restart rebuild / finality recovery + canonical commit + 远程 canonical block 持久化（follower
> sync）、validator 安全持久化（fail-closed）/ 重启恢复、持久化区块存储 / chain head / 崩溃一致性提交、
> Network 运行时基础设施（network_service / event_loop / security / session / 出站握手 initiation / 配置化连接目标 /
> 多 peer 生命周期 / sync 握手集成 / 生产 TcpTransport）——均已实现（D8 / D9 / D10 集成与 E2E 通过，持续 hardening）。
> **仍未完成**：libp2p（未采用）、WASM Execution、完整 Storage / Network 生产认证、Node / RPC / Wallet 发布。
> 未实现的能力均标注为 `PLANNED` / `NOT IMPLEMENTED`，绝不虚报。
> **Release**：Devnet / Testnet / Mainnet — `NOT RELEASED`（当前不是 Devnet / Testnet / Mainnet）。

## 1. 简介

YAZIMAO 采用分层架构：

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

- **PHASE**: PHASE 2 — Protocol Design COMPLETE / FROZEN；Implementation & Integration In Progress
- **Consensus**: 协议设计 FINAL FROZEN + 纯计算核心已实现（STEP 10-1~10-14 COMPLETE / FINAL FROZEN）；
  node-driven consensus + production consensus auto-drive + finality commit bridge + DAG restart rebuild /
  finality recovery + canonical commit 已实现（D9 / D10 集成与 E2E 通过）
- **WASM Execution**: `NOT IMPLEMENTED`（state transition / block 执行纯计算已实现）
- **Network / P2P**: 运行时基础设施已实现（message / transport / security / session / network_service / event_loop /
  gossip / sync，含生产 std::net TcpTransport）；**出站握手 initiation、配置化连接目标、多 peer 生命周期、
  sync 握手集成已完成**；**libp2p 未采用**
- **Storage**: StateStore / SMT + PersistentBackend（8E）+ chain head persistence + block store +
  crash-consistent block commit 已实现；进一步集成 / 加固中（**非"生产已认证"**）
- **Node**: 运行时 / 集成层已实现（NodeRuntime / driver / ValidatorActor / bootstrap / restart recovery / egress /
  block builder / inbound / dispatch / sync / follower sync persistence），持续 integration hardening
- **Wallet / Explorer / Website**: `PLANNED`
- **Release**: Devnet / Testnet / Mainnet：`NOT RELEASED`（尚未进入任何网络阶段，见 Master Prompt §72）。
- **命名**: 公开品牌 **YAZIMAO**，内部开发代号 **Nova**；`nova-*` crate / package 名按 ADR-0063（ACCEPTED）保留
- 详见 [docs/architecture/overview.md](docs/architecture/overview.md) 与 [docs/adr/](docs/adr/)

## 4. Repository Structure

```
YAZIMAO/                    # 公开品牌 YAZIMAO；内部开发代号 Nova（crate 名保留 nova-*，见 ADR-0063）
├── Cargo.toml            # Cargo Workspace 根（统一版本/依赖/lints）
├── crates/
│   ├── core/             # nova-core：协议类型与规则（transaction/nonce/replay/gas/state，已实现）
│   ├── consensus/        # nova-consensus：PoS + DAG + BFT 协议设计 FINAL FROZEN；纯计算核心 + proposer selection + consensus 集成 + production auto-drive / finality commit bridge 已实现
│   ├── crypto/           # nova-crypto：哈希/签名/地址/domain/genesis（PHASE 2 完成）
│   ├── execution/        # nova-execution：state transition / block 执行纯计算（已实现；WASM 未实现）
│   ├── network/          # nova-network：运行时基础设施（message/transport/security/session/network_service/event_loop/gossip/sync；出站握手 / 连接目标 / 多 peer 生命周期已实现；libp2p 未采用）
│   ├── node/             # nova-node：运行时 / 集成层（NodeRuntime/driver/validator safety/bootstrap/restart recovery/block/follower sync 等；integration hardening）
│   ├── rpc/              # nova-rpc（占位）
│   ├── storage/          # nova-storage：StateStore/SMT + PersistentBackend + chain head + block store（持久化 / 崩溃一致性已实现）
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

**已推进 / 已实现**：PHASE 2 Protocol Design（Crypto / Genesis / 协议规范）COMPLETE / FROZEN；Consensus 协议与纯计算核心（STEP 10-1~10-14）COMPLETE / FINAL FROZEN；node-driven consensus、production consensus auto-drive、finality commit bridge、DAG restart rebuild / finality recovery、canonical commit、follower sync persistence、Node 运行时 / 集成层、Storage 持久化（block store / chain head / crash-consistent）、Network 运行时基础设施（出站握手 / 配置化连接目标 / 多 peer 生命周期 / sync 握手集成）、区块生命周期、D8 / D9 / D10 集成与 E2E 均已实现（持续 hardening）。
**未推进 / 未完成**：libp2p（未采用）、WASM Execution、RPC、Wallet、Explorer、Staking 等，均为 `PLANNED` / `NOT IMPLEMENTED`；Devnet / Testnet / Mainnet：`NOT RELEASED`。

---

**License**: Apache-2.0
