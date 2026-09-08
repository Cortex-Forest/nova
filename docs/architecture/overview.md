# YAZIMAO 架构总览

> **状态**：本文档只描述**已批准架构**。任何未批准的新设计不得写入本文档（Master Prompt §15）。

## 1. 当前架构状态

- **PHASE**: PHASE 2 — Protocol Design COMPLETE / FROZEN；Implementation & Integration In Progress
- 工程基础、代码质量工具、CI、文档体系与 ADR 治理框架（ADR-0001~0060 tracked）已完成；Crypto / Genesis / Consensus 协议规范已冻结。
- 实现已推进至节点运行时 / 集成层、validator 安全持久化与 Storage 持久化（详见 §6）。
- **完整可运行区块链尚未发布**；Devnet / Testnet / Mainnet：`NOT RELEASED`。

## 2. 总体分层

```
Application Layer          ← nova-node / nova-rpc / nova-wallet
  ↓
API / SDK（统一接口契约）    ← API Contract First（ADR-0011）
  ↓
WASM Execution Layer       ← nova-execution
  ↓
State Transition
  ↓
Consensus                  ← nova-consensus（PoS + DAG 传播 + BFT 最终性）
  ↓
P2P Network                ← nova-network（rust-libp2p）
  ↓
Storage                    ← nova-storage（RocksDB + 状态树）
```

## 3. 依赖方向（ADR-0001 已批准）

```
Application (node / rpc / wallet)
     ↓
Services (consensus / execution / network)
     ↓
Protocol (core / storage)
     ↓
Infrastructure (crypto)
```

- 严格单向、无环。核心层不得依赖官网/Explorer/手机/业务层（Master Prompt §93）。
- 依赖按已批准设计单向添加；实现阶段已按上图建立 core / crypto / execution / storage / consensus / network / node 之间的依赖。

## 4. 统一版本概念（四者分离，ADR-0001）

| 版本 | 值 | 定义位置 |
|------|-----|---------|
| Software | `0.1.0` | workspace.package |
| Protocol | `0.1` | nova-core `PROTOCOL_VERSION` |
| Database | `1` | nova-storage `DATABASE_VERSION` |
| API | `v1` | nova-rpc `API_VERSION` |

## 5. 本阶段已批准决策（摘要）

详见 [ADR-0001](../adr/ADR-0001-project-foundation.md)。

## 6. 实现状态（防止误解）

- **Consensus**：协议设计 FINAL FROZEN；纯计算核心 + node-driven consensus + validator 安全持久化（fail-closed）/ 重启恢复已实现；**生产鉴权出站网络路径不完整**。
- **Node**：运行时 / 集成层已实现（NodeRuntime / driver / ValidatorActor / bootstrap / restart recovery / egress / block / sync 等），integration hardening 中。
- **Storage**：StateStore / SMT + PersistentBackend（8E）+ chain head persistence + block store（crash-consistent）已实现；进一步集成 / 加固中（非"生产已认证"）。
- **Network / P2P**：运行时基础设施已实现（message / transport / security / session / network_service / event_loop / gossip / sync）；**libp2p 未采用；生产鉴权出站运行时 BLOCKED**。
- **WASM 执行**：`NOT IMPLEMENTED`（state transition / block 执行纯计算已实现）。
- **RPC**：占位（placeholder），非生产就绪。
- **钱包 / Explorer / 官网**：`PLANNED`。
- **Release**：Devnet / Testnet / Mainnet：`NOT RELEASED`。

## 7. 后续阶段

开发顺序为 PHASE 1 → PHASE 24（Project Foundation → Crypto → Address → Transaction → State → Storage → Block/DAG → P2P → PoS → BFT → Node → WASM → RPC → Explorer → Wallet → Staking → Mobile → Website → Creator → Devnet → Public Testnet → Security/Chaos/Economic → Mainnet Candidate → Mainnet），与 README §9 一致。
各阶段有独立 Exit Criteria（Master Prompt §91）；当前处于实现 / 集成推进中，**完整可运行区块链与任何网络阶段均尚未发布**。
