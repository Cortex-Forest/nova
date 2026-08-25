# Nova Chain 架构总览

> **状态**：本文档只描述**已批准架构**。任何未批准的新设计不得写入本文档（Master Prompt §15）。

## 1. 当前架构状态

- **PHASE**: PHASE 1 — Project Foundation
- 本阶段只建立工程基础；**所有区块链核心功能均未实现**。

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
- PHASE 1 中各 crate 之间**零 Cargo 依赖**；依赖方向在实现时按此图添加。

## 4. 统一版本概念（四者分离，ADR-0001）

| 版本 | 值 | 定义位置 |
|------|-----|---------|
| Software | `0.1.0` | workspace.package |
| Protocol | `0.1` | nova-core `PROTOCOL_VERSION` |
| Database | `1` | nova-storage `DATABASE_VERSION` |
| API | `v1` | nova-rpc `API_VERSION` |

## 5. 本阶段已批准决策（摘要）

详见 [ADR-0001](../adr/ADR-0001-project-foundation.md)。

## 6. 明确未实现（防止误解）

- 共识（PoS / DAG / BFT）：`NOT IMPLEMENTED`
- WASM 执行：`NOT IMPLEMENTED`
- P2P 网络：`NOT IMPLEMENTED`
- 钱包 / Explorer / 官网：`PLANNED`
- 存储（RocksDB）：`NOT IMPLEMENTED`

## 7. 后续阶段

PHASE 2（Crypto）→ PHASE 3（Address/Account）→ … → PHASE 24（Mainnet）。
所有后续阶段均为 `PLANNED`；每阶段有独立 Exit Criteria（Master Prompt §91）。
