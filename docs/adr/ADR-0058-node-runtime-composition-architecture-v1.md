# ADR-0058: NodeRuntime Composition Architecture v1

## Status

DESIGN FROZEN（STEP 10-18I-B Design Freeze Review，2026-09-05）

Freeze Scope:
This ADR freezes runtime composition architecture only.
It does NOT authorize runtime wiring implementation.

Related: ADR-0057（Node Runtime Ownership Migration — **DESIGN FROZEN**）、ADR-0054（Node Lifecycle）、
ADR-0055（NetworkService）、ADR-0056（EventLoop）、STEP 10-18A..I-A

## Context

既有已建立组件（各自边界冻结 / seam 层完成）：

- `NetworkService<T: Transport>`（10-18E；ADR-0055）：own Transport / PeerManager / queues；
  envelope 验签 / 分类 / 收发；**不解析 consensus**。
- `EventLoop<T, H>`（10-18F；ADR-0056）：dispatch only；own NetworkService handle + bounded queue
  + timer 表 + handler；**不拥有 Consensus / safety / key**。
- `NodeConsensusHandler<S, E>`（10-18G-1；wiring.rs）：node 层 decode + 既有验证门面 + Driver
  orchestration + outbound semantic egress（唯一 decode 点）。
- `NodeConsensusDriver<S>`（10-15O + 10-18G-1）：own `ConsensusNode` + `ValidatorActor(s)`；
  outbound semantic seam（`take_outbound` / `OutboundConsensusMessage`）；无网络依赖。
- `NetworkIdentity` seam（10-18I-A；network_identity.rs）：`NetworkSigner` / `NetworkIdentityProvider`
  （NodeId + envelope 签名）；与 validator identity 分离；生产网络 key **DEFERRED（GAP-A）**。
- `NodeRuntime`（10-16 Phase 1 骨架）：own `chain_identity / chain_storage / ConsensusNode /
  ValidatorRuntime`；**尚未装配上述网络/编排组件**。

ADR-0057（FROZEN）已冻结 future ownership 边界：
`NodeRuntime owns { NodeConsensusDriver, EventLoop, NetworkService, NetworkIdentity }`；
`NodeConsensusDriver owns { ConsensusNode, ValidatorActor }`；Runtime 提供 delegation API。

## Problem

需要把已冻结的组件关系细化为 **NodeRuntime composition architecture**（Stage B，Design Only）：
- Runtime 字段 / 装配 / 生命周期形状（不改现有 Rust；仅设计）。
- 组件间装配顺序与 shutdown 顺序。
- `NetworkIdentity`（GAP-A）如何以注入式 seam 进入而不触碰生产网络 key。
- 保持 `runtime.consensus()` / `runtime.validator()` 兼容（ADR-0057 delegation API）。

## Decision (Design Only)

### 1. Future composition（引用 ADR-0057，不新增 ownership 语义）

```
NodeRuntime
│
├── NodeConsensusDriver        (owns ConsensusNode + ValidatorActor; orchestration)
├── EventLoop                  (dispatch only; own NS handle + queue + timer + handler)
├── NetworkService             (independent entity; own Transport/Peer/queues; transport only)
└── NetworkIdentity            (seam 注入; NodeId + envelope signing; 与 validator 分离)
```

### 2. Injection model（装配关系设计）

- `NodeConsensusDriver`：由 Runtime 现有 `ConsensusNode` + validator `ValidatorActor`（Box dyn）
  装配（Stage C 实现；ADR-0057 明确 handle 让渡 = orchestration ownership，语义不变）。
- `NetworkService`：由 Runtime 构造（Transport 注入 / MemoryTransport（dev）/ 未来 adapter）。
- `EventLoop`：由 Runtime 构造（NetworkService + `NodeConsensusHandler`(driver + egress) 装配）。
- `NetworkIdentity`：**注入式**（测试 / 未来 KeyManager 注入 `NetworkIdentityProvider` → 网络 signer）。
  - 生产网络 key 导入 / NodeConfig 网络字段：**GAP-A DEFERRED**（本 ADR 不涉及）。
  - 运行时默认：无生产网络身份 ⇒ 网络层可 disabled（full / 无 key 模式 fail closed，不开假签名）。

### 3. Delegation API（设计；保证兼容）

- `runtime.consensus() -> &ConsensusNode`（delegate `driver.consensus()`）
- `runtime.validator() -> Option<&ValidatorRuntimeView>`（受控视图；actor 已入 driver ⇒ view 暴露
  validator_id / ledger / lock 只读视图 —— 实现细节 Stage C 评估，不破坏签名）
- full-node（无 validator）：driver actors = `[]`，`validator()` = `None`（与现状一致）。

### 4. Lifecycle（Stage D；仅设计）

Startup：storage → consensus + validator → driver → NetworkService → EventLoop → identity 注入。
Shutdown：EventLoop stop → NetworkService shutdown → Driver drop → Storage close。
（NodeRuntime 现无 shutdown 方法；Stage C 引入显式 shutdown —— 设计保留现有 drop 语义。）

### 5. Ownership / responsibilities boundary

引用 ADR-0057 `## Component Responsibilities`：Network = transport only；EventLoop = dispatch only；
Driver = consensus orchestration only；Runtime = lifecycle / assembly only。

## Non Goals / Limits（本 ADR 不授权）

- 禁止任何 Rust 代码实现（本 ADR = design only）。
- 不改 consensus transition / Finality / ForkChoice / ValidatorActor / SafetyStore / VoteLedger。
- 不扩展 SigningCapability；validator key 不作为 network identity；不改 NodeId canonical derivation。
- 不改 NetworkService / EventLoop 冻结结构。
- 不改 NodeConfig；不做生产网络 key loading（GAP-A DEFERRED）。
- 无 API breaking change（delegation 保持 `runtime.consensus()` / `runtime.validator()` 兼容）。

## Open Design Items（Stage C 前待定）

1. `NodeConsensusHandler` 的 driver 泛型化：Runtime 装配用 `NodeConsensusDriver<Box<dyn SigningCapability>>`
   （DynSigner）与 `NodeConsensusHandler<DynSigner, E>` —— E（outbound egress）具体类型 / 生命周期。
2. NetworkService 的 `Transport` 具体类型选择（MemoryTransport dev / 未来 adapter 注入）。
3. `validator()` 受控视图形状（actor 入 driver 后如何保留只读 API 而不复制 safety 状态）。
4. shutdown 显式化对既有 runtime_tests 的影响（RT-26..28 兼容策略）。
5. 网络 disabled 模式（无 identity / 无 transport）下 EventLoop 是否装配（可空 EventLoop）。

## Security Constraints

- Network != Consensus owner；Validator != Network identity；Runtime != Consensus executor。
- 迁移仅 orchestration ownership（ADR-0057）；不改变 Consensus safety authority / state semantics /
  Finality authority。

## Next Steps

- 待 Owner：ADR-0058 Design Freeze Review。
- 之后（各自单独授权）：Stage C Runtime wiring implementation；GAP-A 生产网络 key seam（独立步骤）。

---

> DRAFT（STEP 10-18I-B）。待 Owner 审查后 DESIGN FREEZE → 单独授权 IMPLEMENT。
