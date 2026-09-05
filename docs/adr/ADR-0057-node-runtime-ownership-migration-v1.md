# ADR-0057 Node Runtime Ownership Migration

## Status

DESIGN FROZEN（STEP 10-18I-A Closure / ADR-0057 v2 Design Freeze Review，2026-09-05）

Freeze Scope:
This ADR freezes ownership boundaries and migration design only.
It does NOT authorize Runtime wiring implementation.

## Context

当前 ownership（两处 duplication）：

```
NodeRuntime owns:
  - ConsensusNode
  - ValidatorRuntime（含 ValidatorActor）

NodeConsensusDriver owns:
  - ConsensusNode
  - ValidatorActor
```

- `NodeRuntime`（STEP 10-16）按固定顺序装配：genesis → chain storage → ConsensusNode →
  （validator mode）KeyProvider → SafetyStore → ValidatorActor。
- `NodeConsensusDriver`（STEP 10-15O）是 consensus 编排 owner：own `ConsensusNode` + `ValidatorActor`，
  提供 submit_proposal / submit_local_vote / submit_remote_vote / submit_inbound_qc /
  process_transition_derived（10-18G-1）与 outbound semantic seam。
- 10-18E/F/G/H/I-A 已把 NetworkService / EventLoop / Node wiring / NetworkIdentity seam 建立，
  但尚未装配进 NodeRuntime（GAP-A Controlled Integration：只到 seam 层）。
- 一旦要把 EventLoop/Driver 作为 Runtime 字段，`ConsensusNode` 与 `ValidatorActor` 同时被
  Runtime 与 Driver 持有 ⇒ ownership duplication。

## Problem

需要未来统一为单一 **Runtime lifecycle owner**，同时保持既有公共 API 兼容：

- `runtime.consensus()` 兼容
- `runtime.validator()` 兼容
- runtime_tests（RT-26..28）兼容
- 不破坏 10-15O / 10-16 已冻结语义

## Decision (Design Only)

未来目标（授权实现前仅设计）：

Future NodeRuntime composition:

```
NodeRuntime
│
├── NodeConsensusDriver
│
├── EventLoop
│
├── NetworkService
│
└── NetworkIdentity
```

> NetworkService 是**独立 ownership entity**（10-18E：own Transport / PeerManager / queues）。
> 禁止表述「EventLoop owns NetworkService」——EventLoop 只 dispatch、不拥有网络状态；
> 两者在本 ADR 中为 Runtime 下各自独立的组件（装配关系见 Migration Stage B/C）。

NodeConsensusDriver owns:

```
- ConsensusNode
- ValidatorActor
```

Runtime 提供 **delegation API**（不直接持有 consensus / actor）：

```
runtime.consensus()   → driver.consensus()      （delegate）
runtime.validator()   → driver actor 视图        （delegate / 受控视图）
```

## Non Goals

明确禁止（本 ADR 不授权任何语义 / 结构变更）：

- 修改 consensus transition
- 不改变 ConsensusState canonical structure（migration 仅 orchestration handle 让渡；语义 owner 仍为 ConsensusNode）
- 不改变 Finality semantics
- 不改变 ForkChoice logic
- 不重写 ValidatorActor
- 不修改 SafetyStore
- 不修改 VoteLedger
- 不扩展 SigningCapability
- 不允许 validator key 作为 network identity
- 不改变 NodeId canonical derivation
- 修改 NetworkService / EventLoop（10-18E/F 冻结）
- 生产 NodeConfig 网络 key 实现（GAP-A）

> Runtime ownership migration 只改变 **orchestration ownership**；不会改变：
> Consensus safety authority、Consensus state semantics、Finality authority。

## Migration Plan

### Migration Stage A: NetworkIdentity seam
- Status: **Completed (10-18I-A)**
- 内容：建立 `NetworkSigner` / `NetworkIdentityProvider`（node crate seam；软件实现 test/dev）；
  但不进入 Runtime（GAP-A Controlled Integration）。

### Migration Stage B: Runtime composition design
- Status: Future
- 内容：设计 `NodeRuntime` / `NodeConsensusDriver` / `EventLoop` / `NetworkService` /
  `NetworkIdentity` 之间关系与 delegation API；**禁止代码实现**（本 ADR Design Only）。

### Migration Stage C: Runtime wiring implementation
- Status: Future
- 内容：实际装配 `Runtime → Driver / EventLoop / NetworkService`；
  **需要 Owner 单独授权**（触及 ownership migration）。

### Migration Stage D: Lifecycle integration
- Status: Future
- 内容：shutdown 顺序：
  EventLoop stop → NetworkService shutdown → Driver shutdown → Storage close

## Component Responsibilities

### Network Layer（NetworkService）
- Owns: Transport、Envelope verification、Network routing
- Does NOT own: Consensus、Finality、Vote verification

---

### EventLoop
- Owns: Event dispatch、Handler invocation
- Does NOT own: Consensus transition、QC verification、Actor locking

---

### NodeConsensusDriver
- Owns: Consensus orchestration、Consensus ingress/egress adaptation
- Does NOT own: Transport、NetworkService

---

### NodeRuntime
- Owns: Lifecycle composition、Dependency assembly
- Does NOT own: Consensus execution rules

## Security Constraints

迁移全程必须保持：

- Network != Consensus owner
- Validator != Network identity
- Runtime != Consensus executor

（EventLoop/NetworkService 仍不解析 consensus；Driver 仍不拥有 Transport/NetworkService；
NetworkIdentity 与 validator identity 分离。）
