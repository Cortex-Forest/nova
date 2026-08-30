# Nova Chain — Network Wire Types Design V1（11-2）

- **Status**: **FROZEN**（STEP 11-2；Network Wire Types Design V1 FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 在 **STEP 11-1 FROZEN 设计** 与 **Consensus FINAL FROZEN** 前提下，为 Network crate 注册
  Consensus wire 类型（`MessageType` discriminator），payload 保持 opaque；**只注册类型，不实现语义**。
- **依据**（全部 READ-ONLY）：STEP 11-1 `network-consensus-integration-design-v1.md`（FROZEN）
  §3/§4/§5/§8/§12/§15 + ADR-0032 N-4/N-5（Proposed；**本 STEP 不修改**）+
  既有实现 `crates/network/src/message.rs`。
- **本文件是设计契约文档，不是代码实现**；不改动任何冻结文件；不新增 Cargo 依赖；不修改 Consensus。

---

## 0. 目的与边界

- **目的**：落实 11-1 §3 的 wire 类型注册——Network `MessageType` 增加 3 个 Consensus wire
  discriminator，使未来 Network 信封能承载 Vote/Proposal/QC 的 opaque payload，且**不改变任何冻结共识语义**。
- **范围**：仅 `nova-network` crate 内的 `MessageType` 扩展 + 相应测试。
- **本 STEP 不实现**：payload 结构 / 语义验证 / Node 组装 / QC ingestion / ProposalRef encoding。

## 1. Frozen Dependencies

- STEP 11-1（FROZEN）：§3（wire 类型 = Network Phase；payload opaque；不依赖 consensus）、
  §4（逻辑消息映射）、§5（验证 ownership）、§6（双层签名独立）、§8（Cargo 依赖）、
  §12（QC ingestion DEFERRED）、§15（ADR-0041 NOT REQUIRED 默认）。
- ADR-0032：N-4（`MessageEnvelope` / 签名覆盖 `version‖type‖payload` / 7 类基础）、
  N-5（gossip `max_msg_bytes` 既有约束）。本 STEP 仅扩展 discriminator，**不改变 N-4 架构原则**。
- 既有实现：`crates/network/src/message.rs`（`MessageType` / `TryFrom<u8>` / `encode` / `decode` /
  `sign_message` / `verify_message`）。

## 2. Wire Type Registration（MF-11-2-1 落实）

`MessageType` 新增 3 变体（紧接既有 7 类 0x01~0x07）：

| 变体 | 字节值 |
|---|---|
| `ConsensusVote` | `0x08` |
| `ConsensusProposal` | `0x09` |
| `ConsensusQc` | `0x0A` |

- **MF-11-2-1（注册值 ≠ 协议语义）**：
  > 这些值只是 Network `MessageType` 的 wire discriminator；**不得在 Network 层赋予 Vote/QC/Proposal
  > 的验证、权限、共识状态或路由语义**。
- 尤其：`ConsensusQc = 0x0A` **不代表 QC 已具有可消费的 Consensus ingestion path**。
- **QC ingestion 继续 DEFERRED**（11-1 §12）。

## 3. Payload（opaque）

- 3 类 payload 均为 opaque `Vec<u8>`；Network **不解析 / 不验证 / 不构造**共识语义（11-1 §3/§5）。
- **MF-11-2-2（size 措辞）**：
  > **在既有 Network envelope / message size constraints 内**（`max_msg_bytes`，ADR-0032 N-5），
  > payload 对任意字节内容保持 opaque、无损 roundtrip。
  - **不新增** size limit；不产生"Consensus payload 可无限大"的协议暗示。
- `ConsensusProposal` payload **不定义结构**（ProposalRef 无冻结 encoding，11-1 §3）。
- payload 的构造/解析（`canonical_vote_payload ‖ signature` / `encode_qc`）属 consensus 域，
  归 Node/后续层；**本 STEP 不涉及**。

## 4. 依赖（D3）

- `Cargo.toml` **不变**：`network → core + crypto`；**不新增 consensus 依赖**（11-1 §8 / ADR-0032 N-1）。

## 5. 明确不做（硬边界）

- ❌ 不定义 `VoteMessage / ProposalMessage / QcMessage` 结构（Node 层语义，STEP 11-4）。
- ❌ 不构造/解析 `canonical_vote_payload` / `encode_qc`（consensus 域）。
- ❌ 不新增 `ConsensusEvent` 变体。
- ❌ 不改 consensus crate / 不创建 `external.rs` / 不实现 QC ingestion。
- ❌ 不新增 size limit / domain / signature / canonicalization。

## 6. ADR 边界（MF-11-2-2 落实）

- **ADR-0032：本轮不修改**。当前动作仅为 Network `MessageType` 增加 3 个 discriminator
  （payload opaque），属既有 N-4 范围内的实现性扩展，**不改变 ADR-0032 的架构原则**。
  > 规则：若 11-2 仅注册 MessageType ⇒ STEP 11-2 Design 文档记录即可；若发现需改变 ADR-0032
  > 架构原则 ⇒ **HARD STOP → ADR review**。
- **ADR-0041：NOT REQUIRED**（无 canonicalization / size limit / signature / domain / ingestion API /
  ConsensusEvent variant 变更；11-1 §15）。

## 7. 测试计划（T1~T7）

- **T1** 全 10 类 roundtrip（encode→decode 全等）。
- **T2** 3 个 Consensus 类型 payload opaque roundtrip（**在既有 size constraints 内**任意字节内容无损）。
- **T3** 3 个 Consensus 类型 sign→verify ok（envelope 签名有效）。
- **T4** 篡改 payload/type/version/sender ⇒ verify 拒绝（N-4 双层签名独立基础）。
- **T5** decode 拒未知类型 `0x0B`（0x08~0x0A 已定义后）。
- **T6** 字节值断言：`0x08 / 0x09 / 0x0A` + `TryFrom` 双向。
- **T7** 语义中性断言：Network 对 3 类 payload 不做结构验证（opaque）。

## 8. 最终边界总览（FROZEN）

```
STEP 11-2  Network Wire Types
────────────────────────────
MessageType:  0x08 ConsensusVote / 0x09 ConsensusProposal / 0x0A ConsensusQc
Payload:      opaque Vec<u8>；Network 不解析共识语义
Network:      不依赖 consensus；不 verify_vote；不 verify_qc；不构造 ConsensusEvent；不决定 QC route
Consensus:    FINAL FROZEN / UNCHANGED
Node:         本 STEP 不实现
QC ingestion: DEFERRED
ProposalRef encoding: 本 STEP 不定义
Size:         不新增限制；仅遵守既有 Network envelope/message constraints
ADR-0032:     不修改，除非发现架构原则发生变化
ADR-0041:     NOT REQUIRED
external.rs:  NOT CREATED
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-2 Network Wire Types Design V1（MessageType 3 discriminator + opaque payload + 测试计划 + 硬边界 + ADR 边界） | STEP 11-2 DESIGN PROPOSAL v1 🟡 APPROVED WITH 2 MICRO-FREEZES |
| 2026-08-30 | **DESIGN FREEZE（11-2）**：Status Draft→FROZEN。MF-11-2-1（注册值≠协议语义）与 MF-11-2-2（ADR-0032 不修改 / size 措辞仅引用既有约束）已落实；Consensus 保持 FINAL FROZEN/UNCHANGED；QC ingestion DEFERRED；ADR-0041 NOT REQUIRED；Code/Consensus/Node/external.rs/Protocol Changes 全 0 | 用户裁决 🟡 APPROVED WITH 2 MICRO-FREEZES → DESIGN FREEZE |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（11-2）**：`crates/network/src/message.rs` 实现 3 个 `MessageType` discriminator（`ConsensusVote=0x08` / `ConsensusProposal=0x09` / `ConsensusQc=0x0A`）+ `TryFrom<u8>` 映射 + 文档注释更新；T1~T7 全 PASS（lib 18 tests）；四项 Gate 全 PASS（fmt/check/test/clippy `-D warnings`）。仅该文件变更（+115/-5）。Security/Protocol Review APPROVED：0 BLOCKER / 0 MUST-FIX / 0 Protocol Violation | 用户授权 STEP 11-2 IMPLEMENTATION → commit `b09c3aa` |
| 2026-08-30 | **FINAL FREEZE（11-2）**：STEP 11-2 全链封版（DESIGN FROZEN + IMPLEMENTATION COMPLETE）。仅文档变更记录更新；**不修改实现代码**。Consensus/Node/ADR-0032 UNCHANGED；external.rs NOT CREATED；QC ingestion DEFERRED；payload OPAQUE；Protocol changes 0 | 用户裁决 🟢 APPROVED → STEP 11-2 FINAL FREEZE（独立 documentation commit） |
