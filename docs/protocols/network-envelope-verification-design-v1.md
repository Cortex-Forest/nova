# Nova Chain — Network Envelope / Payload Verification Design V1（11-3）

- **Status**: **FROZEN**（STEP 11-3；Network Envelope / Payload Verification Design V1 FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 在 **STEP 11-1/11-2 FROZEN** 与 **Consensus FINAL FROZEN** 前提下，建立 Network 域的
  **完整 envelope 验证面**（Network envelope validation API）；payload 保持 **OPAQUE**，
  **不解析 Consensus semantic payload**。
- **依据**（全部 READ-ONLY）：STEP 11-1 `network-consensus-integration-design-v1.md`（FROZEN）
  §3/§5/§6/§8/§15 + 10-11 `consensus-external-integration-contract-v1.md`（FROZEN）§6/§7 +
  STEP 11-2 `network-wire-types-design-v1.md`（FROZEN）+ ADR-0032 N-4/N-5/N-7 +
  既有实现 `crates/network/src/message.rs` / `gossip.rs`。
- **本文件是设计契约文档，不是代码实现**；不改动任何冻结文件；不新增 Cargo 依赖；不修改 Consensus。

---

## 0. 目的与边界

- **目的**：为 3 个 Consensus wire 类型（`ConsensusVote` / `ConsensusProposal` / `ConsensusQc`）
  建立 Network 域的 envelope 验证边界——**Network envelope validation API**，非 Consensus validation。
- **范围**：仅 `nova-network` crate 内的验证函数 + 相应测试。
- **本 STEP 不实现**：Consensus semantic validation / Node event construction / QC ingestion。

## 1. 验证边界总图（Network vs Node/Consensus）

```
Network validation
    │
    ├─ envelope binary structure
    ├─ MessageType discriminator
    ├─ existing message-size constraint
    ├─ N-4 signature coverage
    ├─ sender binding
    │
    └─ payload = OPAQUE
             │
             ↓
        Node / Consensus
             │
             ├─ Vote validity
             ├─ QC evidence
             ├─ quorum
             ├─ context/replay
             └─ consensus transition
```

- **Network 可验证**：envelope structure / discriminator / existing size constraint /
  canonical envelope bytes / N-4 signature / sender binding / malformed envelope / unknown discriminator。
- **Network 不验证**：Vote validity / QC evidence / quorum / finality / fork choice /
  Consensus context / Consensus replay semantics / proposal authority / equivocation / slashing。
- **payload = OPAQUE**。

## 2. Frozen Dependencies

- STEP 11-1（FROZEN）：§3（wire 类型 = Network Phase；payload opaque；不依赖 consensus）、
  §5（验证 ownership）、§6（双层签名独立）、§8（Cargo 依赖）、§15（ADR-0041 默认 NOT REQUIRED）。
- 10-11（FROZEN）：§6（不新增验证规则）、§7（replay/duplicate/malformed 契约——语义 replay 归
  Consensus context guards）。
- STEP 11-2（FROZEN）：3 个 `MessageType` discriminator（0x08/0x09/0x0A）。
- ADR-0032：N-4（envelope 签名覆盖 `version‖type‖payload`）、N-5（gossip `max_msg_bytes` 既有）、
  N-7（安全边界）。本 STEP 不改 ADR-0032。

## 3. 设计决策

| # | 决策 | 依据 |
|---|---|---|
| **D1** | 新增 **Network envelope validation API**：`validate_consensus_envelope(vk, envelope, max_msg_bytes) -> Result<MessageType, NetworkError>`。① `verify_message`（N-4 签名 + sender 身份绑定）② `message_type ∈ {ConsensusVote, ConsensusProposal, ConsensusQc}`（否则 `InvalidMessageType`）③ `payload.len() <= max_msg_bytes`（**既有消息大小约束**，非"完整 payload validation"）④ 返回 `MessageType`（不引入新枚举）⑤ payload **OPAQUE 不解析**。**定位 = Network envelope validation；不是 Consensus validation** | 11-1 §3/§5/§6；Review MF（D1 收紧） |
| **D2** | 放置于 `message.rs`（紧邻 `verify_message`）；不新建模块 | 职责归属 |
| **D3** | 不新增 `NetworkError` 变体（复用 InvalidMessageType / InvalidLength / InvalidSignature / SenderMismatch） | 10-11 §6 |
| **D4** | `max_msg_bytes` 调用方传参（复用既有 `GossipConfig.max_msg_bytes=64K` / N-5）；**不新增 size limit** | 11-1 §15 / MF-11-2-2 |
| **D5** | `Cargo.toml` 不变（不依赖 consensus crate） | 11-1 §8 |
| **D6** | 双层签名独立性 Network 侧证明：opaque payload（伪装 vote/QC 字节）→ `Ok`（Network 不验证语义） | 11-1 §6 |
| **D7** | **Replay Boundary**：`validate_consensus_envelope` **不做语义 replay 检测**（不判断 payload 内容新旧——Consensus context guards 职责，10-11 §7）。Network 域 replay 相关仅既有 gossip 去重（N-5 `seen`）。重复调用同一有效 envelope → 均 Ok（无状态、无 replay 跟踪）。**不新增去重/时序逻辑** | 10-11 §7 / 10-5.1 / N-5 |
| **D8** | **Malformed Payload 边界**：Network 域"malformed"仅指 ① decode 长度/结构不符（既有 `decode` 拒绝）② 超既有 `max_msg_bytes`（D1③）。**payload 语义级 malformed（vote 字段错/签名错）归 Node/Consensus（STEP 11-4/11-6）** | 11-1 §5 |
| **D9** | **Signature Coverage 显式覆盖**：验证签名覆盖 `version‖type‖payload`（N-4）——篡改任一字段 ⇒ `InvalidSignature`；sender 篡改 ⇒ `SenderMismatch`（身份绑定） | ADR-0032 N-4 |

## 4. 测试计划（T1~T9）

| # | 检查项 | 断言 |
|---|---|---|
| T1 | 有效 Consensus envelope | 3 类型 → `Ok(MessageType)` |
| T2 | unknown / 非 Consensus discriminator | Handshake/…/Status → `Err(InvalidMessageType)` |
| T3 | existing size constraint | payload > max_msg_bytes → `Err(InvalidLength)` |
| T4 | tampering + signature coverage + sender binding | 篡改 payload/type/version → `InvalidSignature`；sender → `SenderMismatch` |
| T5 | 双层签名独立性（不解析语义） | opaque payload（伪装 vote/QC 字节，含 185B/长字节）→ `Ok` |
| T6 | size 边界 | max_msg_bytes=0：空 payload Ok / 非空 Err |
| T7 | canonical envelope bytes（roundtrip） | encode→decode→validate 一致性 |
| T8 | unknown discriminator 解码 | `0x0B` decode → `InvalidMessageType`（既有测试，显式覆盖） |
| T9 | replay boundary（无状态） | 同一有效 envelope 重复验证 → 均 `Ok`（Network 不跟踪 replay） |

## 5. 明确不做（硬边界）

- ❌ 不验证 Vote validity / QC evidence / quorum / finality / fork choice（Consensus 域）。
- ❌ 不构造 `VoteMessage / ProposalMessage / QcMessage` / 不组装 `ConsensusEvent`（Node 层，STEP 11-4）。
- ❌ 不新增 `ConsensusEvent` variant / QC ingestion / `external.rs`。
- ❌ 不定义 payload 结构 / ProposalRef encoding / 不新增 canonicalization / domain / signature / transition。
- ❌ 不做语义 replay 检测 / 不新增去重 / 不跟踪到达时序（归 Consensus / gossip）。
- ❌ 不改 consensus / node / ADR-0032。

## 6. ADR 边界

- **ADR-0032**：UNCHANGED（Network 域 envelope 验证边界，N-4/N-5/N-7 既有）。
- **ADR-0041**：NOT REQUIRED（无 canonicalization / signature / domain / quorum / 共识 validation /
  transition / ingestion / ConsensusEvent variant；size 复用既有约束非新增）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-3 Network Envelope / Payload Verification Design V1（Network envelope validation API + 完整验证边界图 + payload OPAQUE + T1~T9 + 硬边界 + ADR 边界） | STEP 11-3 DESIGN PROPOSAL v2（对齐 MASTER CONTROLLER v2.0 STEP 11-3 全面目标） |
| 2026-08-30 | **DESIGN FREEZE（11-3）**：Status Draft→FROZEN。D1 收紧（Micro-Freeze）：函数定位 = Network envelope validation API（非 Consensus validation）；`max_msg_bytes` 表述 = 既有消息大小约束（非"完整 payload validation"）。其余决策 D2~D9 / T1~T9 APPROVED。Consensus 保持 FINAL FROZEN/UNCHANGED；QC ingestion DEFERRED；ADR-0041 NOT REQUIRED；Code/Consensus/Node/external.rs/Protocol Changes 全 0 | 用户裁决 🟡 APPROVED WITH 1 MICRO-FREEZE（D1 收紧）→ DESIGN FREEZE |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（11-3）**：`crates/network/src/message.rs` 实现 `validate_consensus_envelope`（Network envelope validation API：N-4 签名 + sender 身份绑定 → discriminator ∈ {0x08/0x09/0x0A} → 既有 size constraint → payload OPAQUE）+ T1~T9（T8 由既有 decode 测试覆盖）；nova-network lib 26 tests；四项 Gate 全 PASS（fmt/check/test/clippy `-D warnings`）。Security/Protocol Review APPROVED：0 BLOCKER / 0 MUST-FIX / 0 Protocol Violation | 用户授权 MASTER PARALLEL EXECUTION Track A → commit `8582f97` |
| 2026-08-30 | **FINAL FREEZE（11-3）**：STEP 11-3 全链封版（DESIGN FROZEN + IMPLEMENTATION COMPLETE）。仅文档变更记录更新；**不修改实现代码**。Consensus/Node/ADR-0032 UNCHANGED；external.rs NOT CREATED；QC ingestion DEFERRED；payload OPAQUE；Protocol changes 0 | 用户裁决 → 独立 documentation commit |
