# Nova Chain — Network ↔ Consensus Integration Design V1（11-1）

- **Status**: **FROZEN**（STEP 11-1；Network ↔ Consensus Integration Design V1 FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: 在 **Consensus 保持 FINAL FROZEN** 前提下，设计 **Network → Node → Consensus** 的集成路径：
  Network = wire/信封（不解析共识语义）；Node = decode/dispatch/construct logical input（不执行共识验证）；
  Consensus = 验证 + transition（唯一验证/转换 owner）。
- **依据**（全部 READ-ONLY）：ADR-0033~0040（FROZEN）+ 10-9~10-13（FROZEN/CLOSED）+ 10-11 External
  Integration Contract（FROZEN）+ 既有实现（network/consensus）。
- **本文件是设计契约文档，不是代码实现**；不改动任何冻结文件/Cargo 依赖；不创建新 consensus API。

---

## 0. 目的与边界

- **目的**：定义 Network ↔ Node ↔ Consensus 集成边界，使未来 Network 能承载 Vote/Proposal/QC，
  Node 能组装 `ConsensusEvent`，且**不改变任何冻结共识语义**。
- **三层职责严格分离**：
  - Network owns：transport / wire / envelope / gossip（payload opaque，不解析共识语义）。
  - Node owns：decode / classify / construct logical input / 本地 RoundTimeout（**不执行共识验证**）。
  - Consensus owns：`verify_vote`（V-5）/ `verify_qc`（F-6a）/ guards / transition。
- **本设计不创建**：新 Consensus API、新 `ConsensusEvent` 变体、新 DomainId、`external.rs`。

## 1. Frozen Dependencies

- ADR-0033 C-1（依赖方向）/ 0034 V-1~V-6 / 0035 D-1~D-5 / 0036 W-1~W-6 / 0037 B-1~B-6 / 0038 F-1~F-18 /
  0039 CP-1~CP-8 / 0040 FC-1~FC-14。
- 10-9（MF-1~MF-12）、10-10（consensus-spec）、10-11（External Integration Contract，L1~L5）。
- 冻结类型：`ValidatorVote` / `ProposalRef` / `QuorumCertificate` / `ConsensusEvent` /
  `ConsensusState` / `TransitionResult` / `MessageEnvelope` / `MessageType`。

## 2. Proposed Architecture

```
wire bytes → Network（Envelope / Transport / Gossip；payload opaque；不依赖 consensus crate）
           → Node（decode / classify / construct logical input；本地 RoundTimeout；不执行共识验证）
           → Consensus（verify_vote / verify_qc / guards → transition）→ TransitionResult → Node 路由
```

## 3. Wire Type Placement

- **wire 类型 = Network Phase**：`MessageType::ConsensusVote / ConsensusProposal / ConsensusQc`
  （Network 扩展；payload 为 **opaque bytes**；Network **不依赖** consensus crate）。
- **payload 内容**（复用冻结 canonical，不新增共识 canonicalization）：
  - Vote → `canonical_vote_payload(vote) ‖ signature(64B)`；
  - QC → `encode_qc(qc)`；
  - **ProposalRef wire representation**：仅在其对应编码规范**已冻结后**复用；**本设计不新定义 ProposalRef encoding**。
- **10-11 逻辑消息（VoteMessage / ProposalMessage / QcMessage）** = 语义层（Node 侧 decode 产物），非 wire 结构。

## 4. 逻辑消息映射（MF-11-2 / MF-11-3）

| wire payload | 语义层 | Consensus 映射 | 状态 |
|---|---|---|---|
| Vote | `VoteMessage{ValidatorVote, signature}` | `ConsensusEvent::Vote`（已有 variant） | ✅ 复用 |
| Proposal | `ProposalMessage{ProposalRef}` | `ConsensusEvent::SetProposal`（已有 variant） | ✅ 复用 |
| QC | `QcMessage{QuorumCertificate}` | **✕ 不映射到 ConsensusEvent（无 QC variant）** | ⚠️ **DEFERRED** |

- **QC Ingestion（MF-11-3）**：QcMessage 的合法 ingestion 必须**复用已冻结 Consensus API**；
  若冻结 API **无外部 QC 合法入口** ⇒ 标记 **DEFERRED**（作为后续 Consensus/Node integration design 的
  明确输入）。**本 STEP 不创造 ingestion API；不由 Node 决定进入 prevote_qcs / checkpoint / finality。**
- **不新增 `ConsensusEvent` 变体。**

## 5. Verification Ownership（MF-11-1）

```
Network envelope verify（网络域，N-4）            →  Network 职责
Node decode / classify / construct logical input  →  Node 职责（不含共识验证）
Consensus verify_vote / verify_qc / guards / transition  →  Consensus 职责（唯一验证 owner）
```

- **Node 不执行 V-5 / verify_qc**（不隐式成为 Consensus verifier）。
- **MF-2 "validated vote"** = Consensus 验证边界的**内部 precondition**（Consensus 侧完成 V-5）；
  进入 `ConsensusEvent::Vote` 的 vote 必须已通过 Consensus 验证边界。
- **不设计新 `Node → verify_vote()` API**（Node 只 decode/dispatch；pre-validation 需求留待后续接口设计）。

## 6. 双层签名独立（N-4）

- Layer 1（网络域）：envelope 签名覆盖 `version‖type‖payload`，sender = NodeId（network `verify_message`）。
- Layer 2（共识域）：`ValidatorVote`（`DomainId::ValidatorVote`，V-5）/ QC evidence（F-6a）。
- **envelope valid ≠ vote valid；vote valid ≠ envelope valid**；两层不可互相替代。
- **不新增 DomainId**。

## 7. RoundTimeout

> **RoundTimeout 是 Node-local event（B-3）**，由 Node 本地构造 `ConsensusEvent::RoundTimeout`；
> **不经过 Network**（无 Timeout 消息）。

## 8. Cargo 依赖

```
consensus → core/crypto（不变，C-1）
network   → core/crypto（不变；不依赖 consensus）
node      → network + consensus（组装层）
```

## 9. Determinism

- Node 只传**内容**（vote / proposal / QC 数据）入 transition；peer / arrival order / gossip /
  retry / transport timing / connection state **不得**进入 `ConsensusEvent` 或 transition 输入
  （MF-12 / 10-11 §8）。

## 10. A6 / A11 边界

- **A6（equivocation）**：不因集成新增检测/惩罚（保持 **ASSUMPTION**；slashing DEFERRED）。
- **A11（proposal 真实性）**：**Network identity ≠ Consensus proposer authority**——envelope 证明
  sender = NodeId，**不等于**证明 proposer 拥有合法 authority（A11 **DEFERRED**，归 PHASE 7）；
  不新增 proposer 签名验证到 consensus。

## 11. Security Boundary

- 双层独立验证**降低** network sender spoofing 与 validator signature forgery 风险。
- **不表述为**"双层签名保证 Proposal authenticity"（A11 = DEFERRED；Proposal 不被包装为已认证）。

## 12. QC Ingestion — DEFERRED 状态（明确记录）

> **当前冻结 Consensus API 无外部 QC ingestion 入口**（`ConsensusEvent` 无 QC variant；QC 由 transition
> 内部从 prevote/precommit quorum 组装，registry 由调用方维护）。因此**网络到达的外部 QC 的合法消费路径
> 未定义**，标记 **DEFERRED**。不得在 Draft/后续实现中自行补 ingestion API；若后续需要 ⇒ 触发 ADR-0041
> 审查（新 ingestion API / ConsensusEvent variant）。

## 13. Testing / Verification Plan（只设计，不写代码）

- envelope roundtrip / 未知类型 / 长度校验（network 既有测试）。
- 映射测试：payload ↔ 逻辑消息 ↔ `ConsensusEvent`（Node 组装，后续阶段）。
- 双层签名独立性：envelope 有效 + vote 签名错 ⇒ 拒绝；反之亦然。
- RoundTimeout 仅本地构造（无网络消息）断言。
- determinism：不同到达顺序 ⇒ 同 transition 结果（MF-12 T17/T23 语义）。
- QC ingestion：仅验证冻结 API 是否存在入口；**若否 ⇒ 测试标记 DEFERRED**（不断言 Node 自造路由）。

## 14. Open Questions（保留，QC ingestion 已 DEFERRED）

1. `MessageType::Consensus*` 注册：若涉及新 wire canonicalization / domain / signature ⇒ 重查 ADR-0041。
2. **Node 组装实现位置**：STEP 11-1 = Architecture/Design only；Node orchestration 实现归 Node Integration Phase。
3. QC ingestion：已按 MF-11-3 标记 **DEFERRED**（非"fork_choice vs checkpoint"二选一）。

## 15. ADR Requirement

> **ADR-0041 = NOT REQUIRED（默认）**：本设计是 10-11 契约的实例化（wire + Node 组装 + 明确验证 ownership）。
> **触发条件（一旦出现 HARD STOP → ADR-0041）**：新 canonicalization / size limit / signature / quorum /
> validation / transition / primitive / domain / **ingestion API / ConsensusEvent variant**。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-1 Network↔Consensus Integration Design V1（三层职责分离 + wire 承载 + 验证 ownership + 双层签名 + RoundTimeout + QC ingestion DEFERRED + A6/A11 边界） | STEP 11-1 DESIGN PROPOSAL v2 APPROVED（MF-11-1/2/3 PASS） |
| 2026-08-30 | **DESIGN FREEZE（11-1）**：Status Draft→FROZEN。Consensus 保持 FINAL FROZEN/UNCHANGED；Network/Node = Design boundary only；QC ingestion DEFERRED；A6=ASSUMPTION；A11=DEFERRED；Code/Consensus/external.rs/ADR-0041/Protocol Changes 全 0 | 用户裁决 🟢 APPROVED → DESIGN FREEZE |
