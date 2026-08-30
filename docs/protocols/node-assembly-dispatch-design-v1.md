# Nova Chain — Node Assembly / Dispatch Design V1（11-4）

- **Status**: **FROZEN**（STEP 11-4；Node Assembly / Dispatch Design V1 FINAL FREEZE，2026-08-30）
- **Date**: 2026-08-30
- **Scope**: Node 组装层（decode / classify / construct / dispatch / route）的**设计契约**；
  **本 STEP 不写 Node 代码**（实现需单独授权）。
- **依据**（全部 READ-ONLY）：STEP 11-1（FROZEN）§3/§5/§7 + 11-2（FROZEN）+ 11-3（FROZEN）+
  10-11（FROZEN）L1/L5 + P0-B1（FINAL FROZEN，`decode_validator_vote` 恢复）+ 既有实现
  （network / consensus / node crate）。

## 0. 目的与边界

- **目的**：冻结 Node 组装层边界——Node 接收 Network 已验证的 envelope，decode/classify/construct
  `ConsensusEvent`，调用 Consensus `transition`，路由 `TransitionResult`；**不执行 Consensus verification**。
- **本 STEP 不实现**：Node 代码（Design only）；ProposalRef encoding；QC ingestion；A11 proposer authority。

## 1. FACT AUDIT（关键 API 现状）

| 层 | API | 状态 |
|---|---|---|
| Network | `MessageEnvelope` / `MessageType`（10 类）/ `decode` / `validate_consensus_envelope`（11-3） | FROZEN/IMPLEMENTED |
| Consensus | `ConsensusEvent{Vote{vote,signature}, SetProposal(ProposalRef), RoundTimeout}` / `transition` / `TransitionResult` / `decode_validator_vote`（P0-B1 恢复）/ `decode_qc` / `verify_vote` | FROZEN/IMPLEMENTED |
| Node | `crates/node`：零依赖，仅 `config` 骨架 | NOT IMPLEMENTED（组装层缺失） |

## 2. 三条 Node 组装路径裁决

| 路径 | 当前状态 | 11-4 处理 |
|---|---|---|
| **Vote** | `decode_validator_vote` 已恢复并 FINAL FROZEN（P0-B1） | ✅ **可进入 Node 设计**（classify → decode → construct） |
| **Proposal** | `ProposalRef` wire encoding **未冻结**（SPEC-NOT-FROZEN，11-1 §3） | 🔒 **DEFERRED**（不发明 encoding） |
| **QC** | `decode_qc`/`verify_qc` 存在，但 ingestion **未定义**（无合法入口） | 🔒 **DEFERRED**（不创建 ingestion API） |

> **注意**：Vote decode 已恢复 **不** 意味着 ProposalRef encoding / QC ingestion / Node implementation
> 可一并补上。三条路径独立裁决。

## 3. 核心边界（锁定）

```
Network
  │
  ├─ decode envelope
  ├─ envelope validation（validate_consensus_envelope，N-4 + discriminator + size）
  └─ payload = OPAQUE
        │
        ▼
Node
  │
  ├─ classify discriminator（MessageType ∈ Consensus 3 类）
  ├─ Vote → decode_validator_vote（Node 调用 Consensus 冻结 API）
  ├─ construct ConsensusEvent
  ├─ RoundTimeout（local event，B-3）
  └─ route TransitionResult（Applied / Ignored / Rejected）
        │
        ▼
Consensus
  │
  ├─ verify_vote（V-5）
  ├─ context / terminal guards
  └─ transition（MF-12）
```

## 4. 职责与边界声明（锁定）

| 项 | 归属 |
|---|---|
| Envelope signature / sender binding | **Network**（N-4） |
| Payload opaque（不解析共识语义） | **Network** |
| Vote semantic signature | **Consensus**（verify_vote V-5） |
| Semantic replay / context / terminal | **Consensus**（guards） |
| RoundTimeout | **Node-local**（B-3，不经过 Network） |
| Vote decode（121B canonical） | **Consensus**（`decode_validator_vote`；Node 调用） |
| Node decode/classify/construct/route | **Node**（不含验证） |
| ProposalRef encoding | **DEFERRED**（A11 = DEFERRED） |
| QC ingestion | **DEFERRED** |
| Proposer authority | **A11 = DEFERRED**（NodeId ≠ proposer） |

## 5. Vote 组装路径（可设计，实现待授权）

```
ConsensusVote wire → Network decode + validate_consensus_envelope
    → Node classify（MessageType::ConsensusVote）
    → Node decode payload = canonical_vote_payload(121B) ‖ signature(64B)
        → vote = decode_validator_vote(payload[..121])?      （Consensus API）
        → signature = payload[121..185]
    → Node construct ConsensusEvent::Vote { vote, signature }
    → Node call transition(state, event, context, chain_id, set, genesis_hash, dag)
    → Node route TransitionResult
```

- **Node 不验证 vote 签名**（verify_vote 是 Consensus precondition，MF-2；由 Consensus 验证边界保证）。
- Node 只做 decode + construct + dispatch（11-1 §5）。

## 6. 明确不做（硬边界）

- ❌ 不写 Node 代码（本 STEP 仅设计冻结；实现需单独授权）。
- ❌ 不定义 ProposalRef wire encoding（保持 DEFERRED）。
- ❌ 不创建 QC ingestion API / `ConsensusEvent::Qc`（保持 DEFERRED）。
- ❌ 不实现 A11 proposer authority（保持 DEFERRED）。
- ❌ 不修改 Consensus（decode_validator_vote 已冻结，不再动）。
- ❌ 不新增 canonicalization / signature / domain / quorum / validation / transition / ingestion API。
- ❌ 不创建 `external.rs`。

## 7. ADR 边界

- **ADR-0032**：UNCHANGED。
- **ADR-0041**：NOT REQUIRED（无 canonicalization / signature / domain / quorum / 共识 validation /
  transition / ingestion / ConsensusEvent variant）。
- **依赖方向**：`node → network + consensus`（11-1 §8 已批准；实现授权时落地 Cargo，本 STEP 不落地）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Node Assembly / Dispatch Design V1（三路径裁决 Vote✅/Proposal🔒/QC🔒 + 核心边界 + 职责归属 + Vote 组装路径 + 硬边界） | STEP 11-4 DESIGN（P0-B1 FINAL FROZEN 后） |
| 2026-08-30 | **DESIGN FREEZE（11-4）**：Status Draft→FROZEN。三路径裁决锁定（Vote ✅ 可进设计 / Proposal DEFERRED / QC DEFERRED）；Node 不执行 Consensus verification；semantic replay=Consensus；envelope signature=Network；vote signature=Consensus；A11 DEFERRED。**不写 Node 代码**；Code/Consensus/ADR-0032/external.rs/Protocol Changes 全 0 | 用户裁决 → 11-4 DESIGN FREEZE（独立 documentation commit） |
| 2026-08-30 | **IMPLEMENTATION COMPLETE（11-4）**：`crates/node` 落地 `node → network + consensus + crypto` 依赖（Cargo.lock 同步）；`assembly.rs` 实现 `ConsensusNode`（`handle_envelope` Vote 路径 + `round_timeout` Node-local + `classify_vote_payload` 121B+64B + `TransitionResult` 路由 + `apply_result` MF-12 契约 3）+ `NodeError`（node 自有，无新增 network/consensus 错误）；nova-node 7 tests（6 新增：valid vote Applied / wrong context Ignored / timeout round 推进 / bad envelope sig / unsupported Proposal / bad payload len / payload roundtrip）；四项 Gate 全 PASS；Security/Protocol Review 0 Blocker/0 Must-Fix/0 Protocol Violation。边界确认：Node 不调用 verify_vote（MF-2 precondition 归 Consensus 验证边界，11-6 明确）；Proposal/QC/A11 全 DEFERRED（ConsensusProposal → UnsupportedMessage） | 用户授权 STEP 11-4 Implementation → commit `437da98` |
| 2026-08-30 | **FINAL FREEZE（11-4）**：STEP 11-4 全链封版（DESIGN FROZEN + IMPLEMENTATION COMPLETE）。仅文档变更记录更新；**不修改实现代码/不改变协议**。Vote/RoundTimeout ✅；ProposalRef / QC ingestion / A11 保持 DEFERRED；Consensus/Network/ADR-0032 UNCHANGED；external.rs NOT CREATED；Protocol changes 0 | 用户裁决 → STEP 11-4 FINAL FREEZE（独立 documentation commit） |
