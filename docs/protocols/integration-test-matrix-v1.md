# Nova Chain — STEP 11-9 Integration Test Matrix Design V1

- **Status**: Draft（STEP 11-9；待 Review → Freeze）
- **Date**: 2026-08-30
- **Scope**: Network → Node → Consensus 端到端集成测试矩阵（**DESIGN only，不实现**）。
- **依据**（全部 READ-ONLY）：STEP 11-1（FROZEN）/ 11-2（FROZEN）/ 11-3（FROZEN）+
  10-11 External Integration Contract（FROZEN）+ consensus-spec-v1.md（FROZEN）+
  既有 consensus/network 测试。

## 覆盖矩阵（Input → Owner → Expected → Test Layer → Frozen Reference）

| # | 场景 | Input | Owner | Expected Result | Test Layer | Frozen Reference |
|---|---|---|---|---|---|---|
| 1 | Valid Vote | `ConsensusVote` wire → VoteMessage → `ConsensusEvent::Vote` | Network→Node→Consensus | Applied 或合法结果 | 11-6 集成 | 11-1 §4 / V-5 |
| 2 | Valid Proposal | `ConsensusProposal` → ProposalMessage → `SetProposal` | Network→Node→Consensus | Applied | 11-7 集成 | 11-1 §4 / B-1 |
| 3 | RoundTimeout | Node 本地构造 | Node | transition 处理 | 11-5 | 11-1 §7 / B-3 |
| 4 | Invalid envelope | 签名错 | Network | 拒 | 11-3 ✅ | N-4 |
| 5 | Invalid signature | envelope 签名伪造 | Network | `InvalidSignature` | 11-3 ✅ | N-4 |
| 6 | Sender mismatch | sender ≠ 验证 key | Network | `SenderMismatch` | 11-3 ✅ | N-4 |
| 7 | Unknown discriminator | `0x0B` | Network | decode 拒 | 11-2 ✅ | N-4 |
| 8 | Malformed bytes | 截断/畸形 | Network | decode 拒，无 panic | 11-9 | crypto-serialization §7 |
| 9 | Oversized payload | > max_msg_bytes | Network | `InvalidLength` | 11-3 ✅ | N-5 |
| 10 | Envelope valid + vote invalid | 双层签名独立 | Node→Consensus | Network Ok → Consensus Reject/Ignore | 11-6 | 11-1 §6 |
| 11 | Duplicate vote | 同 validator 同 target | Consensus | 去重不重复计权 | 10-9 ✅ | B-2 |
| 12 | Replay | 旧 height/round | Consensus | `Ignored{ContextMismatch}` | 10-5.1 ✅ | guards |
| 13 | Wrong context | height/round 不符 | Consensus | `Ignored` | 10-9 ✅ | guards |
| 14 | Terminal state | Finalized 后 vote | Consensus | `Ignored{Terminal}` | 10-5.1 ✅ | 修复 B |
| 15 | Deterministic ordering | 不同到达顺序 | Consensus | 同 transition 结果 | 11-11 | MF-12 |
| 16 | QC wire | `ConsensusQc` 承载 | Network | **DEFERRED**（不构造消费路径） | 11-8 | 11-1 §4/§12 |
| 17 | A11 proposer authority | NodeId ≠ proposer | — | **DEFERRED**（不新增 proposer 签名验证） | 11-10 | A11 |
| 18 | A6 equivocation | 双投 | — | **ASSUMPTION**（slashing DEFERRED） | 11-10 | A6 |
| 19 | Node 不执行 Consensus verification | Node 只 decode/dispatch | Node | Node 无 verify_vote/verify_qc | 11-10 | 11-1 §5 |
| 20 | Network 不解析 Consensus semantic payload | payload opaque | Network | Network 无语义验证 | 11-3 ✅ | 11-1 §5 |

## Serialization Boundary 影响

- **#1（Vote）** 依赖 ValidatorVote decode 路径：**TRACEABILITY GAP — SERIALIZATION BOUNDARY**
  （canonical 布局冻结 / ADR-0034 V-4 + crypto-serialization §8；专门 decode API 未冻结）。
- **#2（Proposal）** 依赖 ProposalRef wire encoding：**SPEC-NOT-FROZEN → DEFERRED**（11-1 §3）。
- 上述两项在 Serialization Boundary 裁决前**不得实现**（11-4 Design Freeze 前置）。

### ROUND 3 分类结论（B1 Deep Fact Audit）

- **#1（Vote）**：`ValidatorVote` decode = **SPEC-FROZEN / API-MISSING**
  （crypto-serialization §8 roundtrip 契约冻结 + ADR-0034 V-4 布局冻结；decode API 缺失实现，
  无隐含实现；decode 属 `nova-consensus::vote` 对称 API）→ 形成 **Minimal API Restoration Proposal**
  （等待授权，不写代码；Protocol change = NO / Consensus semantic = NO / Canonicalization = NO）。
- **#2（Proposal）**：`ProposalRef` encoding = **SPEC-NOT-FROZEN → DEFERRED**（11-1 §3）。
- 矩阵 #1/#2 标记 **BLOCKED**（不删除；待 Serialization Boundary 裁决后恢复）。

## 明确不做

- 不实现任何测试（DESIGN only）。
- 不新增 Consensus API / `ConsensusEvent` variant / QC ingestion / `external.rs`。
- 不修改 Consensus / ADR-0032。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：STEP 11-9 Integration Test Matrix Design V1（20 项覆盖矩阵 + Serialization Boundary 影响 + 硬边界） | MASTER PARALLEL EXECUTION ROUND 2 — Track C |
