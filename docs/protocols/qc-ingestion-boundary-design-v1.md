# Nova Chain — QC Ingestion Boundary Design V1（11-8）

- **Status**: Draft（STEP 11-8；QC Ingestion Boundary Design；待统一 Independent Review；
  **只设计不实现**）
- **Date**: 2026-08-30
- **Scope**: 审计冻结 Consensus API 是否存在外部 QC 合法 ingestion 入口；定义 ingestion 边界。
- **依据**（全部 READ-ONLY）：ADR-0038 F-2/F-6a + 11-1 §4/§12 + 10-11 L1 + integration.rs
  （QcRegistry）/ finality.rs（verify_qc）/ fork_choice.rs 实现。

## 0. FACT AUDIT

| API | 位置 | 行为 |
|---|---|---|
| `decode_qc` | finality.rs | QC bytes → `QuorumCertificate`（结构解析） |
| `verify_qc(qc, set, genesis_hash, dag)` | finality.rs | F-6a：target∈DAG → vset → 升序 → duplicate → 逐条 verify_vote → quorum |
| `QcRegistry::admit(qc)` | integration.rs | **不含验证**（canonical 去重 + bounded set；注释明确"调用方保证只对 PrevoteQC 调用"） |
| `QcRegistry::prevote_qcs()` | integration.rs | fork_choice 消费（确定性 BTreeMap 序） |
| `ConsensusEvent` | integration.rs | **无 QC variant** |

## 1. 结论：外部 QC Ingestion = NOT FOUND → DEFERRED

```
外部网络到达 QC 的合法消费路径：未定义。
原因:
  1. QcRegistry::admit 不验证（F-6a 不在 admit 内）——外部 QC 直接 admit 绕过 verify_qc。
  2. Node 不执行 verify_qc（11-1 §5）——Node 不能自建 verify+admit 链路。
  3. ConsensusEvent 无 QC variant——transition 无 QC 入口。
  4. 无冻结的"QC ingestion 门面"（对比 11-6 verify_vote_input 门面，QC 侧不存在）。
⇒ 与 11-1 §12 一致：DEFERRED（无冻结合法入口，不造 API）。
```

## 2. 未来推进路径（仅设计，触发 ADR）

若项目所有者决定推进 QC ingestion，候选 API 形状（**不实现、不预设 ADR**）：
```rust
// Consensus 侧 QC ingestion 门面（对比 verify_vote_input）：
// verify_qc（F-6a）→ registry admit（Prevote-only）→ 返回 QcAdmission
pub fn ingest_qc_input(
    qc: &QuorumCertificate,
    set: &ValidatorSet,
    expected_genesis_hash: &[u8; 32],
    dag: &Dag,
    registry: &mut QcRegistry,
) -> Result<QcAdmission, FinalityError>
```
- 或 `ConsensusEvent::Qc`（**B3 明确禁止**——需完整协议设计 + ADR）。
- **触发条件**：新 ingestion API / ConsensusEvent variant ⇒ **HARD STOP → ADR / Protocol Review**。

## 3. 明确不做（本设计）

- ❌ 不实现 ingestion API / `ConsensusEvent::Qc`。
- ❌ Node 不决定 QC 消费路径（prevote_qcs / checkpoint / finality 归 Consensus）。
- ❌ 不修改 Consensus / 冻结规范 / external.rs。
- ❌ 不因"链路跑通"造 API。

## 4. 测试计划（设计）

- 维持现状：`ConsensusQc` wire 仅承载（11-2）；无 ingestion 断言（11-9 矩阵 #16 DEFERRED）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：QC Ingestion Boundary Design V1（审计冻结 API → NOT FOUND → DEFERRED；未来路径 ADR 触发标记） | 用户授权并行 STEP 11-8（仅设计不实现） |
