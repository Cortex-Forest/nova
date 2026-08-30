# Nova Chain — P7-4 Block Lifecycle Final Freeze V1

- **Status**: **FROZEN**（P7-4 Block Lifecycle Final Review / Freeze；2026-08-31）
- **Date**: 2026-08-31
- **Scope**: P7-4 Block 执行/生命周期集成封版（nova-runtime 协调层；E1=A / E2=B / E3=A 冻结）。

## 0. 冻结基线（固化）

```
P7-3 Block Validation             FINAL / FROZEN
P7-4 Block Lifecycle Design       FROZEN（5fd26b6）
P7-4 Block Lifecycle              FINAL / IMPLEMENTED（6eef166）
P7-4 Final Review                 FINAL / FROZEN（本记录）
────────────────────────────────────────────────
Git 基线: HEAD 6eef166 · CLEAN
Final Review Gates（重跑）: fmt / check / clippy / workspace test 全 PASS
Security: 0 Blocker / 0 High / 0 Medium / 0 Low
Protocol Defect: NO · Security Defect: NO
```

## 1. 冻结内容（不得改变除非新 ADR / Protocol Review）

| 项 | 冻结值 |
|---|---|
| 协调层 crate | `nova-runtime`（E1=A）：依赖 `{ nova-core, nova-crypto, nova-execution, nova-storage }`；本阶段不引入 consensus 语义 |
| 依赖方向 | `nova-runtime → { core, crypto, execution, storage }`（上游消费，ADR-0025 合法；仅禁 storage→execution 反向）；`nova-node` 依赖边界不变（不引入 execution/storage） |
| 分层步骤 API（E2=B） | 无单 `process_block`；调用方按序调用：`decode_block（①）→ validate_block_signature（②）→ validate_transaction_root（③）→ execute_and_verify_state_root（④）→ validate_height_parent（⑤）→ commit_block（⑥）` |
| ④ 职责 | `execute_block`（execution，纯计算）→ `tx_changes` → `calculate_state_root`（storage，只读重算）→ `verify_block_state_root`（比对 header.state_root）；**不提交**（commit 归 ⑥） |
| ⑥ 职责 | `apply_block`（storage，区块级原子事务，snapshot/rollback） |
| 错误模型（E3=A） | `BlockPipelineError`：Decode(BlockCodecError) / Validation(BlockValidationFailure{Block(BlockValidationError) \| StateRoot(BlockStateRootError)}) / Execution(BlockError) / Storage(StorageError)；直接包装底层错误，不改变语义 |
| 委托纪律 | runtime **不重造**冻结函数（P7-2/3、8D）；只做跨层组合、错误包装、依赖集中 |
| authority boundary | `validate_block_signature` 纯签名（P7-3 委托），无 membership/authority/eligibility；A11 = DEFERRED |

## 2. Final Review 结果

```
FACT AUDIT:       PASS（runtime block.rs 与冻结设计一致；Git CLEAN）
协议一致性（R）:   R1~R8 全 PASS（E1/E2/E3 / 职责分离 / 委托 / 依赖边界 / authority / 冻结零改动）
测试证据（重跑）:  nova-runtime 6 passed / 0 failed
                  workspace 全 PASS / 0 failed
四项 Gate（重跑）: FMT / CHECK / CLIPPY / TEST 全 PASS
Security:         S1~S10 全 PASS
Git Scope:        PASS（Cargo.toml + Cargo.lock + crates/runtime/，6eef166）
```

## 3. 测试覆盖（nova-runtime 6 tests）

- 全管线 ok：① decode roundtrip + ②③⑤ 验证 + ④ 执行+state_root + ⑥ 提交落库（root == header.state_root）。
- ② 签名篡改 ⇒ `Validation(Block(InvalidProposerSignature))`（④ 不执行）。
- ③ body 篡改 ⇒ `Validation(Block(TransactionRootMismatch))`。
- ④ state_root 篡改重签 ⇒ `Validation(StateRoot(Mismatch))`。
- ⑤ height 不连续 / parent_hash 不匹配 ⇒ `Validation(Block(...))`。
- ① decode 截断 ⇒ `Decode(InvalidLength)`（错误分类）。

## 4. 边界声明

```
A11            = DEFERRED
QC             = DEFERRED（不进 P7 pipeline）
Consensus      = untouched（nova-runtime 不依赖 consensus）
block_hash     = UNCHANGED
P7-2 Revision  = FINAL / FROZEN
P7-3 Block Validation = FINAL / FROZEN
P7-4 Block Lifecycle  = FINAL / FROZEN
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-4 Block Lifecycle Final Freeze V1（FACT AUDIT / R1~R8 / 测试重跑 / 四项 Gate 重跑 / Security S1~S10 / 冻结内容固化） | 用户授权 P7-4 Final Review / Freeze |
