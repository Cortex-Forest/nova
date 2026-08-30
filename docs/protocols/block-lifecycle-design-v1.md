# Nova Chain — Block Lifecycle / Execution Integration Design V1（P7-4）

- **Status**: **FROZEN**（P7-4 Block 执行/生命周期集成实现设计；Design Review 通过，2026-08-31）
- **Date**: 2026-08-31
- **Scope**: 把 P7-2 Block + P7-3 验证 + 8D（execute_block / apply_block / verify_block_state_root）编排成
  完整 Block 处理管线（P7-3 D1=C 调用方编排落地）。
- **协议基线**: ADR-0042 FROZEN + Signature Amendment FROZEN；P7-2 FINAL FROZEN；P7-3 Design+Impl FINAL FROZEN；
  ADR-0025 S-A/S-H、ADR-0029/0030（8D）冻结。

## 0. 目标

落地 P7-3 D1=C 的"调用方编排"：定义 Block 从**接收/构造 → 验证 → 执行 → 提交**的完整管线
（structure → proposer signature → tx_root → state_root → height/parent → apply），
复用既有冻结函数，不重造、不改变冻结语义。

## 1. 管线顺序（冻结基线：ADR-0042 §9 + 8D D-3/D-4）

```
① 结构          decode_block（P7-2）
② proposer sig  verify_block_signature（P7-3）
③ transaction_root  verify_transaction_root（P7-3）
④ state_root    execute_block（8D）→ tx_changes → verify_block_state_root（8D，重算比对）
⑤ height/parent verify_height_parent（P7-3，ParentContext）
⑥ 提交          apply_block（8D，区块级原子事务）
```

- 任一 FAIL ⇒ Reject（不 fallback）；② 失败 ⇒ ③④⑤⑥ 不执行（短路）。
- ④ 与 ⑥ 的顺序语义：先验证执行承诺（state_root 重算比对）再提交；提交原子（snapshot/rollback，8D）。

## 2. 现有资产（FACT，已核实）

| 步骤 | 资产（冻结/实现） | 归属 |
|---|---|---|
| ① 结构 | `decode_block` | nova-core（P7-2） |
| ② 签名 | `verify_block_signature(block, proposer_vk, chain_id)` | nova-core（P7-3） |
| ③ tx_root | `verify_transaction_root(expected, body)` / `compute_transaction_root` | nova-core（P7-3） |
| ④ 执行 | `execute_block(state, txs, sender_keys, ctx, max_gas)` → `BlockExecutionResult` | nova-execution（8D） |
| ④ state_root | `calculate_state_root(store, tx_changes)` / `verify_block_state_root(expected, computed)` | nova-storage（8D） |
| ⑤ height/parent | `verify_height_parent(block, parent: &ParentContext)` | nova-core（P7-3） |
| ⑥ 提交 | `apply_block(tx_changes)` → `NodeHash` | nova-storage（8D） |

依赖方向（ADR-0025 冻结）：`execution → core/crypto`；`storage → core/crypto`；
**禁 `storage → execution`**；execution 与 storage 互不依赖；Execution=calculate，Storage=commit。

## 3. 编排设计（**已裁决 E1=A / E2=B / E3=A**）

### 3.1 E1 = A：新建协调层 crate `nova-runtime`

- **新 crate**：`nova-runtime`（Block 生命周期协调层）。
- **依赖**：`nova-core` + `nova-crypto` + `nova-execution` + `nova-storage`。
  本阶段**不引入 consensus 语义**（编排逻辑不依赖 consensus 类型；`consensus` 依赖可后续按需添加）。
- **不破坏现有依赖边界**：runtime 是上游消费方（同时依赖 execution+storage 合法；ADR-0025
  仅禁 `storage → execution` 反向，未禁上游同时依赖）；`nova-node` 保持现有
  network/consensus/crypto 依赖（**不**加 execution/storage，即否决 E1-B）。
- **否决 E1-D**：`tests/vectors` 仅 dev-only，不构成生产级 Block 生命周期集成。
- 依赖方向（冻结）：
  ```
  nova-runtime → { nova-core, nova-crypto, nova-execution, nova-storage }
  ```

### 3.2 E2 = B：分层步骤函数（无单 `process_block` 巨函数）

`nova-runtime` 提供**步骤级 API**（对应管线 ①~⑥），调用方显式串联；**不提供**强组合
`process_block(...)`（避免隐藏验证/执行边界，与 P7-3 D1=C 一致）。

| 步骤 | runtime 函数（分层步骤） | 底层复用 |
|---|---|---|
| ① 结构 | `decode_block`（复用 nova-core，re-export/薄封装） | nova-core `decode_block`（P7-2） |
| ② 签名 | `validate_block_signature(block, proposer_vk, chain_id)` | nova-core `verify_block_signature`（P7-3） |
| ③ tx_root | `validate_transaction_root(block)` | nova-core `verify_transaction_root`（P7-3） |
| ④ 执行+state_root | `execute_and_verify_state_root(store, block, sender_keys, ctx, max_gas)` | nova-execution `execute_block`（8D）+ nova-storage `calculate_state_root`/`verify_block_state_root`（8D） |
| ⑤ height/parent | `validate_height_parent(block, parent: &ParentContext)` | nova-core `verify_height_parent`（P7-3） |
| ⑥ 提交 | `commit_block(store, execution_result)` | nova-storage `apply_block`（8D） |

- 每个 runtime 函数**独立可调用**、返回 `Result<_, BlockPipelineError>`；顺序由调用方保证
  （② 失败 ⇒ ③④⑤⑥ 不调用；短路是调用方职责，runtime 不强加单函数）。
- runtime **不重造**任何底层逻辑（全部委托冻结函数）；仅做：跨层组合（④）、错误包装、依赖集中。

### 3.3 E3 = A：`BlockPipelineError`（错误组合）

```
pub enum BlockPipelineError {
    Decode(BlockCodecError),               // ① 结构（nova-core）
    Validation(BlockValidationFailure),    // ②③⑤ 验证（nova-core）+ ④ state_root mismatch
    Execution(BlockError),                 // ④ execute_block（nova-execution）
    Storage(StorageError),                 // ④ calculate_state_root / ⑥ apply_block（nova-storage）
}

pub enum BlockValidationFailure {
    Block(BlockValidationError),           // ②③⑤（nova-core）
    StateRoot(BlockStateRootError),        // ④ verify_block_state_root mismatch（nova-storage）
}
```

- 4 顶层类别（decode / validation / execution / storage）明确区分失败域；`Validation` 内部
  细分 Block（②③⑤）与 StateRoot（④ mismatch）——因 `BlockStateRootError` 属 nova-storage 类型，
  不能并入 nova-core `BlockValidationError`，故单列（语义仍属 validation 类）。
- **不改变底层错误语义**：各变体直接包装底层错误（不吞掉、不重映射为模糊错误）。
- **ADR impact review**：新增 `BlockPipelineError` 为组合层错误（纯分类包装），不改变
  ADR-0042 §10 / ADR-0029 rejection 语义；按项目先例（P7-3 D5）结论：**不修改冻结 ADR**。

## 4. 边界（冻结，不得违反）

- 不改变任何冻结函数签名/语义（P7-2/3/8D 全保持）。
- Execution=calculate，Storage=commit；编排层**不得**把 storage 职责塞进 execution 或反之。
- 禁 `storage → execution` 反向依赖。
- `proposer signature ≠ authority/membership proof`；A11 DEFERRED。
- decode ≠ semantic；Block ≠ BlockReference ≠ QC。
- 编排层不实现网络强制（max_block_bytes 归网络/验证层，ADR §11）。
- `nova-node` 依赖边界不变（不引入 execution/storage）。

## 5. 决策点裁决（项目所有者已裁决，2026-08-31）

| # | 决策 | 裁决 | 影响 |
|---|---|---|---|
| **E1** | 编排层位置 | **A：新建协调层 crate `nova-runtime`**（依赖 core/crypto/execution/storage；本阶段不引入 consensus 语义） | 不破坏 execution/storage 互不依赖；`nova-node` 依赖边界不变；生产级生命周期集成 |
| **E2** | 编排 API 形状 | **B：分层步骤函数**（①~⑥ 各一 runtime 函数，调用方显式串联；无单 `process_block`） | 与 P7-3 D1=C 一致；不隐藏验证/执行边界 |
| **E3** | 错误组合 | **A：`BlockPipelineError`**（Decode/Validation/Execution/Storage 4 顶层类别；Validation 内部分 Block/StateRoot） | 明确区分失败域；不改变底层错误语义 |
| **E4** | ④ sender_keys / ctx / max_gas 来源 | 外部传入（沿用 `execute_block` 契约）——确认，不新决策 | — |
| **E5** | ⑤ parent context 来源 | 外部传入（P7-3 D6 `ParentContext`）——确认，不新决策 | — |

否决：E1-B（nova-node 加 execution/storage，破坏已审计依赖边界）；E1-D（仅 tests/vectors，无生产级集成）。

## 6. 测试计划（已裁决后）

- **nova-runtime 步骤函数**：
  - ② `validate_block_signature`：ok / 篡改 / 错误 key / 错误 chain_id（委托 P7-3 语义）。
  - ③ `validate_transaction_root`：ok / body 篡改 ⇒ `Validation(Block(TransactionRootMismatch))`。
  - ④ `execute_and_verify_state_root`：ok（root 匹配）/ 执行结果与 header 不符 ⇒
    `Validation(StateRoot(...))` / storage 故障 ⇒ `Storage(...)`。
  - ⑤ `validate_height_parent`：ok / height 不连续 / parent_hash mismatch。
  - ⑥ `commit_block`：ok（apply 落库 root）/ storage 故障 ⇒ `Storage(...)`。
- **错误分类**：各失败正确落入 `BlockPipelineError` 类别（Decode/Validation/Execution/Storage）。
- **短路语义**：调用方按序调用；② 失败后不调用 ③④⑤⑥（runtime 不强加单函数）。
- **回归**：P7-2/3/8D 全部测试保持 PASS；`nova-node` 依赖边界不变（Cargo 未加 execution/storage）。

## 7. 禁令（冻结后仍适用）

- 不改 P7-2/3/8D 冻结函数（签名/语义/错误）。
- 不引入 storage→execution 反向依赖；不把 commit 职责塞进 execution。
- 不新增 authority/membership/eligibility（A11 DEFERRED）。
- `nova-node` **不得**新增 execution/storage 依赖（E1-B 否决）。
- **E1=E2=E3 一经冻结，不得改变**（除非新 ADR / Protocol Review）。
- 不实现网络层强制 / QC / Node 运行时全量。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-4 Block Lifecycle 实现设计 V1（DRAFT——管线顺序 / 现有资产 / 编排候选 E1~E3 / 边界 / 测试计划 / 禁令） | 用户授权 P7-4 Block 执行/生命周期集成（FACT AUDIT 完成 → 实现设计，待 Review） |
| 2026-08-31 | **E1~E5 裁决落地**：E1=A 新建 `nova-runtime` 协调层 crate（依赖 core/crypto/execution/storage，不引入 consensus 语义；`nova-node` 边界不变）/ E2=B 分层步骤函数（①~⑥ 各一 runtime 函数，调用方串联，无单 process_block）/ E3=A `BlockPipelineError`（Decode/Validation/Execution/Storage 4 顶层类别，Validation 内部分 Block/StateRoot；ADR impact review 不改冻结 ADR）；E4/E5 确认沿用既有契约；否决 E1-B / E1-D | 项目所有者裁决 E1~E3 |
| 2026-08-31 | **DESIGN FROZEN（P7-4 Block Lifecycle）**：Design Independent Review **10/10 PASS / 0 findings**；冻结内容（不得改变除非新 ADR / Protocol Review）：`nova-runtime` 协调层（依赖方向冻结）/ 分层步骤 API（decode / validate_block_signature / validate_transaction_root / execute_and_verify_state_root / validate_height_parent / commit_block）/ `BlockPipelineError` 错误模型 / 边界与禁令。**不写代码；P7-4 Implementation NOT AUTHORIZED** | Design Independent Review 通过 → 项目所有者授权 Design FROZEN（独立 documentation commit） |
