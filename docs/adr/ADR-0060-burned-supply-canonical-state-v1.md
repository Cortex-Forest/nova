# ADR-0060: Burned Supply Canonical State v1

- **Status**: FROZEN
- **Freeze Date**: 2026-09-06（STEP 7G-BURN-ADR-FREEZE：正式冻结；正文设计不变，仅状态元数据变更）
- **Date**: 2026-09-06
- **STEP**: 7G-BURN-DESIGN（GAP-7G-BURN-STATE canonical representation）
- **Scope**: PHASE 3 — Economic State / Burn Accounting（canonical state 表示）
- 关联：ADR-0016（Genesis Accounting Invariants，**FROZEN**）、ADR-0022（Gas & Fee F1–F10，
  **FROZEN**）、ADR-0017/0018（AccountState）、ADR-0023（State Transition G1/G-I/G-J）、
  ADR-0026（SMT / TrieKey）、ADR-0028（StateStore）、ADR-0030（State Root）

## Context

ADR-0016 §4 / ADR-0022 F7 冻结：`total_supply` 为供应上限（cap，不因 burn 递减）；
`burned_supply` 为**累计账本概念**（`burned_supply_new = burned_supply_old + block_burned`），
持续不变量 `Σ liquid + Σ bonded + burned_supply ≤ total_supply`。

当前事实（代码）：`apply_transaction`（execution/state_transition.rs）正确计算
`burned_fee = compute_burn(actual_fee, fee_burn_bps)` 并写入 per-tx `TransactionReceipt.burned_fee`
（core/state.rs，派生数据）；但 **Σ burned_fee 没有任何 canonical state 表示**——既无全局
economic 状态字段，也未进入 state_root。→ GAP-7G-BURN-STATE。

本 ADR 冻结 `burned_supply` 的 canonical representation，使 burn 进入确定性、可验证、
可重启恢复的协议状态。

## Decision（建议，待批准）

### 1. burned_supply semantic meaning（不变，承接 ADR-0016/0022）
- `burned_supply` = 自 Genesis 以来累计销毁金额（u128）。
- 单调不减：`burned_supply_new ≥ burned_supply_old`。
- `total_supply` 保持协议 cap **不递减**；burn 只增 burned_supply。

### 2. Canonical representation — Option A：Burn System Account（推荐）
用**保留 Burn 账户**承载 burned_supply 累计，复用既有账户 canonical（ADR-0018 88B）与
storage（StateStore/trie/state_root）：

- 保留地址常量（core 定义，非 crypto 新类型）：
  ```
  BURN_ADDRESS = NovaAddressPayload {
      address_version: 0x01,
      address_type: 0x01 (UserAccount),   // 保持既有合法域（不新增 AddressType，不触 crypto 冻结）
      network_id: <当前链 network_id>,
      key_hash: [0x00; 32],               // 无 pubkey preimage ⇒ 任何真实账户都无法拥有
  }
  ```
- **Burn 账户 balance = burned_supply 累计**（协议语义，非 liquid）。
- **惰性创建**：`burned_supply == 0` 时账户不存在（trie 无该 leaf ⇒ Genesis 后初始
  state_root 与现状一致）；首次 `burn > 0` 时以 `AccountChange{ created: true }` 创建。
- 落账：`apply_transaction` 在成功路径将 `burned_fee` 作为该账户的
  `AccountChange`（new_balance = old + burned_fee；checked_add）追加到 `changes`
  （顺序：sender → receiver → burn 账户；ADR-0023 G-J 扩展，burn 账户固定序）。
- state_root 自动覆盖（账户 trie 含该 leaf；无新 commitment 结构）。

### 3. Canonical encoding
- 无新编码：Burn 账户复用 `AccountState` 88B canonical + `account_commitment`
  （ADR-0018/0028）；`storage_root = EMPTY_STORAGE_ROOT`、`code_hash = EMPTY_CODE_HASH`、
  `nonce = 0`（永不递增）。

### 4. State root inclusion
- Burn 账户是普通账户 leaf ⇒ 进入账户 SMT ⇒ `StateStore.state_root()` 自动承诺。
- `calculate_state_root` / `verify_block_state_root`（ADR-0030）无需结构性改动
  （仅 input changes 追加 burn 账户 change）。

### 5. Genesis initialization
- **方案 2**：Genesis canonical bytes **不新增字段**（`GenesisV1` 不变；`genesis_hash`
  不变 —— 不改 genesis encoding）。
- 初始 canonical state 隐含 `burned_supply = 0`（= Burn 账户不存在；惰性语义）。
- Genesis 后首块若含 burn tx ⇒ 该块创建 Burn 账户（created），state_root 相应变化。

### 6. Block accumulation
- 区块级：`block_burned = Σ tx_i.burned_fee`（由各成功 tx 的 burn AccountChange 自然累计；
  无需单独计数器）。
- `burned_supply_new = burned_supply_old + block_burned` 由账户 balance 演化体现
  （每 tx 在该账户上的 checked_add）。

### 7. Overflow behavior
- Burn 账户累加使用 `checked_add`；溢出 ⇒ `Err`（ExecutionError 扩展或
  `GasFeeError::BurnOverflow` 语义），fail-closed；禁 wrapping / saturation / panic。

### 8. Atomicity
- Burn 账户 change 与 sender/receiver 同一 `StateTransition.changes` 批次
  （ADR-0023 G-I）：整体成功提交 / 整体失败回滚。绝不出现「sender 已扣费而 burn 未入账」。

### 9. Replay / idempotency boundary
- 复用现有单次应用机制（txid + block 单次 apply + storage snapshot/rollback；
  ADR-0021/0023/0029）。不新增 replay 系统。burn 账户累加与其它 changes 同一批 → 天然幂等。

### 10. Invariants
```
ECO-A: burned_supply = BURN_ADDRESS.balance
ECO-B: burned_supply 单调不减（无 burn 写入反向路径）
ECO-C: burn ≤ actual_fee ≤ fee_max（ADR-0022 保持）
ECO-D: Σ liquid（普通账户，排除 BURN_ADDRESS）+ Σ bonded + burned_supply ≤ total_supply
ECO-E: total_supply 不因 burn 递减（immutable cap）
ECO-F: BURN_ADDRESS 不可作为普通 Transfer 的 receiver/sender 目标（仅 fee-burn 路径写入）
```

### 11. Tests（7G-IMPL 时）
- 单 tx burn：sender/receiver/burn 账户 balance 与 invariant（`=amount + fee`、`+=burned`）。
- 多 tx block：burned 累计；state_root 反映 burn 账户 leaf。
- 溢出：burned 累加 checked fail-closed。
- 原子：receiver 不足回滚 ⇒ burn 账户不变。
- 伪造拦截：receiver == BURN_ADDRESS 的普通 transfer ⇒ Reject。
- 惰性：全 burn=0 ⇒ trie 无 burn leaf ⇒ root == 无 burn 时 root。
- determinism / proptest：同输入同 state_root。

### 12. Deferred economic state
- fee 非 burn 部分（`actual_fee - burned_fee`）的最终去向（validator reward / treasury /
  protocol revenue）—— **DEFERRED**（Economics/PoS Phase；本 ADR 不冻结接收方）。
- validator / creator reward、treasury、staking issuance、inflation：DEFERRED（与本 ADR 无关）。
- 其它全局经济计数器（如需）后续经独立 ADR 冻结（可选在 BURN_ADDRESS 模式上扩展保留地址族）。

## Alternatives（已评估）

| 方案 | 结论 |
|------|------|
| Option B — Dedicated EconomicState（独立全局状态 + 新 commitment） | 语义最干净、防伪造最稳、扩展最强，但需改 state_root 承诺结构（ADR-0030/0026/0029）、head/persistence、load —— 跨架构 Breaking，**非最小**；留作 future 若出现多全局计数器需求再评估 |
| Option C — Trie Global Key（`economic/burned_supply` namespace key） | SMT TrieKey 冻结 = `NovaAddressPayload`(35B)（ADR-0026 T-2）；store.load 假设 backend 全为 88B 账户；非账户全局键需 namespace + load 分派 + 新 canonical —— 污染「账户集合承诺」语义，改动中等，不选 |
| Option A（本推荐）| storage ≈ 0、state_root 自动、genesis 不破、原子/持久化/replay 全复用；成本 = burn 账户非 liquid 语义 + receiver 拦截规则（本 ADR 冻结） |

## Consequences

- **正面**：burned_supply 进入 canonical state 与 state_root；可审计、可证明、可重启恢复；
  supply invariant（ADR-0016）链上可验证；storage/execution 改动最小。
- **成本**：BURN_ADDRESS 为协议保留常量；需拦截普通转账至该地址（新增有效性规则）；
  fee 非 burn 部分去向仍 DEFERRED。
- **不改变**：GenesisV1 编码/genesis_hash、total_supply、gas price、burn rate、F1-F10、
  AccountState/SMT/state_root 结构、consensus/network/crypto。

## Security Impact

- 防 supply 双计/伪造：BURN_ADDRESS 无 pubkey preimage、仅 fee-burn 路径写入、普通 transfer
  拦截。
- 防溢出破坏：checked_add；fail-closed。
- 防半提交：原子批次（G-I）。
- 防状态失真：惰性创建 ⇒ Genesis 后 root 语义与现状一致，无迁移成本。
