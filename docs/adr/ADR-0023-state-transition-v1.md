# ADR-0023: State Transition V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（State Transition）
- 关联：ADR-0009（签名覆盖，receipt 为派生数据）、ADR-0016（供应上限/burned 累计）、ADR-0017（账户模型）、
  ADR-0018（账户承诺，State Root DEFERRED）、ADR-0019（交易 Schema/四状态）、ADR-0021（Nonce/Replay）、
  ADR-0022（Gas/Fee）、`crypto-serialization-v1.md`

## Context

Transaction 执行必须一次冻结：状态转换模型、账户变更顺序、失败语义、receipt、State Root 边界、
Block Gas 隔离。7F 已把 balance sufficiency 划归执行时检查；本 ADR 冻结 **G1–G6 + G-A~G-K**。

**职责流水线（硬边界）**：

```
7C Encoding → 7D Signature → 7E Nonce/Replay → 7F Gas/Fee → 7G State Transition
```

**归属**：`apply_transaction` 实现于 **`nova-execution`**；协议类型（`AccountState`/`AccountChange`/
`TransactionReceipt`/`StateTransition`）于 **`nova-core`**。禁止：core 直接修改状态；crypto 引入
执行逻辑；execution 自定义协议字段。

## Decision（建议，待批准）

### G1. State Transition Model

```rust
// nova-core（协议类型）
pub struct AccountState {
    pub balance: u128,
    pub nonce: u64,
    pub code_hash: [u8; 32],     // User Account = EMPTY_CODE_HASH
    pub storage_root: [u8; 32],  // V0.1 = EMPTY_STORAGE_ROOT（数值 DEFERRED TO STEP 8）
}

pub struct AccountChange {
    pub address: NovaAddress,
    pub new_balance: u128,
    pub new_nonce: u64,
    pub created: bool,           // 隐式创建（ADR-0017 §3）
}

pub struct TransactionReceipt {  // G4
    pub tx_hash: [u8; 32],       // txid（7C）
    pub status: TxStatus,        // V0.1 仅 Success
    pub gas_used: u64,           // = TRANSFER_INTRINSIC_GAS
    pub fee_paid: u128,          // = actual_fee
    pub burned_fee: u128,        // = compute_burn(actual_fee, bps)
}

pub struct StateTransition {
    pub changes: Vec<AccountChange>,  // 确定性顺序（G-J）
    pub receipt: TransactionReceipt,
    pub gas_used: u64,                // 供区块聚合（G6）
}

// nova-execution（执行逻辑）
pub trait AccountStateView {
    fn account(&self, addr: &NovaAddress) -> Option<AccountState>;  // None = 不存在（逻辑默认）
}

pub struct ExecutionContext {   // 只读；禁止写入 ctx
    pub chain: ChainIdentity,
    pub current_height: u64,
    pub fee_burn_bps: u16,      // 来自 EconomicsParamsV1（≤10_000；Genesis 已保证）
}

pub fn apply_transaction<S: AccountStateView>(
    state: &S,
    tx: &TransactionV1,
    sender_vk: &VerifyingKey,   // 调用方提供（7D 身份绑定保证正确性）
    ctx: &ExecutionContext,
) -> Result<StateTransition, ExecutionError>;
```

- `apply_transaction` 为**纯函数**：不直接修改 state，返回确定性 `AccountChange` 列表；caller 应用并 commit。
- **Events**：V0.1 无事件机制，`StateTransition` **不含** events 字段；Event API 留 WASM Phase（不提前造协议）。

### G2. Account Mutation 顺序（冻结）

```
 1. Signature verify（7D）                      → Invalid，无副作用
 2. Replay check（7E: chain/network/expiration） → Invalid，无副作用
 3. Gas validation（7F: gas>0, fee_max, required）→ Invalid，无副作用
 4. Load sender（state.account(sender)）
 5. Nonce check（7E: classify_nonce == Current） → Invalid（TooLow/Future 均拒）
 6. Balance check（7F: balance >= required）     → 执行期失败，无副作用
 7. Load receiver（state.account(receiver)）
 8. Execute transfer（receiver checked_add(amount)）
 9. Deduct amount（sender checked_sub(amount)）
10. Deduct actual_fee（sender checked_sub(actual_fee)）
11. Burn fee（compute_burn → burned_fee 入 receipt）
12. Increment nonce（checked_next_nonce，N15）
13. Commit state（生成 AccountChange；全有或全无）
```

**避免**：nonce 提前增（最后一步）；fee 重复扣（10 只扣一次 actual_fee）；failed 污染状态（失败在 13 前返回 Err）。

**self-transfer（sender==receiver）**：net amount = 0，仅扣 actual_fee + nonce+1；产生**单个** AccountChange（不重复记录同地址）。

**隐式创建**：receiver 不存在 + `amount > 0` ⇒ `created = true`（balance=amount, nonce=0）；
`amount == 0` 且 receiver 不存在 ⇒ 不创建、不产生 receiver change（ADR-0017 §3 / ADR-0019 §11）。

### G3. Failure Semantics（V0.1 冻结）

| 失败 | nonce | fee | state | receipt |
|------|-------|-----|-------|---------|
| signature / replay / nonce / gas / balance fail | 不变 | 无 | 无 | 无 |
| execution fail（V0.1 无 WASM） | 不变 | 无 | 无 | 无 |
| **成功** | **+1** | **actual_fee** | **转移+扣费+创建** | **Success** |

- V0.1 所有失败均无副作用（G-B）；未来 WASM 失败语义须**新 ADR**（不得提前设计）。

### G-E. Calculate-First, Commit-Last（纪律）

- 内部先计算/校验全部变更（局部变量），**全部通过后才构建 `AccountChange`**；禁止中途修改
  state 后才发现错误（半状态污染）。原子性（G-I）由"先算后提交"保证。

### G-I. Atomic Commit Rule（冻结）

> State transition MUST be atomic. No intermediate state mutation is observable.
> 成功 ⇒ commit all changes；失败 ⇒ commit nothing。

### G-J. Deterministic Ordering（冻结）

`AccountChange` 顺序固定：**sender → receiver**（self-transfer 仅 sender）。未来 trie update /
state root / replay verification 依赖此确定性。

### G4. Receipt（冻结）

```
TransactionReceipt { tx_hash, status, gas_used, fee_paid, burned_fee }
```

- receipt 为**执行后派生数据**（ADR-0009 原则 2：不进入 signature / tx hash / canonical bytes）。
- 失败交易不产生 on-chain receipt（G-B）。receipt 聚合（receipt root）在 **Block STEP**。

### G5. State Root（V0.1 决策 A）

- **V0.1 不实现完整 Merkle / proof / empty root / storage commitment**（ADR-0018 §6 DEFERRED）。
- 7G 输出确定性 `AccountChange[]`；STEP 8（Storage）负责 trie 化与 State Root。
- 7G **不定义** `EMPTY_STORAGE_ROOT` 数值。

### G6. Block Gas（隔离）

- `max_gas_per_block`（ProtocolParamsV1）为区块级 Consensus 上限；7G 的 `apply_transaction`
  是**单交易**，不持有/不检查它。
- 区块执行器累加 `StateTransition.gas_used` 并检查 `<= max_gas_per_block` → **Block STEP**。

### G-F. ExecutionError（冻结；含补充变体）

```rust
pub enum ExecutionError {
    Signature(nova_crypto::transaction::TransactionError), // 7D
    Replay(nova_core::transaction::replay::ReplayError),   // 7E
    NonceNotCurrent,                                       // 7E：TooLow 或 Future
    Gas(nova_core::transaction::gas_fee::GasFeeError),     // 7F
    BalanceInsufficient,                                   // 执行期余额不足（7G 层）
    ReceiverOverflow,                                      // receiver + amount 溢出
    SenderOverflow,                                        // sender 扣款不足（防御）
    NonceExhausted,                                        // N15：nonce == u64::MAX
    Malformed(nova_crypto::transaction::TransactionError), // 补充：txid/canonical 编码失败
}
```

- `BalanceInsufficient` 为 **7G 执行期**检查（区别于 7F admission 的 `InsufficientBalance`）：7F 回答
  "can this transaction afford?"；7G 回答 "can this state transition safely apply?"。分层错误边界。
- `Malformed` 承载 `compute_txid` / canonical 编码错误（7C 层传播）。

### G-K. Zero Value Transfer（确认 ADR-0019 §11）

- `amount == 0`：交易可成功；**不创建 receiver**；`nonce+1`；`fee charged`。

### Decision Log

| # | 决策 | 层 | 状态 |
|---|------|-----|------|
| G1 | State Transition Model（core 类型 + execution 函数） | Consensus | 冻结 |
| G2 | Mutation 顺序（13 步；self-transfer 单 change） | Consensus | 冻结 |
| G3 | V0.1 失败无副作用 | Consensus | 冻结 |
| G-E | calculate-first, commit-last | Consensus | 冻结 |
| G-I | Atomic commit | Consensus | 冻结 |
| G-J | AccountChange 顺序 sender→receiver | Consensus | 冻结 |
| G4 | Receipt 5 字段；失败无 receipt | Consensus | 冻结 |
| G5 | State Root placeholder；STEP 8 实现 | Consensus | 冻结 |
| G6 | max_gas_per_block 归 7G/Block | Consensus | 冻结 |
| G-F | ExecutionError 8+1 变体 | Consensus | 冻结 |
| G-K | zero-value 允许；不创建 | Consensus | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| core 直接修改 state | 破坏分层（core=protocol types，execution=transition） |
| 失败产生 on-chain receipt | V0.1 无 VM/partial execution；链上失败 receipt 暂无必要（未来 WASM 新 ADR） |
| V0.1 实现 Merkle State Root | ADR-0018 DEFERRED；提前固化易错值（STEP 8 统一） |
| `Balance(GasFeeError)` 复用 7F 错误 | 层不同：7F admission vs 7G 执行期；独立变体保持边界 |
| receiver change 记录零值无变化账户 | 状态最小；无变化账户不产生 change |

## Consequences

- **正面**：执行模型/顺序/失败语义/错误分类一次冻结；7G 为 Block STEP 与 STEP 8 提供无歧义输出。
- **成本**：`sender_vk` 需调用方提供（公钥来源/存储由 STEP 8/账户层决定）。
- **可迁移**：WASM / 新交易类型 / on-chain 失败 receipt 经对应 Phase + 新 ADR。

## Security Impact

- 防状态污染：原子性（G-I）+ calculate-first（G-E）+ 失败无副作用（G3）。
- 防溢出：所有金额/nonce 运算 checked（ReceiverOverflow/SenderOverflow/NonceExhausted）。
- 防重放：沿用 7D/7E/7F 全部防线；执行顺序保证无漏检。
- 防歧义：AccountChange 确定性顺序（G-J）；self-transfer 单 change。
