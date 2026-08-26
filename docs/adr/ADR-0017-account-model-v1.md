# ADR-0017: Account Model V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（架构评审修订：AccountState 不含 account_type；隐式创建语义收紧）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（设计冻结）
- 关联：ADR-0004（地址）、ADR-0008（address_type）、ADR-0010/0011（链/网络）、ADR-0013（crypto 边界）、
  ADR-0014/0016（Genesis）、ADR-0018（账户承诺）、`genesis-v1.md`、`crypto-serialization-v1.md`

## Context

Transaction / State / Mempool 之前必须先冻结账户模型。必须回答：
**"账户余额在哪里才是最终真相？"** —— 答案：**Protocol State（State Root）= 唯一真相**；
Wallet / Explorer / RPC / 本地 DB 只是读取它，任何一方的本地余额都不是真相。

## Decision（建议，待批准）

### 1. Account Identity（账户身份）

- 账户身份 = `NovaAddress`（35B payload：`version‖type‖network‖key_hash`，ADR-0004）。
- 账户语义（User Account / Contract）**从 `address_type` 派生**（ADR-0008）；
  **AccountState 不重复存储 `account_type`**（D6）。

### 2. AccountState（Final，架构评审修订）

```rust
AccountState {
    balance:      u128,       // LE canonical
    nonce:        u64,        // LE canonical
    code_hash:    [u8; 32],   // SHA-256(code)；User Account = EMPTY_CODE_HASH
    storage_root: [u8; 32],   // 存储 trie 根；V0.1 = EMPTY_STORAGE_ROOT（值 DEFERRED）
}
```

- **不包含 `address`**（address 作为 state trie key，ADR-0018）。
- **不包含 `account_type`**（从 `address_type` 派生，D6）。

### 3. Implicit Account Model（隐式账户）

- **不存在的地址 = 逻辑默认状态**：`balance=0, nonce=0, code_hash=EMPTY_CODE_HASH,
  storage_root=EMPTY_STORAGE_ROOT`。
- **逻辑默认状态 ≠ trie 中实际存储的零值记录**：地址不存在时，读取 API 可返回
  `DefaultAccountState`（不写盘）。
- **只有成功的 state transition 才能产生显式账户状态**，且至少满足：
  `positive value transfer + valid execution`。**不得**因以下原因创建账户：
  - invalid transaction（坏签名 / 坏 chain_id / 坏 domain / 坏 algorithm / 坏 nonce /
    余额不足 / malformed）
  - zero-value transaction（D9：zero-value transfer 不允许创建账户；zero-value 的其他
    协议用途由 STEP 7B Transaction Schema 决定）

### 4. Nonce Semantics（nonce 语义）

- 类型 `u64`，**初始化 `0`**（与 `genesis-v1.md` §3 implicit defaults 一致）。
- **Invalid Transaction 不改变 nonce**（不进入 state transition；D7）：
  - invalid signature / invalid chain_id / invalid domain / invalid algorithm /
    invalid nonce / 余额不足以支付费用 / malformed transaction ⇒ nonce unchanged。
- **Valid Transaction** 通过 transaction admission 后进入 execution/state transition；
  其 execution failure / revert 是否 `nonce increment / gas charge / state revert`
  由 **STEP 7B / 7F / 7G 统一冻结**（D10，本 ADR 不猜）。

### 5. Balance Rules（余额规则）

- 类型 `u128`（LE canonical）。
- 所有状态修改使用 **`checked_add` / `checked_sub`**：
  - 加法溢出 ⇒ 错误（`BalanceOverflow`）；
  - 减法 underflow ⇒ 错误（`InsufficientBalance`）。
- **禁止** wrapping arithmetic / floating point / silent saturation。
- 余额受 supply invariant 约束（`total_supply == Σ liquid`，ADR-0016；bonded 非新增供应）。

### 6. Zero-Balance Account & Deletion

- **允许 `balance=0, nonce>0`**（已发起过交易即保留）；**不得**因 `balance==0` 自动删除。
- **V0.1 禁止账户删除**。未来若引入 state rent / pruning / storage reclamation，
  **必须新建 ADR**。

### 7. Zero-Value Transaction

- **V0.1 不允许**通过 zero-value transfer 创建新账户（§3）。
- Transaction 是否允许 zero-value 用于非转账用途（如部署/调用）→ **STEP 7B** 决定（D9）。

### 8. Replay Protection Boundary

| 层 | 机制 | 防 |
|----|------|-----|
| 同链同账户 | `nonce` 单调递增 | 重复花费 / 同链重放 |
| 跨链 | `chain_id`（签名上下文） | 另一链重放（ADR-0010/0011） |
| 跨域 | `domain_id`（signed_bytes） | 对象域混淆（ADR-0005） |
| 跨网 | `network_id` / HRP | mainnet↔testnet 混用（ADR-0011） |

nonce 只保证"同链同账户不重放"；跨链/跨域/跨网由签名上下文承担。

### 9. State Root Boundary

- **State Root 是唯一协议状态真相**。
- **本 ADR 不固定具体 trie 类型**；STEP 8（Storage）负责：trie structure / empty root /
  key hashing / proof / node encoding / persistence / state root computation。

### 10. Decision Log（D1–D10）

| # | 决策 | 状态 |
|---|------|------|
| D1 | 空 `storage_root` 常量数值 | **DEFERRED TO STEP 8**（D8） |
| D2 | 账户承诺是否含 address | **不含**（ADR-0018；key 绑定） |
| D3 | 隐式创建 | 修订：仅成功 state transition（positive value + valid execution）创建 |
| D4 | 删除策略 | V0.1 禁止；未来 rent/pruning 须新 ADR |
| D5 | state trie 结构 | DEFERRED TO STEP 8 |
| D6 | `account_type` 不入 AccountState | 冻结（从 address_type 派生） |
| D7 | invalid tx 不改变 nonce | 冻结 |
| D8 | `EMPTY_STORAGE_ROOT` 数值 | DEFERRED TO STEP 8 |
| D9 | zero-value tx 协议允许性 | DEFERRED TO STEP 7B |
| D10 | execution failure/revert 的 nonce+gas 语义 | DEFERRED TO STEP 7F/7G |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| AccountState 保存 account_type | 与 address_type 重复；地址已携带语义（评审 §1） |
| 账户承诺含 address | trie key 已绑定；冗余（评审 §10） |
| 显式创建交易 | 增加状态操作面；隐式 + 成功 transition 更简 |
| zero-value 创建账户 | 无价值流动却产生状态 ⇒ 状态膨胀攻击面（评审 §13） |
| 允许删除零余额账户 | 破坏 nonce 重放历史；V0.1 禁（评审 §8） |

## Consequences

- **正面**：账户模型最小且与地址语义单源（address_type）；nonce/余额规则明确；状态真相单一（State Root）。
- **成本**：zero-value 创建受限（转账场景）；deletion 留待未来 ADR。
- **可迁移**：Contract（`0x02` Reserved）复用同一 AccountState（code_hash/storage_root 预留字段）。

## Security Impact

- 防状态膨胀：只有 positive value + valid execution 才创建账户（D3/D9）。
- 防重放：nonce（同链）+ 签名上下文四层（§8）。
- 防余额破坏：checked 运算，禁 wrap/float/saturation（§5）。
- 防账户替换：账户承诺与 trie key 绑定（ADR-0018 安全不变量）。
