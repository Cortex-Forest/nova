# ADR-0019: Transaction Schema V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26（架构评审修订：fee_payer=sender；protocol/mempool 边界明确）
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（设计冻结）
- 关联：ADR-0005（域）、ADR-0008（address_type）、ADR-0009（签名覆盖）、ADR-0012（算法）、
  ADR-0013（crypto 边界）、ADR-0017（账户）、ADR-0020（交易类型）、`crypto-serialization-v1.md`

## Context

Transaction 决定签名 / Mempool / State Transition。必须一次锁死字段、canonical 序列化、
签名链路、txid、四个生命周期状态，以及 **Protocol Validity ≠ Mempool Policy** 的边界。
**Protocol State（State Root）= 唯一真相**；Mempool 只是节点本地候选队列，不是协议状态。

## Decision（建议，待批准）

### 1. Final TransactionV1（冻结）

```rust
TransactionV1 {
    version:          u8,          // = 0x01
    chain_id:         u64,         // 显式字段（须与 signed_bytes 头部一致）
    nonce:            u64,         // sender 当前 nonce
    sender:           NovaAddress, // 签名者 + 付费者（fee_payer = sender）
    receiver:         NovaAddress,
    amount:           u128,        // 转账金额（LE）
    gas_limit:        u64,         // gas 上限（> 0）
    gas_price:        u128,        // 每单位 gas 价格（LE，> 0）
    transaction_type: u8,          // ADR-0020：0x01 Transfer（V0.1 唯一）
    payload:          Vec<u8>,     // V0.1 Transfer = 空
    expiration:       u64,         // 过期高度（current_height <= expiration）
    signature:        [u8; 64],    // Ed25519（R‖S）；不参与 canonical_tx_payload
}
```

**V0.1 常量**：`version = 0x01`、`transaction_type = 0x01 Transfer`、`fee_payer = sender`、
`payload = empty`。**不增加独立 `fee_payer` 字段**（ADR-0009 修订）。

### 2. Canonical Transaction Payload（冻结，继承 ADR-0009 §1 字段顺序）

```
canonical_tx_payload =
    version(1B)
  ‖ chain_id(8B LE)
  ‖ nonce(8B LE)
  ‖ sender(35B payload)
  ‖ receiver(35B payload)
  ‖ amount(16B LE)
  ‖ gas_limit(8B LE)
  ‖ gas_price(16B LE)
  ‖ transaction_type(1B)
  ‖ payload_length(u32 LE) ‖ payload
  ‖ expiration(8B LE)
```

- 地址 = 35B payload raw bytes（ADR-0015 惯例）；整数 LE；长度 `u32` LE。
- **`signature` 不进入 canonical_tx_payload**。

### 3. Signature Pipeline（严格）

```
signed_bytes = algorithm_id(1B, 0x01)
            ‖ domain_id(1B, 0x01 Transaction)
            ‖ chain_id(8B LE)
            ‖ payload_length(4B LE)
            ‖ canonical_tx_payload
message_hash = SHA-256(signed_bytes)   // SigningMessageHash（ADR-0013）
signature    = Ed25519.sign(message_hash)
```

- **必须验证 `Transaction.chain_id == signed_bytes.chain_id`**（双绑）；不一致 ⇒ **Invalid**。

### 4. txid（冻结）

```
canonical_transaction_bytes = canonical_tx_payload ‖ signature(64B)
txid = SHA-256(canonical_transaction_bytes)
```

- **txid 包含 signature**（完整交易承诺）。
- **txid 不进入 signature coverage**（ADR-0009 原则 2）。

### 5. Protocol Validity vs Mempool Policy（边界）

| 概念 | 决定 | 性质 |
|------|------|------|
| **Protocol Validity** | 交易能否被共识/执行（结构/签名/chain/domain/nonce/余额/gas/过期） | 共识状态，跨节点一致 |
| **Mempool Policy** | 节点是否本地暂存该交易（nonce gap / lifetime / anti-spam / 上限） | 节点本地，**非 protocol state**，可配置 |

- Mempool policy **不进 consensus state**；节点间可不同，不影响链上一致性。

### 6. Nonce Rules

- **Protocol**：执行交易必须 `tx.nonce == account.nonce`。
- **Mempool**：可暂存 future nonce（`account.nonce < tx.nonce`），但受
  **`MAX_FUTURE_NONCE_GAP`** 限制（**推荐 64**；作为 Mempool Policy，不进入 consensus state）。
- 防止无限 nonce gap spam。

### 7. Same Nonce

- 同一 sender 同一 nonce：**V0.1 冲突 ⇒ Reject second transaction**（不做 fee replacement）。
- 定义：duplicate（同 txid）/ conflict（同 sender+nonce 不同内容）均拒绝第二个。
- 未来引入 replacement 须新 ADR（避免 V0.1 额外协议复杂度）。

### 8. Fee Accounting（Admission）

```
fee_max   = checked_mul(gas_limit, gas_price)     // 溢出 ⇒ Reject
required  = checked_add(amount, fee_max)          // 溢出 ⇒ Reject
```

- **`gas_limit > 0`、`gas_price > 0`**（V0.1；未来若允许零 gas price 须 ADR）。

### 9. Gas Invariant（Execution）

```
gas_used <= gas_limit                             // 必须
actual_fee = checked_mul(gas_used, gas_price)     // 不能 overflow
```

- refund / failure charging / revert / fee burn 语义 → **STEP 7F** 冻结。

### 10. Expiration

- `current_height <= expiration`（有效）。
- 增加 **`MAX_TX_LIFETIME`** 防止 `u64::MAX` 永久交易（建议值 100_000 区块；
  作为 Mempool Policy，不进入 consensus state）。
- `expiration > current_height + MAX_TX_LIFETIME` ⇒ Mempool 拒绝（policy）。

### 11. Zero-value Transfer（V0.1 允许）

- `amount == 0`：**允许**；但必须：支付 gas、`nonce += 1`、
  **不创建不存在的 receiver**、不产生凭空账户状态（ADR-0017 §7）。
- zero-value 的其他协议用途留未来 Transaction Type（ADR-0020）。

### 12. Self Transfer（V0.1 允许）

- `sender == receiver`：允许；执行结果 `net amount change = 0`、`nonce += 1`、`fee deducted`；
  不产生特殊错误。

### 13. Receiver Policy

- V0.1 Transfer：`receiver` 只能 **UserAccount**（`address_type == 0x01`）。
- Contract 地址（`address_type == 0x02` Reserved）⇒ **Reject / Reserved**
  （Contract execution 未实现；PHASE 12 WASM）。

### 14. Admission vs Execution（四状态）

| 状态 | 行为 | balance / nonce / state |
|------|------|--------------------------|
| **Invalid** | admission 拒绝 | 不变 |
| **Accepted** | 进入 Mempool | 不变 |
| **Executed** | State Transition | nonce / gas / balance / revert 由 STEP 7F/7G 冻结 |
| **Finalized** | BFT finality 后最终确认 | 不再回滚 |

### 15. Balance Admission

- 当前 nonce 交易：检查 `balance >= amount + fee_max`。
- future nonce：Mempool 可暂存，但**执行前重新进行完整状态检查**；
  **Admission snapshot 不是最终执行保证**（余额可能被同区块前序交易消耗）。

### 16. Mempool Anti-Spam Policy（Policy 层）

- max transactions per sender / max nonce gap（§6）/ max payload / max total mempool bytes /
  duplicate txid detection。
- 全部为 **Mempool Policy**（节点本地），**不进入 consensus state**。

### 17. Decision Log（P1–P12）

| # | 决策 | 状态 |
|---|------|------|
| P1 | chain_id 显式 tx 字段 | 冻结（§1 + 双绑校验 §3） |
| P2 | expiration 单位 | 区块高度（§10） |
| P3 | Mempool 不预扣费 | 冻结（§14 Accepted 不变） |
| P4 | zero-value Transfer 允许 | 冻结（§11） |
| P5 | fee_payer = sender | 冻结（§1；不启用独立字段） |
| P6 | txid 含签名 | 冻结（§4） |
| P7 | valid-but-failed 语义 | DEFERRED TO STEP 7F/7G |
| P8 | self-transfer 允许 | 冻结（§12） |
| P9 | MAX_FUTURE_NONCE_GAP | 64（Mempool Policy，非 consensus） |
| P10 | MAX_TX_LIFETIME | 100_000 区块（Mempool Policy，非 consensus） |
| P11 | TransactionType Registry | ADR-0020（0x01 Transfer；未知拒绝） |
| P12 | Contract receiver | V0.1 Reject / Reserved（§13） |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 独立 fee_payer 字段（V0.1） | fee_payer=sender，冗余；未来 delegation 升级版本 + 新 ADR |
| Mempool 预扣费 | Mempool 非协议状态；预扣引入状态面 |
| 同 nonce replacement（V0.1） | 复杂度；V0.1 拒绝冲突，未来 ADR |
| 零 gas price 允许 | 无费用可触发 spam；V0.1 要求 gas_price>0 |

## Consequences

- **正面**：交易字段/签名/txid/四状态一次性冻结；Protocol/Mempool 边界清晰。
- **成本**：Mempool policy 值（gap/lifetime/anti-spam）为节点本地，需在节点实现文档标注可配置。
- **可迁移**：fee delegation / replacement / 新交易类型经升级版本 + 新 ADR。

## Security Impact

- 防重放：nonce + chain_id（双绑）+ domain_id + network_id + expiration。
- 防溢出：所有 fee/amount 运算 checked；溢出 Reject。
- 防状态膨胀：zero-value 不创建账户；Contract receiver 拒绝；Mempool anti-spam。
- 防永久交易：MAX_TX_LIFETIME。
