# ADR-0021: Nonce & Replay Protection V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（Nonce / Replay Protection）
- 关联：ADR-0005（域）、ADR-0009（签名覆盖）、ADR-0010/0011（链/网络身份）、ADR-0013（crypto 边界）、
  ADR-0017（账户模型）、ADR-0019（交易 Schema）、ADR-0020（交易类型）、`crypto-serialization-v1.md`

## Context

Transaction admission 必须一次锁死 **nonce 语义** 与 **replay protection 四层结构**，
并把 **Protocol（Consensus）规则** 与 **本地 Mempool Policy** 严格分离，防止后续 Mempool /
执行层把 admission、execution、state transition 混为一谈。

**职责流水线（硬边界，后续开发不可逾越）**：

```
7C Encoding → 7D Signature/Identity → 7E Nonce/Replay/Expiration
           → 7F Gas/Fee → 7G State Transition
```

**7E 只负责**：`nonce` 分类与递增边界、`chain_id`、`network_id`、`expiration`。
**7E 不负责**：`signature`（7D）、`gas/fee/balance sufficiency`（7F）、
`state transition/revert`（7G）、Mempool 采集排序（Mempool STEP）。

## Decision（建议，待批准）

### 1. NonceClass 与 classify_nonce（Consensus 中立纯函数）

```rust
pub enum NonceClass {
    Current,          // tx_nonce == account_nonce（可执行）
    Future(u64),      // gap = tx_nonce - account_nonce
    TooLow,           // tx_nonce < account_nonce
}

pub fn classify_nonce(tx_nonce: u64, account_nonce: u64) -> NonceClass;
```

- **纯函数、确定性**；不接收 `MAX_FUTURE_NONCE_GAP` / `current_height` / `balance` / `gas` /
  `mempool` / `policy` 任何参数（防 policy 渗入 protocol primitive）。
- 执行前提 = `Current`；否则 `Invalid`。
- `Future(gap)` 本身不含任何阈值；gap 是否可接受由 Mempool Policy 层判断。

### 2. Nonce 规则（Consensus）

| 规则 | 内容 |
|------|------|
| N1 | 执行交易必须 `tx.nonce == account.nonce`（`Current`），否则 Invalid |
| N7 | `nonce-too-low`（`TooLow`）⇒ **Invalid**（consensus；nonce 已前进，防重放） |
| N8 | **Invalid 交易不改变 nonce**（ADR-0017 D7）：签名/chain_id/network_id/nonce/过期/malformed 均 nonce unchanged |
| N9 | **成功执行** ⇒ `nonce += 1`（`checked_next_nonce`）；增量上限 = 1。失败/revert 的 nonce+gas 语义由 7F/7G 冻结（ADR-0017 D10） |
| N15 | **Nonce Exhaustion**：`account.nonce == u64::MAX` ⇒ 不存在合法下一 nonce ⇒ 交易不能成功完成 |

### 3. Nonce Exhaustion（N15，必须）

```
account.nonce < u64::MAX  → 成功执行后 nonce += 1（checked）
account.nonce == u64::MAX → 无合法下一 nonce（nonce exhaustion boundary）
```

```rust
pub enum NonceError { Exhausted }   // account.nonce == u64::MAX

pub fn checked_next_nonce(account_nonce: u64) -> Result<u64, NonceError>;
//  < u64::MAX → Ok(account_nonce + 1)
// == u64::MAX → Err(NonceError::Exhausted)
```

- **禁止** `wrapping_add(1)`（静默回绕）与 `checked_add(1).unwrap()`（panic/掩盖）。
- 7E 只冻结边界；具体 failure / fee / revert 语义 ⇒ 7F/7G。

### 4. Replay Protection 四层结构（冻结）

```
                   Replay Protection
                         │
       ┌─────────────────┼──────────────────┐
       ↓                 ↓                  ↓
     nonce            chain_id            domain_id
   same-account      cross-chain         cross-domain
       │
       └────────────── network_id（address-network compatibility）
+
expiration = temporal replay boundary
```

| 层 | 机制 | 防 | 责任 STEP |
|----|------|-----|-----------|
| nonce | 单调递增（N1/N7/N9/N15） | 同链同账户重放 | 7E 冻结 / 7G 应用 |
| chain_id | 签名绑定 + 显式比对 | 跨链重放 | 7C 双绑 + 7D 验签 + **7E 比对** |
| domain_id | signed_bytes 域分离 | 跨域重放（对象混淆） | **7D（7E 不重复实现）** |
| network_id | 地址网络兼容性约束 | 跨网地址混淆 | 7E |
| expiration | `current_height ≤ expiration` | 时间窗口重放 | 7E |

### 5. check_replay_context（Consensus，7E）

```rust
pub enum ReplayError { ChainIdMismatch, NetworkMismatch, Expired }

pub fn check_replay_context(
    tx: &TransactionV1,
    chain: &ChainIdentity,
    current_height: u64,
) -> Result<(), ReplayError>;
```

只检查三项（已冻结）：
1. **chain_id**：`tx.chain_id == chain.chain_id`，否则 `ChainIdMismatch`。
   `chain_id` = **cryptographic replay domain**（主防线；7C 双绑 + 7D 验签 + 此处纵深防御）。
2. **network_id**：`tx.sender.network_id == chain.network_id` 且
   `tx.receiver.network_id == chain.network_id`，否则 `NetworkMismatch`。
   `network_id` = **protocol address-network compatibility constraint**（辅助；防地址混淆，
   **不是**主要 replay ID，**≠ chain_id**）。
3. **expiration**：`current_height > tx.expiration` ⇒ `Expired`。
   `Expired` 只表示时间窗口已过；**"太远"不产生 ReplayError**（无共识语义）。

**不重复实现 signature / domain validation**（分别由 7D 保证）。

### 6. Expiration 分层（Consensus vs Policy，硬性）

| 条件 | 层 | 结果 |
|------|-----|------|
| `current_height ≤ expiration` | **Consensus** | 有效 |
| `current_height > expiration` | **Consensus** | `Expired`（Invalid，nonce 不变） |
| `expiration > current_height + MAX_TX_LIFETIME` | **Policy** | Mempool Reject（本地） |
| `expiration = current_height + 100_001` 进入区块 | **Consensus** | **不因"太远" Invalid**；仅查 `current_height ≤ expiration` |

- **Consensus 不得因 expiration 太远而拒绝交易**；`MAX_TX_LIFETIME = 100_000` 是 Mempool Policy，
  **禁止**被 Block Builder 当共识规则使用。
- `MAX_TX_LIFETIME` 防 `u64::MAX` 永久交易，属防 spam（policy），非共识语义。

### 7. Same-nonce conflict 与 Block 规则（分别定义）

**Mempool（Policy，节点本地）**：
- duplicate（同 txid）：幂等忽略。
- conflict（同 `(sender, nonce)` 不同内容）：**Reject second**（V0.1 无 replacement，ADR-0019 §7）。

**Block（Consensus，区块内容有效性）**：
- 同一 block 内，同一 sender 的 nonce **必须严格递增且唯一**。
- 若含 `Alice nonce=5, Alice nonce=5` ⇒ **Block Invalid**（不是 Mempool conflict——进入 block 后
  已是区块内容，不由本地 Mempool 定义）。
- 此规则由 7E 冻结为 **block validity**，区块 STEP 应用。

### 8. Mempool Policy（本地，非 consensus）

```rust
pub struct MempoolPolicy {        // 节点本地；不进入 consensus state / ProtocolParamsV1
    pub max_future_nonce_gap: u64,  // 64（N2/N3）
    pub max_tx_lifetime: u64,       // 100_000（N4；仅防永久交易 spam）
    pub max_txs_per_sender: usize,
    pub max_mempool_bytes: usize,
}
```

- `MAX_FUTURE_NONCE_GAP = 64` / `MAX_TX_LIFETIME = 100_000` **只属于 Mempool Policy**。
- **不进** `ProtocolParamsV1` / Consensus State / State Transition。
- core 的 `classify_nonce` / `check_replay_context` **不持有**任何 policy 常量。
- Mempool 实现（采集/排序/广播）留 Mempool STEP。

### 9. Future nonce 的时点相关语义

- `Future(gap)` 且 `gap ≤ 64` ⇒ Mempool Accepted（排队）。
- 同一笔 future tx 若直接落入执行层 ⇒ `Invalid`（`nonce ≠ account.nonce`）。
- **nonce 检查是时点相关**（依赖 `account.nonce` 当前值），非交易固有属性
  （ADR-0019 §15 "Admission snapshot 不是最终执行保证"）。

### 10. 错误模型（分层，防大杂烩）

```
底层分类（7E）：
  NonceError { Exhausted }
  ReplayError { ChainIdMismatch, NetworkMismatch, Expired }

未来 admission 组合（7F 起，不现在实现）：
  TransactionValidityError
    ├── Nonce(NonceError)
    ├── Replay(ReplayError)
    ├── Signature(...)     // 7D
    ├── Encoding(...)      // 7C
    └── Fee(GasFeeError)   // 7F
```

- `NonceClass` / `classify_nonce` 是**分类**（非错误）；`TooLow` 由分类表达，不产生 `NonceError`。

### 11. Decision Log（N1–N15）

| # | 决策 | 层 | 状态 |
|---|------|-----|------|
| N1 | 执行必须 `tx.nonce == account.nonce` | Consensus | 冻结 |
| N2 | future nonce 可暂存，`gap ≤ 64` | Policy | 冻结 |
| N3 | `MAX_FUTURE_NONCE_GAP = 64` | Policy | 冻结 |
| N4 | `MAX_TX_LIFETIME = 100_000` | Policy | 冻结 |
| N5 | duplicate（同 txid）幂等忽略 | Policy | 冻结 |
| N6 | conflict（同 sender+nonce）Reject second | Policy | 冻结 |
| N7 | nonce-too-low ⇒ Invalid | Consensus | 冻结 |
| N8 | invalid tx 不消耗 nonce | Consensus | 冻结（ADR-0017 D7） |
| N9 | 成功执行 nonce+1（checked；失败语义 7F/7G） | Consensus | 冻结 |
| N10 | `tx.chain_id == ChainIdentity.chain_id` | Consensus | 冻结 |
| N11 | `domain_id == 0x01`（7D 保证，7E 不重复） | Consensus | 冻结 |
| N12 | sender/receiver `network_id == 当前网络` | Consensus | 冻结 |
| N13 | `current_height ≤ expiration` | Consensus | 冻结 |
| N14 | 远期 expiration 仅 Mempool Reject，非 Consensus Invalid | Policy | 冻结 |
| N15 | nonce exhaustion：`u64::MAX` 无合法下一 nonce | Consensus | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| `classify_nonce(tx, acc, max_gap)` | policy 渗入 protocol primitive；阈值应由调用方本地判断 |
| `MAX_FUTURE_NONCE_GAP` 进 ProtocolParamsV1 | 非共识状态；Mempool 可配置，跨节点不同 |
| 7E 检查 balance sufficiency | 属 7F fee 层；提前实现造成职责重叠 |
| 7E 重复实现 domain 校验 | 7D 签名已验证 domain；重复造一套检查增加分歧面 |
| block 内同 `(sender,nonce)` 视为 Mempool conflict | 区块内容是共识；须按 Block Invalid 处理 |
| `wrapping_add(1)` 处理 nonce 溢出 | 静默回绕破坏重放保护（N15 禁止） |
| `checked_add(1).unwrap()` | panic/掩盖，不可接受（N15 禁止） |

## Consequences

- **正面**：nonce/replay 语义与 consensus/policy 边界一次锁死；7E 为 7F/7G/Mempool 提供无歧义前置。
- **成本**：Mempool policy 值（gap/lifetime/anti-spam）为节点本地，需在节点实现文档标注可配置。
- **可迁移**：replacement / fee delegation 等经升级版本 + 新 ADR。

## Security Impact

- 防重放：nonce（同链同账户）+ chain_id（跨链）+ domain_id（跨域，7D）+ network_id（跨网）+ expiration（时间窗）。
- 防 nonce 溢出：N15 checked 递增，禁 wrap/unwrap。
- 防状态污染：7E 不触碰 balance/fee/state；职责单一，降低后续执行层混叠风险。
- 防永久交易 spam：MAX_TX_LIFETIME（policy 层）。
- 防区块歧义：block 内 (sender, nonce) 严格递增（Block Validity）。
