# ADR-0024: Transaction Test Vectors V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（Test Vectors）
- 关联：ADR-0009（签名覆盖）、ADR-0019/0020（交易 Schema/类型）、ADR-0021（Nonce/Replay）、
  ADR-0022（Gas/Fee）、ADR-0023（State Transition）、`crypto-serialization-v1.md` §13、
  `crypto-test-vectors-v1.md` §9

## Context

Transaction 协议已冻结（7B–7G）。本 ADR 建立**跨实现一致性**基础：Transaction Test Vectors。
**7H 不增加任何协议功能**，只验证冻结协议（encoding / signature / replay / nonce / gas /
state transition / atomic failure）。

**六层确定性链**：

```
canonical_tx_payload → signed_bytes → message_hash → signature
                    → canonical_transaction_bytes → txid
```

任何一层变化 ⇒ 最终 txid 必须变化（7C/7D proptest 已覆盖 mutation 性质；本向量逐层重算比对固化）。

## Decision（建议，待批准）

### 1. Vector Schema（`schema_version: "transaction-vector-v1"`）

```jsonc
{
  "schema_version": "transaction-vector-v1",
  "id": "tx-normal-transfer-001",      // immutable：一旦合并不可改名（外部工具可能引用）
  "category": "transaction",
  "note": "...",
  // --- 执行上下文（决定 Replay / expiration / fee burn / execution outcome）---
  "chain_id": 1001,
  "network_id": 1,
  "current_height": 1000,
  "fee_burn_bps": 1000,
  // --- 交易字段 ---
  "transaction": {
    "version": 1,
    "chain_id": 1001,
    "nonce": 5,
    "sender": "nova1...",
    "receiver": "nova1...",
    "amount": "1000000",               // u128 十进制字符串
    "gas_limit": 21000,
    "gas_price": "100",                // u128 十进制字符串
    "transaction_type": 1,
    "payload_hex": "",                 // 严格小写 hex
    "expiration": 2000000,
    "signature_hex": "<64B hex>"
  },
  "sender_public_key": "<32B hex>",
  "account_sender":    { "balance": "10000000", "nonce": 5 },
  "account_receiver":  { "balance": "500", "nonce": 0 },   // 或 null（不存在）
  "expected": {
    "result": "valid" | "invalid",
    "phase": "signature" | "replay" | "nonce" | "gas" | "balance" | "execution",
    "error": "<ExecutionError 分类名> | null",
    "canonical_tx_payload": "<hex>",
    "signed_bytes": "<hex>",
    "message_hash": "<32B hex>",
    "signature": "<64B hex>",
    "canonical_transaction_bytes": "<hex>",
    "txid": "<32B hex>"
  }
}
```

- **`result`**：`valid` = 交易通过全部校验且执行成功；`invalid` = admission 或执行期失败
  （**不暗示所有失败同一类**）。
- **`phase`**：失败发生的协议阶段（signature / replay / nonce / gas / balance / execution），
  未来 RPC/Explorer 可区分"交易被拒绝" vs "进入执行但失败"（V0.1 状态一致，语义不同）。
- **`error`**：`ExecutionError` 分类名（ADR-0023 G-F；valid 时为 null）。
- **`id` immutable**：合并后禁止改名（外部测试工具可能引用）。
- **`schema_version`**：未来 V2 Transaction（memo / contract call / multisig / wasm payload）
  用新 version，loader 可区分。

### 2. 17 类覆盖矩阵（23 个向量）

**组 1 — 基础交易（3）**：tx-normal-transfer-001 / tx-zero-amount-001 / tx-self-transfer-001

**组 2 — Nonce（4）**：
| id | error | phase |
|----|-------|-------|
| tx-nonce-current-001 | — | valid |
| tx-nonce-too-low-001 | `NonceNotCurrent` | nonce |
| tx-nonce-future-001 | `NonceNotCurrent` | nonce |
| tx-nonce-max-001 | `NonceExhausted` | nonce |

**组 3 — Gas/Fee（5）**：
| id | error | phase |
|----|-------|-------|
| tx-fee-normal-001 | — | valid |
| tx-fee-overflow-001 | `FeeMaxOverflow` | gas |
| tx-required-overflow-001 | `RequiredOverflow` | gas |
| tx-gas-limit-invalid-001 | `InvalidGasParams` | gas |
| tx-gas-price-invalid-001 | `InvalidGasParams` | gas |

**组 4 — Replay（3）**：
| id | error | phase |
|----|-------|-------|
| tx-wrong-chain-001 | `ChainIdMismatch` | replay |
| tx-wrong-network-001 | `NetworkMismatch` | replay |
| tx-expired-001 | `Expired` | replay |

**组 5 — Account（3）**：tx-receiver-created-001 / tx-receiver-existing-001 / tx-zero-value-no-create-001（均 valid）

**组 6 — Signature（3）**：
| id | error | phase |
|----|-------|-------|
| tx-signature-valid-001 | — | valid |
| tx-modified-payload-001 | `SignatureVerificationFailed` | signature |
| tx-modified-signature-001 | `SignatureVerificationFailed` | signature |

**组 7 — Execution（2）**：
| id | error | phase |
|----|-------|-------|
| tx-success-transition-001 | — | valid |
| tx-failed-no-mutation-001 | `BalanceInsufficient` | balance |

合计 **23 个向量**。

### 3. Canonicalization Rules（六层确定性，冻结）

```
1. canonical_tx_payload = version(1B)‖chain_id(8B LE)‖nonce(8B LE)‖sender(35B)‖receiver(35B)
        ‖amount(16B LE)‖gas_limit(8B LE)‖gas_price(16B LE)‖transaction_type(1B)
        ‖plen(u32 LE)‖payload‖expiration(8B LE)                    // ADR-0019 §2
2. signed_bytes = 0x01‖0x01‖chain_id(8B LE)‖len(u32 LE)‖payload    // ADR-0019 §3
3. message_hash = SHA-256(signed_bytes)
4. signature    = Ed25519.sign(message_hash)                        // 输入+验证（见 §4）
5. canonical_transaction_bytes = payload‖signature(64B)            // ADR-0019 §4
6. txid = SHA-256(canonical_transaction_bytes)                      // 含签名
```

- **signature 不进入 canonical_tx_payload**（否则签名无法计算）；**signature 进入 txid**
  （同交易不同签名 ⇒ 不同 txid，ADR-0019 §4）。

### 4. Loader 语义（六层重算 + 结果分类）

- **派生重算（loader 独立计算并比对）**：`canonical_tx_payload` / `signed_bytes` /
  `message_hash` / `canonical_transaction_bytes`（派生 payload + fixture signature）/ `txid`。
- **signature 是输入 + 验证**：loader **不重算** signature（Ed25519 由 fixture 提供）；
  `valid` 向量经 `verify(signature, message_hash)` 通过；`signature` 类 `invalid` 向量验证失败
  （expected）。
- **结果分类**：构造 `AccountStateView`（fixture `account_sender`/`account_receiver`）+
  `ExecutionContext`（`chain_id`/`network_id`/`current_height`/`fee_burn_bps`）→
  `apply_transaction(...)`：
  - `Ok(transition)` ⇒ `result=valid`；校验 `receipt.tx_hash == txid`、`gas_used`、`fee_paid`、
    `burned_fee` 与六层/上下文一致。
  - `Err(ExecutionError)` ⇒ `result=invalid`；比对 `phase` + `error` 分类。
- 对 `invalid` 向量额外断言：**无任何 state mutation**（原子性 G-I）。

### 5. 生成器与运行约束

```
生成阶段（一次性）：随机 keypair → 生成向量 → commit JSON fixture（含六层期望）
运行阶段（每次测试）：fixture → loader → 重算 → 比对
```

- 禁止测试运行时重新生成 key / 时间随机数 / 环境随机值（保证跨机器可验证）。
- 生成器 `cargo run -p nova-test-vectors --bin gen_transaction_vectors`；向量经
  `include_str!` 编译期内嵌（确定性）。

### 6. 依赖与归属

```
nova-execution → nova-core → nova-crypto（依赖方向不变）
tests/vectors → {nova-core, nova-execution, nova-crypto}   // 禁止反向依赖
```

- `tests/vectors/src/transaction.rs`：loader（schema 校验 + 六层重算 + 结果分类）。
- `tests/vectors/src/bin/gen_transaction_vectors.rs`：生成器。
- `tests/vectors/transaction/*.json`：23 个 fixture。
- `tests/vectors/tests/vector_tests.rs`：集成入口。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 只存 txid（不存六层） | 无法逐层交叉验证（用户要求六层） |
| 无 `phase` 字段 | RPC/Explorer 无法区分"拒绝" vs "执行失败"（V0.1 状态一致但语义不同） |
| 测试运行时重新生成 key | 非确定性，无法跨机器验证 |
| 不校验 invalid 无副作用 | 原子性（G-I）是核心安全属性，必须断言 |

## Consequences

- **正面**：跨实现一致性验证基础；六层逐层比对防向量内部不一致；结果分类含阶段语义。
- **成本**：23 个 fixture 需维护；未来 V2 Transaction 用新 schema_version。
- **可迁移**：任何语言实现可加载同一 JSON 重算比对。

## Security Impact

- 防向量内部不一致（六层独立重算）。
- 防跨实现编码歧义（canonical 规则固化）。
- 断言失败原子性（无副作用），防半状态污染回归。
