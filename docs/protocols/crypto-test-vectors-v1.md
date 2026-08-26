# Nova Chain Crypto Test Vectors v1（协议冻结）

- **Status**: Frozen（待批准）
- **Date**: 2026-08-26
- **Scope**: PHASE 2 — Cryptography
- **用途**：跨实现一致性验证；所有向量为**确定性断言**（相同输入 ⇒ 相同接受/拒绝结果）。
- 关联：`crypto-serialization-v1.md`、ADR-0004/0005/0008/0009/0010/0011/0012

## 1. Address 向量

| 类别 | 断言 |
|------|------|
| valid | 合法地址可解码，字段正确 |
| invalid checksum | 校验码错误 ⇒ 拒绝 |
| invalid HRP | HRP 非注册值（非 `nova`/`novat`/`novad`）⇒ 拒绝 |
| invalid version | `address_version` 不支持 ⇒ 拒绝 |
| invalid address type | `address_type` 未注册 ⇒ 拒绝（`InvalidAddressType`） |
| invalid network | `network_id` 与当前网络不匹配 ⇒ 拒绝 |
| corrupt payload | 数据损坏 ⇒ 拒绝 |
| roundtrip | `encode(decode(a)) == a_canonical`；`decode(encode(p)) == p` |

补充：uppercase / mixed case / truncated address / altered character / malformed data
（见 ADR-0004 测试要求）。

## 2. Domain 向量

| 类别 | 断言 |
|------|------|
| each domain ID | 每个注册 `domain_id` 产生确定且不同的签名消息前缀 |
| each chain ID | 每个 `chain_id` 产生确定且不同的签名消息 |
| same payload across domains | 相同 payload 在不同 `domain_id` 下 ⇒ 消息哈希**不同** |
| same payload across chains | 相同 payload 在不同 `chain_id` 下 ⇒ 消息哈希**不同** |
| domain collision check | 不存在两个不同 `(domain_id, chain_id, payload)` 产生相同 `signed_bytes` |

## 3. Signature 向量

| 类别 | 断言 |
|------|------|
| valid | 正确签名可验证通过 |
| malformed | 畸形签名 ⇒ 拒绝 |
| truncated | 截断签名 ⇒ 拒绝 |
| oversized | 超长/额外字节 ⇒ 拒绝 |
| wrong public key | 错误公钥验证 ⇒ 失败 |
| wrong chain | 使用错误 `chain_id` 构造 ⇒ 验签失败 |
| wrong domain | 使用错误 `domain_id` 构造 ⇒ 验签失败 |
| wrong algorithm | 使用错误 `algorithm_id` 构造 ⇒ 验签失败 |
| canonical | 非 canonical 公钥/签名编码 ⇒ 拒绝（Strict Verification，ADR-0002） |

### 3b. Signature 向量完整链路 Schema（评审 §16）

每个签名测试向量必须包含以下字段，以验证**完整协议链路**：

```
{
  "algorithm_id": u8,
  "domain_id":    u8,
  "chain_id":     u64,
  "canonical_payload": hex,
  "signed_bytes":      hex,      // 由上下文构造（测试器独立重算比对）
  "message_hash":      hex(32B), // SHA-256(signed_bytes)
  "public_key":        hex(32B),
  "signature":         hex(64B),
  "expected": "valid" | "invalid" | "malformed" | ...
}
```

- 测试器必须**独立重算** `signed_bytes` 与 `message_hash` 并与向量比对（防向量内部不一致）。
- 覆盖：valid / malformed / truncated / oversized / wrong key / wrong chain / wrong domain /
  wrong algorithm / canonical 拒绝。

## 4. 来源

- 地址编码：官方 Bech32m test vectors + Nova 自定义 vectors（ADR-0004）。
- Ed25519：RFC 8032 测试向量 + Nova 自定义（ADR-0002）。
- 签名消息：Nova 自定义（本文件 §2/§3）。

## 5. Genesis 向量（ADR-0014/0015/0016，`genesis-v1.md` §18）

向量为 **fixture（JSON human-readable）**，非 Nova 协议编码；loader 做 **schema 层校验**
（字段存在 / 类型 / 注册表 / 重复 / 排序 / 基本范围），**不**在测试基础设施中实现
canonical 编码或 `genesis_hash` 计算（`expected_genesis_hash` 在 STEP 6 IMPLEMENTATION 后
由生成器回填并启用重算）。

### 5a. 向量字段

```
{
  "id": string,
  "category": "genesis",
  "network_id": u8,                    // ADR-0011
  "chain_id": u64,                     // > 0（Genesis 显式配置）
  "genesis_timestamp": u64,            // > 0（Unix 秒）
  "initial_validator_set": [
    { "account_address": "bech32m", "consensus_public_key": "hex(32B)",
      "bonded_stake": "u128-decimal-string", "commission_bps": u16 }
  ],
  "initial_accounts": [
    { "address": "bech32m", "liquid_balance": "u128-decimal-string" }
  ],
  "protocol_parameters": {
    "max_tx_bytes": u32, "max_block_bytes": u32, "max_gas_per_block": u64,
    "max_contract_code_bytes": u32, "max_contract_storage_bytes": u32,
    "epoch_length_blocks": u64, "snapshot_interval_blocks": u64
  },
  "economics_parameters": {
    "total_supply": "u128-decimal-string", "min_validator_stake": "u128-decimal-string",
    "unbonding_period_seconds": u64, "fee_burn_bps": u16
  },
  "expected": "VALID" | "INVALID",
  "expected_error": "GenesisError 分类名" | null,
  "expected_genesis_hash": ""          // DEFERRED（STEP 6 IMPLEMENTATION 后回填）
}
```

- **`u128` 字段必须用十进制字符串**（JSON 数字无法安全表示 u128）。
- 地址必须为真实 bech32m（`nova1`/`novat1`/`novad1`），网络必须匹配 `network_id`。
- `validator_id = SHA-256(consensus_public_key)`（派生，不在 JSON 中存储）。

### 5b. 向量分类

**Valid（三网络）**：

| 向量 | 断言 |
|------|------|
| genesis-mainnet-valid-001 | mainnet（`nova`），chain_id=1001 |
| genesis-testnet-valid-001 | testnet（`novat`），chain_id=2002 |
| genesis-devnet-valid-001 | devnet（`novad`），chain_id=3003 |

**Invalid（各触发一种 `GenesisError` 分类）**：

| 向量 | 触发 | 期望错误 |
|------|------|----------|
| genesis-invalid-network-001 | `network_id=0x04`（未注册） | `InvalidNetwork` |
| genesis-invalid-chain-id-001 | `chain_id=0` | `InvalidChainId` |
| genesis-invalid-timestamp-001 | `genesis_timestamp=0` | `InvalidTimestamp` |
| genesis-duplicate-validator-001 | 同 `consensus_public_key` 两次 | `DuplicateValidator` |
| genesis-duplicate-account-001 | 同 `address` 两次 | `DuplicateAccount` |
| genesis-invalid-stake-001 | `bonded_stake=0` | `InvalidValidator` |
| genesis-stake-exceeds-account-001 | `bonded_stake > 对应 liquid_balance` | `InvalidStake` |
| genesis-invalid-protocol-params-001 | `max_block_bytes < max_tx_bytes` | `InvalidProtocolParams` |
| genesis-invalid-economics-001 | `fee_burn_bps > 10_000` | `InvalidEconomicsParams` |
| genesis-wrong-validator-order-001 | validator 列表非 `validator_id` 升序 | `NonCanonicalOrdering` |
| genesis-wrong-account-order-001 | account 列表非 payload bytes 升序 | `NonCanonicalOrdering` |
| genesis-tampered-genesis-001 | 篡改某字段（如 timestamp）导致 hash 不匹配 | `GenesisHashMismatch`（若提供期望 hash） |
| genesis-wrong-genesis-hash-001 | 提供错误 `expected_genesis_hash` | `GenesisHashMismatch` |
| genesis-supply-invariant-violation-001 | `total_supply != Σ liquid_balance` | `SupplyInvariantViolation` |

- 空 validator set / 空 account set / 超上限：由 structural validation 拒绝
  （`InvalidValidator` / `InvalidInitialState`）。

### 5c. 跨网 / 身份分离断言

- 相同 genesis 数据、不同 `network_id` ⇒ 不同 ChainIdentity / validation 结果。
- 相同 `network_id`、不同 `chain_id` ⇒ 不同 ChainIdentity。
- 相同 `network_id` + `chain_id`、不同 genesis 内容 ⇒ `genesis_hash` 不同（链不同）。
- 任一字段篡改 ⇒ `genesis_hash` 变化（tamper detection）。

## 6. 来源（Genesis）

- Schema / 校验：ADR-0014、`genesis-v1.md`。
- Canonical 编码 / hash：ADR-0015、`crypto-serialization-v1.md` §11。
- Accounting invariants：ADR-0016。

## 7. Account 向量（预留，STEP 7H 启用）

- 账户 value 序列化 / 承诺规范见 **ADR-0017 / ADR-0018**、`crypto-serialization-v1.md` §12。
- **预留分类**（待 STEP 7H Transaction Test Vectors 实现后生成 fixture）：
  - account canonical encoding（88B：balance/nonce/code_hash/storage_root）
  - `account_commitment = SHA-256(canonical_account_bytes)`
  - `EMPTY_CODE_HASH`（= SHA-256(empty)）
  - `EMPTY_STORAGE_ROOT`（**DEFERRED TO STEP 8**，不生成 fixture）
  - implicit default / 账户创建（positive value + valid execution）
  - nonce 语义（invalid tx 不改 nonce）
  - balance checked 运算（overflow / underflow）
  - zero-balance 保留 / 删除禁止
- 当前阶段（STEP 7A 架构）不生成 Account 向量 fixture（避免在 trie/空根未冻结前固化易错值）。

## 8. 来源（Account）

- 账户模型：ADR-0017。
- 账户承诺 / 序列化：ADR-0018、`crypto-serialization-v1.md` §12。
