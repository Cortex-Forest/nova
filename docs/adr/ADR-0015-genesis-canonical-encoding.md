# ADR-0015: Genesis Canonical Encoding

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography（Genesis canonical data）
- 关联：ADR-0004（地址）、ADR-0012（算法）、ADR-0014（Genesis Schema V1）、ADR-0016（accounting）、
  `crypto-serialization-v1.md`（统一编码）、`genesis-v1.md`

## Context

STEP 6 的 canonical Genesis encoding 是本阶段最高风险部分。要求：

- 同一 Genesis，任何实现必须产生**完全相同的 bytes**。
- 必须明确 field order / integer encoding / array & list encoding / optional / enum /
  map ordering / string encoding / length encoding。
- 禁止 `JSON.stringify`、普通 serde serialization、BTreeMap iteration 作为**隐式协议定义**。

## Decision（建议，待批准）

### 1. 全局编码规则（继承 `crypto-serialization-v1.md` §1–§8）

- 整数（`u16`/`u32`/`u64`/`u128`）：**little-endian（LE）**；`u8` 单字节。
- 变长集合：**`u32` LE 计数前缀 + 有序 canonical 条目**。
- 定长字节数组：**无长度前缀**（长度由类型决定）。
- Struct 字段：**固定顺序**（本 ADR 逐字段定义，禁止重排）。
- 禁止表示：非 minimal 长度前缀、多余/尾随字节、非规范枚举/顺序 ⇒ 拒绝。

### 2. 地址的 canonical 字节表示（关键决策）

- Genesis canonical 编码中，地址使用 **35B payload raw bytes**（`version‖type‖network‖key_hash`，
  ADR-0004），**不是** bech32m 文本。
- 理由：文本需长度前缀 + 大小写规范化校验，非最小、有歧义风险；35B payload 是地址的
  **唯一 canonical 字节表示**（STEP 5 `payload_to_bytes` 已定义）。
- 解析路径：Genesis 输入（文本）→ `NovaAddress::decode`（严格 bech32m + HRP/网络校验）→
  `payload()` 的 35B bytes。编码时**必须**输出 canonical payload bytes。

### 3. 子结构字节布局

#### ValidatorInit（85 B）

| 字段 | 类型 | 编码 | 大小 |
|------|------|------|------|
| `account_address` | NovaAddress | 35B payload raw bytes（无前缀） | 35 B |
| `consensus_public_key` | [u8; 32] | raw bytes | 32 B |
| `bonded_stake` | u128 | LE | 16 B |
| `commission_bps` | u16 | LE | 2 B |

#### AccountInit（51 B）

| 字段 | 类型 | 编码 | 大小 |
|------|------|------|------|
| `address` | NovaAddress | 35B payload raw bytes | 35 B |
| `liquid_balance` | u128 | LE | 16 B |

#### ProtocolParamsV1（40 B）

| 字段 | 类型 | 编码 | 大小 |
|------|------|------|------|
| `max_tx_bytes` | u32 | LE | 4 B |
| `max_block_bytes` | u32 | LE | 4 B |
| `max_gas_per_block` | u64 | LE | 8 B |
| `max_contract_code_bytes` | u32 | LE | 4 B |
| `max_contract_storage_bytes` | u32 | LE | 4 B |
| `epoch_length_blocks` | u64 | LE | 8 B |
| `snapshot_interval_blocks` | u64 | LE | 8 B |

#### EconomicsParamsV1（42 B）

| 字段 | 类型 | 编码 | 大小 |
|------|------|------|------|
| `total_supply` | u128 | LE | 16 B |
| `min_validator_stake` | u128 | LE | 16 B |
| `unbonding_period_seconds` | u64 | LE | 8 B |
| `fee_burn_bps` | u16 | LE | 2 B |

### 4. GenesisV1 顶层字节布局

```
genesis_hash_preimage = canonical_genesis_bytes =
    network_id                                    (1 B)
  ‖ chain_id                                      (8 B LE)
  ‖ genesis_timestamp                             (8 B LE)
  ‖ u32 LE count(V) ‖ ValidatorInit × N           (list)
  ‖ u32 LE count(M) ‖ AccountInit × M             (list)
  ‖ ProtocolParamsV1                              (40 B)
  ‖ EconomicsParamsV1                             (42 B)
```

### 5. 列表顺序（属于 Genesis 身份）

- `initial_validator_set`：**必须**已按 `validator_id`（32B，= SHA-256(consensus_public_key)）
  **字节升序**。
- `initial_accounts`：**必须**已按 `address` 的 **35B payload raw bytes 字节升序**。
- **非 canonical 顺序 ⇒ REJECT**（`GenesisError::NonCanonicalOrdering`）。
- **禁止 sort-and-accept**：Genesis 输入本身必须已是 canonical representation。
- 顺序属于 Chain Identity（顺序变化 ⇒ `genesis_hash` 变化）。

### 6. genesis_hash

```
genesis_hash = SHA-256(canonical_genesis_bytes)
```

- 使用 `nova_crypto::hash::protocol_hash`（SHA-256，ADR-0006）。
- **禁止** hash(JSON) / hash(Debug) / hash(非 canonical serialization)。
- **禁止**把 `genesis_hash` 放入正在计算的 canonical Genesis 内容中（**hash-over-preimage** 结构）。

### 7. API 形状（供 STEP 6 IMPLEMENTATION）

```rust
canonical_genesis_bytes(...) -> Result<Vec<u8>, GenesisError>
compute_genesis_hash(...)    -> Result<[u8; 32], GenesisError>
validate_genesis(...)        -> Result<ChainIdentity, GenesisError>
```

- 协议层使用 `[u8; 32]`，**不返回字符串形式 hash**。

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 地址编码为 bech32m 文本 | 需长度前缀 + 大小写规范化，非最小、非唯一字节表示 |
| 顶层字段按字典序（BTreeMap） | 以实现迭代顺序作为协议定义，违反 canonical 纪律 |
| JSON canonical stringify | JSON 不是 Nova 协议编码（测试向量专用格式） |
| sort-and-accept 列表 | 破坏"Genesis 文件本身即 canonical"约束，易掩盖配置错误 |

## Consequences

- **正面**：字节级确定性；跨实现一致；列表顺序纳入承诺（防顺序操纵）。
- **成本**：Genesis 作者必须自行按顺序提交（工具/校验器可提供错误提示）。
- **可迁移**：字段顺序一经冻结不可重排；新增字段需 ADR 修订 + 新版本。

## Security Impact

- 防 canonical encoding attack（T15）：唯一可解码，无多字节表示。
- 防 canonical order manipulation：非序 REJECT，顺序纳入 hash 承诺。
- 防 hash-over-preimage 循环：hash 不进入被 hash 的内容。
