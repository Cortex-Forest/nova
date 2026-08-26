# Nova Chain Genesis Specification v1（协议冻结）

- **Status**: Frozen（待批准）
- **Date**: 2026-08-26（修订：冻结 ValidatorInit/AccountInit/ProtocolParamsV1/EconomicsParamsV1）
- **Scope**: PHASE 2 — Cryptography（PHASE 7 实现 Genesis；STEP 6 实现 identity 校验）
- **权威**：本文件定义 Genesis canonical data、嵌套类型、校验规则与 `genesis_hash`；
  **`chain_id` 是 Genesis 明确配置值，禁止从 `genesis_hash` 截断派生**（用户评审要求）。
- 关联：ADR-0004/0005/0008/0009/0010/0011/0012/0014/0015/0016、
  `crypto-serialization-v1.md`、`crypto-test-vectors-v1.md`

## 1. Genesis canonical data（字段，顺序固定不可重排）

```rust
GenesisV1 {
    network_id:            u8,                  // 网络类别/注册标识（ADR-0011）
    chain_id:              u64,                 // Genesis 明确配置的固定值（非派生）
    genesis_timestamp:     u64,                 // Unix 秒（> 0，LE）
    initial_validator_set: Vec<ValidatorInit>,  // 非空、按 validator_id 升序
    initial_accounts:      Vec<AccountInit>,    // 非空、按地址 payload 升序
    protocol_parameters:   ProtocolParamsV1,    // 共识/网络/执行参数
    economics_parameters:  EconomicsParamsV1,   // 供应/质押/奖励参数
}
```

- 所有字段 canonical 编码遵循 `crypto-serialization-v1.md` 与 **ADR-0015**
  （LE、固定 field order、禁止重排）。
- 嵌套类型定义见本文件 §2–§6（已按 ADR-0014 冻结）。

## 2. ValidatorInit（ADR-0014）

```rust
ValidatorInit {
    account_address:      NovaAddress,  // bech32m 文本，网络必须匹配 Genesis network_id
    consensus_public_key: [u8; 32],     // Ed25519 公钥（压缩点，RFC 8032）
    bonded_stake:         u128,         // 从对应账户 liquid 划转的质押（LE）
    commission_bps:       u16,          // 佣金基点（≤ 10_000）
}
```

- **不保存 `voting_power`**：由 `bonded_stake` 按未来批准的共识权重规则派生；
  禁止同时保存 `bonded_stake` + `voting_power`。

### validator_id（派生身份，不存储）

```
validator_id = SHA-256(consensus_public_key)   // 32B
```

### 校验规则

| 检查 | 失败错误 |
|------|----------|
| `bonded_stake > 0` | `InvalidValidator` |
| `commission_bps <= 10_000` | `InvalidValidator` |
| `account_address` 可解码且 HRP/网络匹配 `network_id` | `InvalidValidator` |
| `consensus_public_key` 为合法 Ed25519 压缩点 | `InvalidValidator` |
| `account_address` 唯一 | `DuplicateValidator` |
| `consensus_public_key` 唯一 | `DuplicateValidator` |
| `validator_id` 唯一 | `DuplicateValidator` |

### 排序（属于 Genesis 身份）

`initial_validator_set` 必须已按 `validator_id` **字节升序**；非 canonical 顺序 ⇒ `NonCanonicalOrdering`
（**禁止 sort-and-accept**）。

## 3. AccountInit（ADR-0014）

```rust
AccountInit {
    address:        NovaAddress,  // bech32m 文本，网络必须匹配 Genesis network_id
    liquid_balance: u128,         // Genesis 初始化前该账户的 liquid balance（LE）
}
```

- **V0.1 implicit defaults（不写入 Genesis）**：`nonce = 0`、`code = empty`、`storage = empty`。

### 校验规则

| 检查 | 失败错误 |
|------|----------|
| `address` 可解码且 HRP/网络匹配 | `InvalidInitialState` |
| `address` 唯一 | `DuplicateAccount` |
| `liquid_balance` 无下溢（u128 编码/解码） | `InvalidInitialState` |

### 排序（属于 Genesis 身份）

`initial_accounts` 必须已按 `address` 的 **35B payload raw bytes 字节升序**；
非 canonical 顺序 ⇒ `NonCanonicalOrdering`（**禁止 sort-and-accept**）。

## 4. ProtocolParamsV1（ADR-0014）

```rust
ProtocolParamsV1 {
    max_tx_bytes:               u32,
    max_block_bytes:            u32,
    max_gas_per_block:          u64,
    max_contract_code_bytes:    u32,
    max_contract_storage_bytes: u32,
    epoch_length_blocks:        u64,
    snapshot_interval_blocks:   u64,
}
```

- 校验与 V0.1 合理上限见 ADR-0014（`max_tx_bytes > 0`、`max_block_bytes >= max_tx_bytes`、
  其余 `> 0` 且不超上限；违反 ⇒ `InvalidProtocolParams`）。
- **不**在本阶段添加共识委员会算法参数。

## 5. EconomicsParamsV1（ADR-0014）

```rust
EconomicsParamsV1 {
    total_supply:             u128,
    min_validator_stake:      u128,
    unbonding_period_seconds: u64,
    fee_burn_bps:             u16,
}
```

- 校验：`total_supply > 0`、`min_validator_stake > 0`、`unbonding_period_seconds > 0`、
  `fee_burn_bps <= 10_000`；违反 ⇒ `InvalidEconomicsParams`。

## 6. Economics Scope Boundary（V0.1 不加入）

Creator/AI/NFT/storage/compute/recommendation reward、future governance allocations、
future economic curves **不加入 V0.1 Genesis**；分别进入对应 Phase。不得为"字段完整"提前造协议。

## 7. 空集合与资源上限（ADR-0014）

| 集合 | 规则 |
|------|------|
| `initial_validator_set` | **REJECT 为空**（PoS 无验证者无法运行） |
| `initial_accounts` | **REJECT 为空**（至少 1 账户） |
| validator 数量 | ≤ 10_000 |
| account 数量 | ≤ 1_000_000 |

## 8. Stake Accounting & Total Supply Invariant（ADR-0016）

- `AccountInit.liquid_balance` = Genesis 初始化前该账户 liquid balance。
- `ValidatorInit.bonded_stake` = 从对应 validator 账户 liquid 转入 staking state 的金额。
- 每个 validator 的 `account_address` **必须**出现在 `initial_accounts` 中；
  **必须**验证 `bonded_stake <= corresponding AccountInit.liquid_balance`（否则 `InvalidStake`）。
- 初始化后：`final_liquid_balance = initial_liquid_balance - bonded_stake`；bonded 进入 staking state，
  **不得再次计入 total supply**。

```
total_initial_account_balances = Σ AccountInit.liquid_balance
total_supply == total_initial_account_balances        // V0.1：全部供应在 Genesis 分配
Σ final_liquid_balance + Σ bonded_stake == total_supply   // 无通胀、无销毁
```

- 未来未分配供应须 ADR 修订并明确去向；禁止"供应缺口去向不明"。
- 所有求和使用 **checked arithmetic**（溢出 ⇒ `SupplyInvariantViolation`，禁止 panic/回绕）。

## 9. Canonical Genesis Encoding（ADR-0015）

```
canonical_genesis_bytes =
    network_id                                    (1 B)
  ‖ chain_id                                      (8 B LE)
  ‖ genesis_timestamp                             (8 B LE)
  ‖ u32 LE count(V) ‖ ValidatorInit × N           (list)
  ‖ u32 LE count(M) ‖ AccountInit × M             (list)
  ‖ ProtocolParamsV1                              (40 B)
  ‖ EconomicsParamsV1                             (42 B)
```

- 整数 LE；长度 `u32` LE；定长 bytes 无前缀；Struct 固定顺序。
- 地址在 canonical bytes 中为 **35B payload raw bytes**（非 bech32m 文本）。
- 列表顺序属于身份：validator 按 `validator_id` 升序、account 按 payload bytes 升序；非序 ⇒ REJECT。
- 禁止 `JSON.stringify` / 普通 serde / BTreeMap iteration 作为协议定义。
- 非 minimal 长度前缀、尾随字节、未知枚举/顺序 ⇒ REJECT（`NonCanonicalEncoding`）。

## 10. genesis_hash

```
genesis_hash = SHA-256(canonical_genesis_bytes)   // 32B 完整 Genesis 承诺
```

- `genesis_hash` 是对**完整 canonical Genesis** 的承诺（覆盖全部字段，含 `chain_id`、列表顺序）。
- 使用 `protocol_hash`（SHA-256，ADR-0006）。
- **禁止** hash(JSON) / hash(Debug) / hash(非 canonical serialization)。
- **禁止**把 `genesis_hash` 放入正在计算的 canonical 内容（**hash-over-preimage**）。
- **`genesis_hash` 不参与生成 `chain_id`**。

## 11. chain_id

- `chain_id` 是 Genesis 中**明确配置的固定 `u64`**（`> 0`），不是派生值。
- **不得从** `genesis_hash` / `block_hash` / `address` / `network_id` / timestamp / validator key **派生**。
- **唯一性声明**：不声称 u64 绝对唯一；`chain_id` 由 Nova 网络配置 / Genesis 管理规则分配并保持唯一。
- **真正用于安全绑定的是**：`chain_id + genesis_hash + domain separation`。

## 12. 三职责严格分离

| 职责 | 值 | 来源 |
|------|-----|------|
| `network_id` | 网络类别/注册标识 | ADR-0011（Network Registry） |
| `chain_id` | Genesis 明确配置的固定 u64 | Genesis 配置 |
| `genesis_hash` | SHA-256(canonical_genesis)（32B） | 由 canonical Genesis 计算 |

三者不可互相替代、不可互相推导。

## 13. ValidateGenesis()（顺序冻结，ADR-0014/0015/0016）

节点启动阶段必须执行，**任何一步失败 ⇒ 节点启动失败，不得进入运行状态**：

```
ValidateGenesis():
  1.  decode                      // canonical 可被唯一解码
  2.  structural validation       // 字段存在、类型、集合非空/上限
  3.  network validation          // network_id 注册（0x01–0x03）+ 地址 HRP/网络一致
  4.  chain_id validation         // chain_id > 0
  5.  timestamp validation        // genesis_timestamp > 0
  6.  validator validation        // §2 校验（非空、权重、唯一性）
  7.  account validation          // §3 校验（唯一性、余额）
  8.  stake accounting            // ADR-0016：bonded_stake <= 对应 liquid；账户存在
  9.  protocol parameters validation  // §4
 10.  economics validation        // §5
 11.  canonical ordering validation   // 列表顺序（validator/account）
 12.  canonical encoding          // 生成 canonical bytes（唯一可解码）
 13.  calculate genesis_hash      // SHA-256(canonical)
 14.  compare expected hash if provided  // computed == configured（若提供）
 15.  construct ChainIdentity     // { network_id, chain_id, genesis_hash }
```

任何失败：返回**结构化错误**（§14）；禁止 panic、禁止 fallback。

## 14. GenesisError 分类

```text
InvalidNetwork           // network_id 未注册（0x00 / 0x04+）
InvalidChainId           // chain_id == 0
InvalidTimestamp         // genesis_timestamp == 0
InvalidValidator         // validator 单条不合法（stake/commission/key/address）
DuplicateValidator       // account_address / consensus_public_key / validator_id 重复
DuplicateAccount         // account address 重复
InvalidStake             // bonded_stake > 对应 liquid；或 validator 账户缺失
InvalidInitialState      // account 不合法
InvalidProtocolParams    // protocol 参数不合法/超上限
InvalidEconomicsParams   // economics 参数不合法
NonCanonicalOrdering     // 列表非 canonical 顺序
NonCanonicalEncoding     // 编码非 canonical（多余字节/非 minimal 前缀等）
GenesisHashMismatch      // computed != configured（若提供）
SupplyInvariantViolation // total_supply != Σ liquid 或溢出
```

**不得合并为笼统的 `InvalidGenesis`**（导致调试困难）。

## 15. 节点启动校验（防 fork / 跨网）

```
configured_chain_id   == genesis.chain_id        // 否则拒绝启动
computed_genesis_hash == configured_genesis_hash // 否则拒绝启动
```

- 即使 `chain_id` 意外相同（独立 fork 场景），`genesis_hash` 不同 ⇒ 链身份验证拒绝。

## 16. 复现性

- 相同 `canonical_genesis` ⇒ 相同 `genesis_hash` ⇒ 相同链身份（可复现，Master Prompt §70）。
- Genesis 文件是权威输入；`genesis_hash` 用于链身份验证（PHASE 7 实现）。

## 17. Cross-Network / Fork Protection（补充证明）

| 场景 | 防护 |
|------|------|
| Testnet → Mainnet | `chain_id` 不同（Genesis 配置不同）⇒ 签名验证失败 |
| Mainnet → 独立 Fork | 即使 `chain_id` 意外相同，`genesis_hash` 不同 ⇒ 启动校验拒绝 |
| 地址跨网 | `network_id`/HRP 不匹配 ⇒ 解码/展示层拒绝（ADR-0011） |

## 18. 测试向量

- 向量 schema / 分类见 `crypto-test-vectors-v1.md` §5（valid 三网络 + invalid 分类）。
- 向量为 **fixture（JSON human-readable）**，非 Nova 协议编码。
- **STEP 6A 起**：`expected_genesis_hash` 已由回填器（`gen_genesis_hashes`）用
  `nova_crypto::identity::compute_genesis_hash` 回填；测试真正调用 `nova_crypto::identity`
  （computed == configured 断言）。
- **STEP 6B 起**：loader 委托 `validate_genesis` 做完整 semantic/canonical 校验。
- 禁止在测试基础设施中自行重新设计 Genesis 编码（本文件纪律）。

## 19. Golden Vector（跨语言黄金向量，STEP 6B）

**mainnet fixture**（`tests/vectors/genesis/genesis-mainnet-valid-001.json`）的
**确定性**黄金向量，供跨语言实现复现核验：

| 项 | 值 |
|----|----|
| `network_id` | `0x01`（mainnet，HRP `nova`） |
| `chain_id` | `1001`（Genesis 显式配置，非派生） |
| `genesis_timestamp` | `1750000000` |
| canonical 长度 | `430` B |
| `genesis_hash` | `035b369237201feae92a271897ad1405d8905573ba21d7f1970551f0d49bf1ef` |

`canonical_genesis_bytes`（430 B，hex，LE）：

```
01e90300000000000080e14e6800000000020000000101013635effc891937e5c08e6cd51dbf43c09cc72bc41fccb985f5ff6556ee2ca1a287aced6f78ab956039c1b8f9e435962bdfa38846505aebf999b02eead45deb3400350c0000000000000000000000000020030101018dd433bf409a7661e18705a8489fb0c5f9c4e9dab0a5d86090e5470fa47e492838c034a3562ed5a66eb5bb9c7113c0af305e40df5a4aa227a4b48afba4b0de9140420f00000000000000000000000000e803030000000101013635effc891937e5c08e6cd51dbf43c09cc72bc41fccb985f5ff6556ee2ca1a260e316000000000000000000000000000101017c26ef0ce873bbbee97593e245bb2ff9b697f363c529d87b5c4279a262a4667dc0c62d000000000000000000000000000101018dd433bf409a7661e18705a8489fb0c5f9c4e9dab0a5d86090e5470fa47e492880841e00000000000000000000000000000001000000100000ca9a3b0000000000800000000010006400000000000000e803000000000000a02e6300000000000000000000000000a08601000000000000000000000000000075120000000000f401
```

- `ChainIdentity { network_id: 0x01, chain_id: 1001, genesis_hash: 035b…f1ef }`。
- 复现：`decode_genesis_bytes(GOLDEN_BYTES)` → `validate_genesis` → 相同 `ChainIdentity`。
- 由 `nova-crypto/tests/identity_vectors.rs::golden_chain_identity_mainnet` 强制断言。
