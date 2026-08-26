# Genesis 测试向量

- **source**: Nova Chain 协议（`docs/protocols/genesis-v1.md`、ADR-0014/0015/0016）
- **specification**: genesis-v1.md（GenesisV1 schema、嵌套类型、canonical 编码、genesis_hash、ValidateGenesis）
- **encoding**: JSON（human-readable 向量格式，**非 Nova 协议编码**）；
  `chain_id`/`genesis_timestamp` 为 u64 整数；**u128 字段（`bonded_stake`/`liquid_balance`/
  `total_supply`/`min_validator_stake`）用十进制字符串**（JSON 数字无法安全表示 u128）。
- **expected behavior**:
  - fixture 包含 genesis-v1.md §1 的 7 个顶层字段 + 完整嵌套类型
    （ValidatorInit/AccountInit/ProtocolParamsV1/EconomicsParamsV1，ADR-0014）。
  - 地址为真实 bech32m，网络必须匹配 `network_id`（ADR-0011/0004）。
  - validator 列表按 `validator_id`（=SHA-256(pubkey)）升序；account 列表按地址 payload bytes 升序
    （ADR-0015；非序 ⇒ `NonCanonicalOrdering`）。
  - loader 先做 schema 层校验（嵌套类型 / 注册表 / 重复 / 排序 / 基本范围 / stake accounting /
    supply invariant，ADR-0016），通过后用 `nova_crypto::identity` 计算 canonical `genesis_hash`
    并断言 computed == `expected_genesis_hash`（STEP 6A：真正调用生产实现，不再 DEFERRED）。

**注意**：Genesis fixture 必须遵循 genesis-v1.md；禁止在测试向量中自行重新设计 Genesis 编码。
