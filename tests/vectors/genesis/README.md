# Genesis 测试向量

- **source**: Nova Chain 协议（`docs/protocols/genesis-v1.md`）
- **specification**: genesis-v1.md（Genesis canonical data、genesis_hash、ValidateGenesis）
- **encoding**: JSON（human-readable 向量格式）；`chain_id` 为 u64 整数；`genesis_timestamp` 为 u64 秒
- **expected behavior**:
  - fixture 必须包含 genesis-v1.md §1 的 7 个顶层字段：
    `network_id / chain_id / genesis_timestamp / initial_validator_set / initial_accounts /
     protocol_parameters / economics_parameters`。
  - `expected_genesis_hash`: 记录预期（**DEFERRED_VALIDATION**——genesis canonical 子结构在
    对应 Phase 定稿，PHASE 7 启用重算；本阶段不伪造 PASS）。
  - loader 本阶段验证：字段存在 + 类型（数组/对象/整数）。

**注意**：Genesis fixture 必须遵循 genesis-v1.md；禁止在测试向量中自行重新设计 Genesis 编码。
