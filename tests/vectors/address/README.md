# Address 测试向量

- **source**: Nova Chain 协议（ADR-0004/0008/0011）
- **specification**: ADR-0004（地址格式与解码规则）、ADR-0008（address_type）、ADR-0011（network/HRP）
- **encoding**: `address` 为 Nova Custom Address Format（Bech32m-derived 文本）；JSON 字段为 human-readable 向量格式
- **expected behavior**:
  - STEP 1（本阶段）**不实现 address codec** ⇒ 地址字符串的实际编码/解码验证标记
    **`DEFERRED_VALIDATION`**（STEP 5 实现后启用）。
  - loader 本阶段验证 **schema 层**：字段存在、`network_id` 注册（0x01-0x03）、
    `address_version` 支持（0x01）、`address_type` 非 0x00、地址非空。
  - `schema_expected`: 本阶段 schema 层预期（`VALID`/`INVALID`）。
  - `expected`: codec 层最终预期（DEFERRED）。
  - `address` 字符串为**占位示例**（真实向量 STEP 5 由 codec 生成），不在此阶段伪造。

覆盖类别（§14）：valid mainnet / valid testnet / valid devnet / wrong HRP / wrong checksum /
wrong network / unknown address_type / unknown version / wrong payload length / uppercase /
mixed case / mutated char / truncated / extra char。
