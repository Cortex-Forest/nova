# Address 测试向量

- **source**: Nova Chain 协议（ADR-0004/0008/0011）
- **specification**: ADR-0004（地址格式与解码规则）、ADR-0008（address_type）、ADR-0011（network/HRP）
- **encoding**: `address` 为 Nova Custom Address Format（Bech32m-derived 文本）；JSON 字段为 human-readable 向量格式
- **expected behavior**:
  - **STEP 5** 起 **真实 codec 验证**（不再 DEFERRED）：loader 委托 `nova_crypto::address`，
    对 VALID 向量执行 `decode` + payload 字段（version/type/network/key_hash）匹配 + canonical
    roundtrip；对 INVALID 向量验证 `decode` 拒绝且错误类别与 `expected_error` 一致。
  - `expected`: codec 层最终预期（`VALID`/`INVALID`）。
  - `expected_error`: INVALID 向量的期望错误类别（`InvalidHrp`/`InvalidChecksum`/
    `NetworkMismatch`/`UnsupportedVersion`/`UnknownAddressType`/`InvalidLength`/`NonCanonicalCase`）。
  - `address` 字符串为**真实 Bech32m 地址**（由 `gen_address_vectors` 生成器用生产 codec 生成，
    不伪造）。

覆盖类别（§14）：valid mainnet / valid testnet / valid devnet / wrong HRP / wrong checksum /
wrong network / unknown address_type / unknown version / wrong payload length / uppercase /
mixed case / mutated char / truncated / extra char。
