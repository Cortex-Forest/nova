# Signature 测试向量

- **source**: Nova Chain 协议（ADR-0002/0005/0009/0012）
- **specification**: `docs/protocols/crypto-serialization-v1.md` §10、`crypto-test-vectors-v1.md` §3/§3b
- **encoding**: JSON（human-readable 向量格式）；hex 一律**小写**；`chain_id` 为 u64 整数
- **expected behavior**:
  - STEP 1（本阶段）**不实现 Ed25519** ⇒ `public_key`/`signature` 的密码学验证标记
    **`DEFERRED_VALIDATION`**，报告 `VECTOR_VALIDATION_READY` 而非伪造 `CRYPTO_SIGNATURE_PASS`。
  - loader 本阶段验证：schema、严格 hex、`signed_bytes`/`message_hash` 独立重算比对。
  - `validation_scope`:
    - `SCHEMA`: 本阶段可验证（hex/字段/链路一致/注册表值）⇒ 断言与 `expected` 一致。
    - `CRYPTO`: 需 Ed25519 验证（DEFERRED）⇒ 本阶段只验证就绪，不断言签名结果。

字段（crypto-test-vectors-v1.md §3b）：`algorithm_id / domain_id / chain_id / canonical_payload /
signed_bytes / message_hash / public_key / signature / expected / validation_scope`。
