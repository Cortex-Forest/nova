# Domain 测试向量

- **source**: Nova Chain 协议（ADR-0005 Domain Registry / crypto-serialization-v1.md §10）
- **specification**: `docs/protocols/crypto-serialization-v1.md` §10（签名流水线）、ADR-0005
- **encoding**: 字段为 JSON（仅 human-readable 向量格式，非协议编码）；`canonical_payload`/`signed_bytes`/`message_hash` 为**小写 hex**
- **expected behavior**:
  - `signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE) || payload_length(4B LE) || canonical_payload`
  - `message_hash = SHA-256(signed_bytes)`
  - 同 payload 跨 domain / 跨 chain ⇒ 必须产生不同 signed_bytes / message_hash（loader 重算比对）
  - 未注册 `domain_id` / `algorithm_id` ⇒ 必须拒绝（禁 fallback）

字段说明：
- `algorithm_id`: u8（0x01=Ed25519 实现；0x02/0x03 Reserved ⇒ 拒绝）
- `domain_id`: u8（0x01 Tx / 0x02 Vote / 0x03 Block / 0x04 Governance / 0x05 Address）
- `chain_id`: u64（整数；loader 按冻结规范生成 8 字节 LE）
- `canonical_payload`: hex（签名覆盖字段的 canonical 编码，占位数据）
- `signed_bytes` / `message_hash`: 由生成器回填；**loader 不信任向量值，独立重算比对**
- `expected`: `VALID`（schema+链路一致+注册）或 `INVALID`（期望被拒绝）
