# O2 Round-Change Certificate 测试向量

- **source**: YAZIMAO 协议（ADR-0066 / ADR-0070 / ADR-0067，均 **FROZEN**）
- **specification**:
  - `docs/adr/ADR-0066-round-change-certificate-v1.md`（结构 / `to_round = from_round + 1`）
  - `docs/adr/ADR-0070-roundchangecertificate-canonical-serialization-v1.md`（canonical 编码）
  - `docs/adr/ADR-0067-domain-registry-amendment-v1.md`（`RoundChangeCertificate = 0x10`）
- **encoding**: 字段为 JSON（仅 human-readable 向量格式，**非**协议编码）；字节字段为**小写 hex**

## 生成方式（PHASE 6H-Y §17）

```text
cargo run -p nova-test-vectors --bin gen_round_change_vectors
```

- 期望值由**实现阶段实际 codec**（`nova_consensus::round_change`）产生；**禁止手工构造字节**。
- 私钥仅存在于生成器进程内（确定性 dev seed，**非 production key**）；向量只写**公钥**。

## 字段说明

- `algorithm_id`: u8（`0x01` = Ed25519，ADR-0012）
- `domain_id`: u8（`0x10` = `RoundChangeCertificate`，ADR-0067）
- `chain_id` / `height` / `from_round`: u64（整数；loader 按冻结规范生成 8 字节 LE）
- `canonical_payload`: hex，**精确 16B** = `height(8B LE) ‖ from_round(8B LE)`
- `signed_bytes`: hex，`algorithm_id(1B) ‖ domain_id(1B) ‖ chain_id(8B LE) ‖ payload_length(4B LE) ‖ payload`
- `message_hash`: hex，`SHA-256(signed_bytes)`
- `certificate_bytes`: hex，`validator_set_id(32B) ‖ height(8B LE) ‖ from_round(8B LE) ‖ evidence_count(2B LE) ‖ evidence[96×n]`
- `certificate_len`: 派生长度（`50 + 96n`；上界 `MAX_CERTIFICATE_BYTES = 2066`）
- `to_round`: 派生目标 round（`from_round + 1`；**不编码、不签名**）
- `validator_set_id`: hex 32B（本向量固定占位；真实网络 = genesis hash）
- `evidence[]`: `{ validator_id(hex 32B), signature(hex 64B) }`，按 `validator_id` **严格升序**
- `validators[]`: `{ validator_id, public_key, weight }`（仅公钥；用于 `validator_id` 派生校验与验签）
- `expected`: `VALID`
- `signed_bytes` / `message_hash` / `certificate_bytes` / `certificate_len` / `to_round` 由生成器回填；
  **loader 不信任向量值，独立重算比对**

## loader 覆盖范围（§17 清单）

exact canonical bytes、exact signing statement、exact hash / signing message、algorithm ID、
domain ID `= 0x10`、chain_id 编码、height、from_round、signature verification、
`validator_id = SHA-256(consensus_public_key)` 派生、evidence 严格升序 / 无重复、quorum 算术
（`weight >= ceil(2T/3)`）。

## 明确不覆盖（由其他测试承担）

- 完整 `verify_certificate`（需 `ValidatorSet` + genesis）：由 `nova-consensus` 聚焦单元测试覆盖。
- wire 层（`MessageType = 0x0D`）：由 `nova-network` 集成测试覆盖。

## 安全边界

`RoundChangeCertificate` **不得**成为 QC / 投票证据 / `QcRegistry` 条目，
**不得**触发 finality，**不得**修改 lock。本向量仅覆盖 codec 与签名验证，不涉及上述语义路径。
