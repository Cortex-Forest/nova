# Block 测试向量

- **source**: YAZIMAO 协议（ADR-0029 block state root 验证 / ADR-0030 state root calculator / ADR-0042 block format）
- **specification**: ADR-0029（D-2/D-3 execute / validate；D-6 验证链）、ADR-0030（state root 计算）、
  `docs/protocols/block-validation-design-v1.md`、`docs/protocols/block-lifecycle-design-v1.md`
- **encoding**: JSON（human-readable 向量格式，**非** YAZIMAO 协议编码）；字节字段为**小写 hex**；
  schema `block-state-root-v1`

## loader 覆盖范围（STEP 8D-5）

- **验证链**：seed `StateStore` → `execute_block` → `apply_block` → `state_root` →
  `verify_block_state_root`（ADR-0029 D-6）。
- **valid**：execute 成功 → apply → `verify_block_state_root` == `expected.state_root`。
- **invalid**：`execute_block` 返回 `BlockError`（nonce conflict / gas 超限 / 参数）⇒ 断言**状态不变**。

## 覆盖类别

single transfer / multi transfer / nonce conflict / gas over limit / skip failed。

## 明确不覆盖

- 交易层编码与签名：见 `tests/vectors/transaction/`。
- 完整 Block canonical 编码与签名承载：规范见 ADR-0042；其实现位于 `nova-core` / `nova-runtime`，
  **其测试覆盖未在本向量范围内核验**。

## 生成方式

```text
cargo run -p nova-test-vectors --bin gen_block_vectors
```

- 期望值由生成器调用生产实现重算写入并静态提交（loader 独立重算比对，不信任向量值）。
