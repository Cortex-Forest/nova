# Transaction 测试向量

- **source**: YAZIMAO 协议（ADR-0019 / ADR-0020 / ADR-0021 / ADR-0022 / ADR-0023 / ADR-0024）
- **specification**: ADR-0019（Transaction schema）、ADR-0020（type 注册表）、ADR-0021（nonce / replay）、
  ADR-0022（gas / fee）、ADR-0023（state transition）、ADR-0024（向量规范）、
  `docs/protocols/crypto-serialization-v1.md`
- **encoding**: JSON（human-readable 向量格式，**非** YAZIMAO 协议编码）；字节字段为**小写 hex**；
  `chain_id` 为 u64 整数

## loader 覆盖范围（STEP 7H；ADR-0024 §3）

- **派生重算**（loader 独立计算并与向量值比对）：`canonical_tx_payload` / `signed_bytes` /
  `message_hash` / `canonical_transaction_bytes` / `txid`。
- `signature` 为**输入 + 验证**：valid 向量执行验签；signature 类 invalid 向量要求验签失败。
- **结果分类**：委托生产实现（`nova_execution::state_transition::apply_transaction`）执行，
  断言与 `expected` 一致，且失败时**状态无副作用**。
- 任意一层编码变化 ⇒ `txid` 变化（与 7C/7D proptest 共同固定）。

## 覆盖类别

normal transfer / self transfer / zero amount / zero value（no create）/ receiver created / receiver existing /
nonce current / nonce future / nonce too low / nonce max / expired / fee normal / fee overflow /
gas limit invalid / gas price invalid / required overflow / modified payload / modified signature /
wrong chain / wrong network / signature valid / success transition / failed（no mutation）。

## 明确不覆盖

- Ed25519 算法实现本身：由 `nova-crypto` 单元测试覆盖。
- 状态根 / 持久化：见 `tests/vectors/block/`。

## 生成方式

```text
cargo run -p nova-test-vectors --bin gen_transaction_vectors
```

- 期望值（六层）由生成器调用生产实现重算写入并静态提交到 fixture；loader 独立重算比对，不信任向量值。
