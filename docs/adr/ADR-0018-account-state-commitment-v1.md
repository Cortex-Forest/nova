# ADR-0018: Account State Commitment V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-26
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 3 — Account / Transaction（设计冻结）
- 关联：ADR-0004（地址 payload）、ADR-0017（Account Model V1）、ADR-0015（canonical 编码）、
  `crypto-serialization-v1.md`（LE/定长 bytes）

## Context

账户状态如何被承诺（commitment）进入 State Root。本 ADR 冻结**账户 value 的 canonical
序列化与承诺**；**trie 结构 / 空根 / key hashing / proof / state root computation 由
STEP 8（Storage）定义**（不在此提前实现/定义）。

## Decision（建议，待批准）

### 1. Trie Key / Value（账户定位与内容分离）

```
Trie Key   = NovaAddressPayload raw bytes（35B，ADR-0004）
Trie Value = AccountState commitment（见 §5）
```

- AccountState value **不保存 address**（address 由 trie key 定位）。
- **安全不变量**：*AccountState value 只有在与对应 trie key 绑定后才构成完整账户状态*；
  单独取出的 value 不构成可验证的账户（必须经 key 绑定）。

### 2. Canonical Account Bytes（账户 value 序列化）

```rust
canonical_account_bytes =
    balance(16B LE)
  ‖ nonce(8B LE)
  ‖ code_hash(32B)
  ‖ storage_root(32B)
  = 88 B
```

- 仅账户状态字段；**不含 address / account_type**（ADR-0017 §2）。
- 整数 LE；定长 bytes 无前缀（`crypto-serialization-v1.md` §1–§3）。
- 本定义只是 **account value serialization**；最终如何进入 State Root → STEP 8。

### 3. Empty Code Hash（冻结）

```
EMPTY_CODE_HASH = SHA-256(empty bytes)   // e3b0c44298fc1c149afbf4c8996fb924…
```

- User Account（`0x01`）：`code_hash = EMPTY_CODE_HASH`。
- Contract（`0x02` Reserved）：`code_hash = SHA-256(contract_code)`（PHASE 12 定义）。

### 4. Empty Storage Root（预留，数值 DEFERRED）

```
EMPTY_STORAGE_ROOT   // 协议预留常量；具体数值 DEFERRED TO STEP 8 STORAGE/TRIE SPEC
```

- **禁止当前实现自行定义** `EMPTY_STORAGE_ROOT` 数值（D8，ADR-0017）。
- V0.1 无存储：`storage_root = EMPTY_STORAGE_ROOT`。

### 5. Account Commitment

```
account_commitment = SHA-256(canonical_account_bytes)   // 88B value 的 32B 承诺
```

- 使用 `protocol_hash`（SHA-256，ADR-0006）。

### 6. State Root Integration（DEFERRED）

- 账户集合如何由 trie（key=35B payload，value=account_commitment）聚合为 State Root、
  空 State Root 值、proof、node 编码、持久化 → **STEP 8 统一冻结**。
- 本 ADR 不提前固定 trie 类型或空根常量。

## Consequences

- **正面**：账户承诺与身份绑定清晰；value 最小（88B）；可安全延后 trie 定义。
- **成本**：实现前需等 STEP 8 确定空根/聚合。
- **可迁移**：Contract 复用同一 value 布局（code_hash/storage_root 预留）。

## Security Impact

- 防账户替换：value 必须与 trie key 绑定（安全不变量）。
- 防冗余身份伪造：value 不含 address/account_type ⇒ 无两套身份来源。
- 空根/聚合留 STEP 8 冻结 ⇒ 不提前固化易错值。
