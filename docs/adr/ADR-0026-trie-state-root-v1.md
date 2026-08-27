# ADR-0026: Trie & State Root V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-27
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 4 — Storage（State Commitment Layer，STEP 8B-1）
- 关联：ADR-0006（protocol_hash / SHA-256）、ADR-0017（AccountState）、ADR-0018（账户承诺 / trie key）、
  ADR-0023（AccountChange / state root placeholder）、ADR-0025（Storage 架构 / S-E SMT 候选）、
  `crypto-serialization-v1.md` §12

## Context

State Commitment 层冻结：**State Root 必须由确定性算法派生**（非 magic），任何节点独立重算一致。
本 ADR 冻结 **Binary Sparse Merkle Tree（SMT）** 的架构级细节（T-1~T-7）。

**边界（STEP 8B 不得回改）**：`AccountState` 字段、`Transaction` bytes、`txid`、Execution 顺序、
Gas 规则均不变；不引入数据库依赖。7G / 7H / 8A 边界保持不变。

## Decision（建议，待批准）

### 1. SMT Selection（T-1）

- **Binary Sparse Merkle Tree**：每个 branch 2 children，bit path；深度固定。
- 理由：固定路径、天然 inclusion/exclusion proof、状态同步友好、不依赖排序结构、适合 L1 state commitment。
- 否决：普通 Merkle List（无 key 寻址 / proof 大）、Verkle（V0.1 复杂不必要）。

### 2. Key Path（T-2）

- **保持 ADR-0018**：`trie key = NovaAddressPayload raw bytes`（35B）。
- SMT path：`35 B × 8 bit = 280 bit`。
- 冻结：
  ```
  SMT_DEPTH = 280
  address → NovaAddressPayload(35B) → SMT path (280 bits)
  ```
- **不采用** `SHA-256(address)`：不改 ADR-0018；proof 自包含地址；避免额外 address-binding layer；
  简化 light client 验证。
- 位序：path 最高位（bit 0 = key[0] 的最高位）为树的最高层；bit 1 走 right，bit 0 走 left
  （`bit 1 => right, bit 0 => left`）——实现时在 8B-2 细冻结并测试固化。

### 3. Node Encoding（T-3）

```
EmptyNode:   （无字节表示；用 EMPTY_NODE_HASH 常量替代空子树根）
LeafNode:    type(1B) ‖ key(35B) ‖ value_hash(32B)
BranchNode:  type(1B) ‖ left_hash(32B) ‖ right_hash(32B)
```

- Leaf 编码：`0x01 ‖ key[35] ‖ value_hash[32]`；value_hash = `account_commitment`（ADR-0018）。
- Branch 编码：`0x02 ‖ left[32] ‖ right[32]`（left = bit 0，right = bit 1）。
- **Leaf 保留完整 key（35B）**（T-7）：防路径歧义；proof 可独立验证；debug / state inspection 安全。
- Leaf key 为 raw 35B（**不是** `hash(key)`）。

### 4. Hash Domain Separation（T-4）

```
STATE_EMPTY  = 0x00
STATE_LEAF   = 0x01
STATE_BRANCH = 0x02
```

```
EMPTY_NODE_HASH = SHA-256(0x00)
leaf_hash       = SHA-256(0x01 ‖ key ‖ value_hash)
branch_hash     = SHA-256(0x02 ‖ left_hash ‖ right_hash)
```

- 统一经 `protocol_hash`（SHA-256，ADR-0006）。
- 分离 leaf / branch / empty hash 域 ⇒ 防类型混淆 / 二阶碰撞。

### 5. Empty Root Derivation（T-5）

```
EMPTY_STATE_ROOT = EMPTY_NODE_HASH = SHA-256(0x00)
EMPTY_STORAGE_ROOT = EMPTY_STATE_ROOT
```

- V0.1 不实现账户内部 storage trie；`storage_root` 仅作协议字段存在，默认 = `SHA-256(0x00)`。
- **不直接写死十六进制**；采用 **algorithm-derived constant**：
  ```
  SHA-256(0x00) → generator → golden vector → loader verification
  ```
  （与 genesis golden 模式一致；数值由算法派生 + 生成器固化 + loader 独立重算比对）。
- 解冻 ADR-0017 D1/D8、ADR-0018 D1/D8 的 DEFERRED 项。

### 6. State Root Formula（T-6）

```
state_root = SMT_root({ (trie_key(35B) → account_commitment(32B)) 对全部显式账户 })
```

- 隐式账户（不存在）不写入 trie（SMT 空路径天然表示）。
- 空 state（无账户）⇒ `EMPTY_STATE_ROOT`。
- `apply(AccountChange[])` → 更新 trie → 算新 `state_root`（ADR-0025 S-C 衔接；8C 实现）。

### 7. Proof Boundary（T-6 / 8B-4 冻结范围）

- **Inclusion Proof**：leaf + ≤280 sibling hashes（root → 280 levels → leaf）。
- **Exclusion Proof**：SMT 原生支持——路径上遇空节点即证明不存在。
- **暂不冻结**（留 STEP 8B-4）：proof serialization / proof compression / RPC API。

### 8. Compatibility Constraints

- 本 ADR 只冻结 State Commitment 层；**不修改** Transaction / Execution / Gas / AccountState 语义。
- trie 实现 / state root 计算 / empty root generator / node hashing / proof 设计在 8B-2/8B-3/8B-4 实现。
- 引入任何数据库依赖 ⇒ 禁止（8E 之前）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| T-1 | Binary SMT，深度固定 | 冻结 |
| T-2 | `SMT_DEPTH=280`；key = 35B raw（不改 ADR-0018） | 冻结 |
| T-3 | Node encoding：empty / leaf(type‖key‖value_hash) / branch(type‖l‖r) | 冻结 |
| T-4 | Hash domain：`STATE_EMPTY=0x00` / `STATE_LEAF=0x01` / `STATE_BRANCH=0x02` | 冻结 |
| T-5 | `EMPTY_STATE_ROOT = EMPTY_STORAGE_ROOT = SHA-256(0x00)`（算法派生+固化） | 冻结 |
| T-6 | `state_root = SMT_root({35B key → commitment})`；proof 边界 8B-4 | 冻结 |
| T-7 | Leaf 含完整 35B key（非 hash(key)） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| 普通 Merkle List | 无 key 寻址 / proof 大 |
| Verkle | V0.1 复杂不必要 |
| `SHA-256(address)` 作 key | 改 ADR-0018；额外 address-binding layer；light client 复杂 |
| Leaf 存 hash(key) | 路径歧义；proof 需额外绑定 |
| empty root 直接写死 hex | 应为 algorithm-derived + golden 固化（可复现验证） |

## Consequences

- **正面**：State Root 完全确定性、可复现；proof 自包含地址；与 genesis golden 模式一致。
- **成本**：280-bit SMT 需自定义实现（无标准库直接匹配）；8B-2/3/4 分步实现。
- **可迁移**：空根/节点编码经 golden 固化，跨实现可验证。

## Security Impact

- 防状态根歧义：domain separation（leaf/branch/empty 前缀）。
- 防 key 碰撞/重排：leaf 含完整 key。
- 防 magic root：`EMPTY_STATE_ROOT` 由算法派生 + golden 验证。
- 防部分提交：State Root 由 `apply` 原子计算（ADR-0025 S-D）。
