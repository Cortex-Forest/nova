# ADR-0034: Validator Set & Vote Verification V1

- **Status**: Proposed（待批准）
- **Date**: 2026-08-28
- **Deciders**: Nova Chain 架构组
- **Scope**: STEP 10 — Consensus（ValidatorSet + Vote Verification，10-2）
- 关联：ADR-0033（C-1~C-9）、ADR-0009（Vote 签名覆盖）、ADR-0005（DomainId::ValidatorVote）、
  ADR-0014/0015（genesis validator set / stake）、ADR-0012（Ed25519）

## Context

ADR-0033 冻结 Consensus 架构（C-1~C-9）。本 ADR 冻结 **ValidatorSet 与 Vote Verification（10-2）**：
类型归属、权重模型、quorum 计算、`ValidatorVote` schema、投票验证流程、实现边界。

## Decision（冻结）

### V-1 — ValidatorSet Ownership（冻结）

- 归属 **`nova-consensus`**（`validator.rs`）：
  ```rust
  pub struct ValidatorId([u8; 32]);                 // = SHA-256(consensus_public_key)
  pub struct ValidatorInfo {
      pub validator_id: ValidatorId,
      pub consensus_public_key: [u8; 32],           // Ed25519 压缩点
      pub account_address: NovaAddress,             // 链账户（fee/reward 归属）
      pub voting_weight: u128,                      // 投票权重（genesis stake）
  }
  pub struct ValidatorSet { validators: Vec<ValidatorInfo>, total_weight: u128 }
  ```
- ValidatorSet 属**共识安全域**：非账户系统、非执行状态、非网络身份。
- 依赖保持 `consensus → core/crypto`；禁 → execution/storage/network（C-1）。

### V-2 — Genesis Stake Weight Model（冻结）

- **`weight(v) = genesis.initial_validator_set[v].stake`**（静态）。
- 理由：确定性、不访问 execution state、不依赖账户余额、不引入经济模块耦合。
- 动态 stake（account balance → weight）留 **PHASE 7+ economics/governance**。

### V-3 — Quorum Calculation（冻结）

```rust
impl ValidatorSet {
    pub fn contains(&self, validator_id: &ValidatorId) -> bool;
    pub fn weight_of(&self, validator_id: &ValidatorId) -> Option<u128>;
    pub fn total_weight(&self) -> u128;
    pub fn quorum(&self) -> u128;      // ceil(total_weight * 2 / 3)
    pub fn is_quorum(&self, weight: u128) -> bool;   // weight >= quorum()
}
```

- **`quorum = ceil(T * 2 / 3)`**，即 `3Q >= 2T`（Q=quorum, T=total voting weight；C-5 ≥2/3 weighted）。

### V-4 — ValidatorVote Schema（冻结）

```rust
pub enum VoteType { Prevote = 0x01, Precommit = 0x02 }

pub struct ValidatorVote {
    pub round: u64,
    pub height: u64,
    pub target_block_hash: [u8; 32],
    pub vote_type: VoteType,
    pub source_block_hash: [u8; 32],
    pub validator_id: ValidatorId,
    pub timestamp: u64,
}
```

- **Canonical 顺序**：`round ‖ height ‖ target_block_hash ‖ vote_type ‖ source_block_hash ‖
  validator_id ‖ timestamp`（与 ADR-0009 完全一致）。

### V-5 — Vote Verification Pipeline（冻结）

```rust
pub fn verify_vote(vote: &ValidatorVote, vk: &VerifyingKey, chain_id: u64)
    -> Result<(), ConsensusError>;
```

流程：`① ValidatorSet membership → ② validator_id == hash(consensus_public_key) →
③ build_signed_bytes(Ed25519, ValidatorVote, chain_id, payload) → ④ hash_signing_message →
⑤ verify_strict`。

```rust
pub enum ConsensusError {
    UnknownValidator,            // ① 非 ValidatorSet 成员
    ValidatorIdentityMismatch,   // ② validator_id 与公钥不符
    InvalidSignature,            // ⑤ 签名验证失败
    InvalidVoteEncoding,         // canonical 编码错误
    InvalidDomain,               // 域分离错误
    InvalidChainId,              // chain_id 不匹配
}
```

- `verify_vote` **不负责**：round 状态 / double vote / finality / fork choice（10-5 BFT Round）。

### V-6 — Implementation Boundary（冻结）

- 本 STEP 只实现：`ValidatorSet` + `ValidatorVote` + **Signature Verification**（纯函数）。
- **不实现**：DAG（10-3）/ Random Witness（10-4）/ BFT Round（10-5）/ Finality（10-6）/
  Checkpoint（10-7）。

### Decision Log

| # | 决策 | 状态 |
|---|------|------|
| V-1 | ValidatorSet 归属 nova-consensus（validator.rs） | 冻结 |
| V-2 | weight = genesis initial_stake（静态） | 冻结 |
| V-3 | quorum = `ceil(T*2/3)`；`3Q >= 2T` | 冻结 |
| V-4 | `ValidatorVote` + `VoteType{Prevote,Precommit}` canonical（ADR-0009） | 冻结 |
| V-5 | verify_vote 五步 + `ConsensusError` | 冻结 |
| V-6 | 边界（只 ValidatorSet/Vote/签名验证） | 冻结 |

## Alternatives（已评估）

| 方案 | 否决原因 |
|------|---------|
| weight = 账户余额（动态） | 需 execution state，违反 C-1 纯计算（V-2） |
| quorum = 简单多数（>1/2） | 非 BFT 安全条件；需 ≥2/3（V-3/C-5） |

## Consequences

- **正面**：ValidatorSet/Vote 纯函数、确定性、与 execution/storage/network 解耦。
- **成本**：静态权重（动态 stake 延后 PHASE 7+）。
- **可迁移**：BLS 聚合签名未来 ADR 迁移（Vote 结构不变）。

## Security Impact

- 防伪装：validator_id 与公钥身份绑定（V-5 ②）。
- 防越权投票：成员 + 权重检查（V-5 ① / V-3）。
- 防签名绕过：verify_strict + 域分离（V-5 ⑤）。
