# ADR-0054: Node Lifecycle Architecture

- Status: FROZEN (STEP 10-16B, 2026-09-04)
- Related: STEP 10-16A / 10-15T / 10-15T-HARDEN / ADR-0033（Consensus 架构）
- Scope: node-local 装配层（非共识协议；不改变 consensus/crypto/core 语义）

## Context

- 生产节点缺少统一生命周期：区块应用路径（`bootstrap::start` → `NodeBlockAdapter`）与共识投票验证者路径（`ValidatorActor` / `NodeConsensusDriver` / `ValidatorSafetyStore` / `ConsensusNode`）各自实现，**验证者侧目前仅测试接线**，无生产装配、无 `main`/event loop。
- 已冻结安全语义（10-15T + HARDEN）：persist-before-sign、double-vote 保护、fail-closed SafetyStore（独立于 canonical storage）、validator identity 绑定、L-8、`VoteLedger`/`SigningCapability` 冻结 API。
- 需要为 Bootstrap / Key Management / Node Startup / Validator Registration / Network Join 提供统一架构基础，同时**不破坏**上述安全边界、不把 validator-local/fs 状态并入 canonical ConsensusState。

## Decision

1. 引入单一装配根 **`NodeRuntime`**（node crate），拥有并编排：block adapter（chain storage）+ `ConsensusNode`/`NodeConsensusDriver` + （validator_enabled 时）`ValidatorActor(s)` + `ValidatorSafetyStore` + （未来）network。
2. **启动顺序固定**（12 步）：Config → Genesis → ChainIdentity 校验 → chain storage → KeyProvider → derive ValidatorId → SafetyStore open → strict recover → ValidatorActor restore → ConsensusNode → Network → EventLoop；验证者侧任一步安全失败 ⇒ **validator mode 启动失败（fail closed）**。
3. **KeyProvider seam**（不修改 `SigningCapability`）：`load_signer() -> SigningCapability`；ValidatorActor 不知私钥位置/载体（software/HSM/remote/KMS 均为实现）。
4. **SafetyStore ownership = NodeRuntime**（非 ValidatorActor 自建）：Runtime open→recover→identity check→inject。
5. **ValidatorId 单一来源**：`derive_validator_id(public_key)`（唯一实现）；consensus 只引用。
6. **Key rotation 规则**：换公钥 ⇒ 新 ValidatorId ⇒ 新 SafetyStore；**禁旧 journal 复用**（identity mismatch 天然 fail closed）。
7. **目录分离**：`node-data/{chain, validator, keys}`；Safety journal 绝不入 chain storage，反之亦然；两种 recovery 语义永不混淆。
8. **Restart recovery 边界**：SafetyStore 管 intent/signature/lock；不持久化 DAG/finality/consensus round（后者未来独立设计）。

## Consequences

- **正面**：验证者可从配置+密钥+genesis 确定性启动；安全失败可预测（fail closed）；安全存储与共识存储边界清晰；HSM/remote 未来接入不改安全核心；多验证者隔离与 key rotation 规则落地。
- **代价**：`NodeConfig` 扩展与目录迁移（storage_dir → node_data_root 语义）；Runtime 装配代码；KeyProvider 首载（SoftwareKey）与 secret-handling 纪律要求。
- **风险（已缓解）**：装配 bug 不得静默降级（所有失败显式 Err）；SafetyStore 与 chain storage 目录必须强制分离（文档 + 目录参数独立）。
- 本 ADR 不改变任何冻结共识/安全原语；实施需单独 Owner 授权。

## Non-goals

- 不实现网络 transport / P2P event loop / join（仅留 seam）。
- 不实现 HSM / Remote signer / Cloud KMS 具体载体（仅 KeyProvider 抽象）。
- 不持久化 canonical `ConsensusState`（round/finality）。
- 不冻结主网 Genesis 值；不实现 validator key 导入 UI。
- 不修改 `VoteLedger` 冻结 API、L-8、Safety Journal 格式、`SigningCapability`、consensus/crypto/core 语义。

---

> FROZEN（STEP 10-16B DESIGN FREEZE，2026-09-04）。实现需 Owner 单独授权 IMPLEMENT STEP 10-16。
