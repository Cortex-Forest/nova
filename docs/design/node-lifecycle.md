# Nova Node Lifecycle Architecture

> STEP 10-16A — Validator Lifecycle Architecture Design；**STEP 10-16B FROZEN（2026-09-04）**。
> 基线：HEAD a166077（10-15T + 10-15T-HARDEN OBS-3B 已提交/冻结）。
> 本文档是已冻结架构设计；下一阶段需 Owner 单独授权 IMPLEMENT STEP 10-16。

## 1. Scope

定义生产节点（Node）的统一生命周期架构，把当前**相互独立**的两条已实现路径——

1. **区块应用侧**（`bootstrap`/`block_adapter`：Genesis → Storage → `NodeBlockAdapter`）；
2. **共识投票验证者侧**（`signer`/`validator`/`vote_ledger`/`safety_store`/`driver`/`assembly`：原语齐备、现仅测试接线）——

统一进单一 `NodeRuntime` 装配入口，覆盖：Bootstrap、Key Management seam（KeyProvider）、Validator Registration（enable/disable）、Safety Store 生命周期、Consensus 启动、Network Join 前置。

**范围外（Non-goals）**：不实现网络 transport/event loop；不实现 Key Management 具体载体（软件加密密钥/HSM/remote/KMS 只定义 seam）；不持久化 canonical `ConsensusState`（round/finality）；不冻结主网 Genesis 值。

**安全边界（继承，不可破坏）**：RT-INV-1（no double vote）、RT-INV-2（persist before sign）、RT-INV-3（persistence failure fail closed）、RT-INV-4（validator identity binding）、RT-INV-5（SafetyStore 独立于 canonical consensus state）；`VoteLedger` 冻结 API、L-8 `LockedState` 语义、Safety Journal 二进制格式、`SigningCapability` trait 均不得修改。

## 2. Current State

| 组件 | 状态 | 生产接线 |
|---|---|---|
| `bootstrap::start()` | ✅ 已实现 | 生产唯一入口；返回 `NodeBlockAdapter`（Genesis load/decode/validate → PersistentBackend open → StateStore load_with_head → first-start vs restart → head） |
| `ConsensusNode`（assembly） | ✅ 原语 | ❌ 仅 test 构造 |
| `NodeConsensusDriver`（driver） | ✅ 原语 | ❌ 仅 test 构造 |
| `ValidatorActor`（validator） | ✅ 原语（new/restore + store seam） | ❌ 仅 test 构造 |
| `ValidatorSafetyStore`（safety_store） | ✅ 原语（create/at/recover/identity） | ❌ 仅 test 构造 |
| `SigningCapability`/`SoftwareSigner`（signer） | ✅ 原语 | ❌ KeyPair::generate 仅 test；无持久化密钥供给 |
| Network（nova-network） | 原语（envelope/gossip/sync/MemoryTransport） | ❌ 无 TcpTransport / event loop / join |
| `config::Config` | ⚠️ 空占位 | — |
| Node 可执行 / main | ❌ | 无 bin（纯 lib crate） |

**当前启动流程图（标记：✅ 存在 / ⚠️ 半成品 / ❌ 缺失）**
```
process start
  ↓ config load            ⚠️ NodeConfig（genesis/storage）；无 validator/key/network 字段
  ↓ identity load          ✅ genesis → ChainIdentity（network/chain/genesis_hash）
  ↓ storage init           ✅ PersistentBackend + StateStore（canonical 块/状态）
  ↓ safety recovery        ❌ 模块就绪、未装配
  ↓ validator init         ❌ 仅测试
  ↓ consensus start        ❌ 仅测试
  ↓ network start          ❌ 无 transport/join/event loop
```
两条路径未连接、无统一 Node 生命周期。

## 3. Target Architecture

单一 `NodeRuntime`（node crate 内装配根），按「全节点 / 验证者节点」两种 mode：

```
NodeRuntime
 ├── block path   : NodeBlockAdapter (bootstrap 产出; chain storage)
 ├── consensus    : ConsensusNode (canonical state) + NodeConsensusDriver
 ├── validator(s) : [ValidatorActor] (仅 validator_enabled) —— each owns VoteLedger+LockedState,
 │                   injected SafetyStore (ValidatorSafetyStore) + KeyProvider-produced Signer
 ├── safety       : ValidatorSafetyStore (validator-only; validator/ 目录, fail-closed)
 └── network      : network handle (未来 transport/event loop)
```

原则：
- `NodeRuntime` **拥有生命周期**（open/start/stop）；组件不自行创建自己的存储/安全状态。
- SafetyStore 与 canonical chain storage **目录分离、语义分离、生命周期分离**。
- Validator 相关只存在于 `validator_enabled=true` 分支；全节点（无验证者）不触碰 KeyProvider/SafetyStore。
- 不把任何 validator-local / fs 状态并入 `ConsensusNode`/canonical state。

## 4. Node Startup Sequence（固定）

```
1.  Load Config            NodeConfig（含 validator.enabled / key provider / 目录 / network）
2.  Load Genesis           读 canonical genesis 文件
3.  Validate ChainIdentity validate_genesis_with_expected → ChainIdentity(network,chain,genesis_hash)
    + expected_chain_id / network_id 比对
4.  Init Storage           打开 canonical chain storage（chain/ 目录; PersistentBackend; 恢复 head）
5.  Load KeyProvider       （validator mode）解析 KeyProvider 配置 → 取得 SigningCapability（不暴露私钥）
6.  Derive ValidatorId     derive_validator_id(public_key)（单一来源）
7.  Open SafetyStore       （validator mode）ValidatorSafetyStore::at/create(validator/ 目录, SafetyIdentity)
8.  Recover Safety State   strict recover（magic→version→identity→checksum→replay）; 失败 ⇒ fail closed
9.  Construct ValidatorActor  inject recovered ledger+lock+store+signer（restore）
10. Construct ConsensusNode    set/chain_id/genesis_hash/dag from genesis+运行上下文
11. Start Network          （future）network handle; NodeId ≠ ValidatorId（身份隔离）
12. Start EventLoop        （future）P2P 收发 / timeout / block 生产 loop
```

**安全失败语义**：步骤 3/5/6/7/8/9 任何 mismatch / corruption / key mismatch / identity mismatch ⇒ **validator mode 启动失败**（`Err`，fail closed；绝不静默降级为空验证者 / 空 ledger / 清空 lock / 用默认 key）。全节点（validator disabled）跳过 5–9。

## 5. NodeRuntime Responsibility

- 装配与顺序编排（§4）；持有 canonical block adapter + consensus +（可选）validator(s) + safety store + network。
- 提供启动产物（chain head / genesis identity / validator_id / recovered state）给上层（未来 RPC / event loop）。
- 所有权：SafetyStore、KeyProvider 产出的 signer、ValidatorActor 均由 Runtime 创建并注入；**ValidatorActor 不自建 SafetyStore**（§7）。
- 停止（drop/stop）：safety store 由 drop 释放（无残留内存锁）；不负责 commit/persist 之外的关闭刷盘（store 每次写已 fsync）。
- 边界：Runtime 是编排层，不复制 consensus state / 不实现 quorum / finality / fork choice / proposer / pacemaker。

## 6. KeyProvider Design

**`SigningCapability` 不修改。** ValidatorActor / Safety 逻辑只依赖 `public_key()` + `sign(&SigningMessageHash)`。

设计 seam（未来实现，本步不写码）：
```text
trait KeyProvider {
    // 返回已绑定身份的签名能力；私钥永不出 Provider 边界。
    fn load_signer(&self) -> Result<Box<dyn SigningCapability>, KeyProvisionError>;
}
```
- ValidatorActor **不知道**：私钥位置 / 存储方式 / 是否远程 / 载体类型；只调用 `sign(message_hash)`。
- 未来实现载体：SoftwareKey（加密 seed 文件）、HSM、Remote signer、Cloud KMS —— 均实现该 trait。
- 派生：ValidatorId 由 `load_signer().public_key()` 经单一 `derive_validator_id` 得出（§8），供 SafetyStore identity 与 actor 构造使用。
- 失败：无法加载 signer / 身份与配置不符 ⇒ validator mode 启动失败（fail closed）。

## 7. SafetyStore Ownership

冻结：**SafetyStore 属于 NodeRuntime 生命周期；不是 ValidatorActor 自行创建。**

```
NodeRuntime
  ↓ SafetyStore::at/create(validator/<validator_id>.journal, SafetyIdentity)   (目录由 Runtime 提供)
  ↓ recover (strict; identity check)
  ↓ 构造 ValidatorActor::restore(vid, signer, chain_id, store)                  (inject)
```
- 每个 validator 独立 journal（多 validator 隔离已冻结）。
- recover / identity 失败 ⇒ validator 不启动（fail closed）。
- 与 canonical chain storage 的恢复语义保持分离（SafetyStore fail-closed vs PersistentBackend 丢尾继续 —— 两者永不混淆，§10）。

## 8. Validator Identity Flow

现状：`crypto identity::validator_id`（helper）与 `consensus ValidatorId::from_consensus_public_key` 为**两份**同式实现（均 SHA-256(pubkey)）。

单一来源设计：
```text
derive_validator_id(public_key_bytes: &[u8;32]) -> ValidatorId   // 唯一实现位置（crypto 域）
```
- Consensus `ValidatorId` 只引用/复用该实现（不重复 SHA-256 逻辑）。
- 流向：`Genesis+NodeConfig → ChainIdentity(network,chain,genesis_hash)`；`KeyProvider → public_key → derive_validator_id`；两者并入 `SafetyIdentity{network_id,chain_id,genesis_hash,validator_id}`（已冻结 store header 字段）→ SafetyStore 校验 → ValidatorActor 构造三重校验（signer 派生 id == configured == store header）。
- 满足：唯一性（抗碰撞）/ 持久性（同密钥稳定）/ 重启一致性（同 key 同 store 同 id）/ 防复制（id 非秘密；签名需私钥；身份检查 + 验签）。
- 非目标：不引入新格式；`ValidatorId ≠ NodeId ≠ AccountAddress` 隔离维持。

## 9. Key Rotation Rules（冻结）

```
Validator key change  ⇒  New public key  ⇒  New ValidatorId  ⇒  New SafetyStore
```
- **禁止旧 journal 复用**：旧 store 绑定的 validator_id 与新 derive 的 id 不同 ⇒ recover 必 `IdentityMismatch`（fail closed），天然禁止复用 —— 必须为该新 key 创建新 store。
- 理由：double-vote 历史（VoteLedger/signature/lock）绑定到旧身份；若用旧 ledger 为新 key 兜底，会**错误地把旧 key 的投票历史当成新 key 的**，破坏 RT-INV-1（同 key 单 target）与 RT-INV-4（身份绑定）语义。
- 运维语义：轮换 = 新的验证者身份起点；旧安全历史随之作废（新 store 从空开始）。
- 私钥本身轮换（同一 ValidatorId 下密钥滚动）不在本架构范围（无此协议概念；ValidatorId 由公钥派生 ⇒ 换公钥即换身份）。

## 10. Storage Separation（冻结）

```
node-data/
  ├── chain/        # canonical 状态（block/state/SMT/head）—— PersistentBackend，丢损坏尾部语义
  ├── validator/    # validator safety journal（每验证者一文件）—— ValidatorSafetyStore，fail-closed
  └── keys/         # （future）加密密钥材料（KeyProvider 载体；永不被 Safety/journal 引用）
```
- **禁止**在 chain storage（state/backend）内混入 safety journal；反之亦然。
- 原因：(a) 两者 failure semantics 不同（canonical 可丢尾恢复 vs safety 必须 fail-closed）；(b) 安全边界不同（safety 属 validator 私密历史；canonical 属共享共识状态）；(c) 权限/备份策略不同。
- `NodeConfig.storage_dir`（现有）→ 演进为 `node_data_root`，派生 chain/validator（validator 目录仅 validator mode 创建）。

## 11. Restart Recovery Boundary（冻结）

- **SafetyStore 负责**：vote intent / signature / lock（validator-local；fail-closed strict replay；identity 绑定）。
- **SafetyStore 不负责**：DAG / finality / canonical consensus round —— 这些属 canonical 域（block 侧由 bootstrap 恢复；consensus round 状态**不持久化**，未来独立设计「Canonical ConsensusState persistence」，不在本步）。
- Validator 重启语义：SafetyStore 恢复出 ledger+lock → 注入 actor → actor 以恢复状态继续（同 key 同 target 幂等 / 异 target 拒绝）；canonical round 由 event loop 从对等/本地重建（未来）。

## 12. Future Implementation Boundary

本架构为 STEP 10-16 IMPLEMENT 提供依据；实现范围（待 Owner 批准）建议：
- 新增/演进（node crate）：`NodeRuntime` 装配、`NodeConfig` 扩展（validator/key/safety/network 字段）、`KeyProvider` seam（含 SoftwareKey 首载）、`derive_validator_id` 收敛、目录布局。
- 保持不动：`VoteLedger` 冻结 API、L-8、Safety Journal 格式、`SigningCapability`、consensus/crypto 语义、block_adapter/bootstrap 既有行为。
- 明确 deferred：HSM/remote/KMS 具体实现、网络 transport/event loop/join、canonical ConsensusState persistence、主网 Genesis 值、validator key 导入 UI/流程。

---

> 状态：FROZEN（STEP 10-16B DESIGN FREEZE，2026-09-04）。实现需 Owner 单独授权 IMPLEMENT STEP 10-16。
