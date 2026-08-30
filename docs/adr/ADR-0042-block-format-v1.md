# ADR-0042: Block Format V1

- **Status**: **FROZEN（ACCEPTED）**（P7-1；Block Format V1 FINAL FREEZE，2026-08-31）
- **Date**: 2026-08-31
- **Deciders**: Nova Chain 架构组
- **Scope**: P7-1 — 完整 Block 格式（Header / Body / block_hash / canonical / signature / validation）
- 关联：ADR-0009（Block 签名字段清单）、ADR-0016（genesis accounting）、ADR-0029（block state root）、
  ADR-0030（state root calculator）、ADR-0031（persistence）、ADR-0035（DAG BlockReference）、
  `crypto-serialization-v1.md`（canonical 规则）、`DomainId::Block = 0x03`（crypto domain.rs，已注册）

## 1. Problem

- Nova 无完整 Block 格式（仅 `BlockReference` / `BlockPayload(Vec<u8>)` 占位）。
- Consensus 只消费 `BlockReference`（10-3）；完整 Block 内容/承诺/签名未冻结（PHASE 7 DEFERRED）。
- 需要冻结 Block 协议，使 Block 可生产、验证、传播、执行、提交、持久化且与 Consensus 桥接。

## 2. Context

- **已冻结可复用**：`execute_block`（8D）/ `apply_block`（8C-3）/ `calculate_state_root` / `verify_block_state_root`
  （8D）/ StateStore（8C）/ PersistentBackend（8E）/ DAG `BlockReference`（10-3）/ `FinalityState.finalized_reference`。
- **已注册**：`DomainId::Block = 0x03`；`protocol_hash`(SHA-256)。
- **父关系决策**（Open Decision 裁决）：**V0.1 Block = 单父**（`parent_hash` 线性链）；
  DAG 多父由 consensus 引用层（`BlockReference.parents: Vec`）表达，Block 层不引入多父。
  （理由：V0.1 最小；避免 Block 链式与 DAG 因果两层歧义；多父块可由 consensus 引用多个单父 Block 组合。）

## 3. Decision（冻结范围）

- 本 ADR 冻结 Block 协议（Header / Body / block_hash / canonical / signature / validation / rejection）。
- **本 ADR 一旦 FROZEN**：未经新 ADR / Protocol Review，不得改变：
  - Block field · field order · encoding · hash coverage · signature coverage · validation semantics。

## 4. BlockHeader（冻结）

```rust
pub struct BlockHeader {
    pub version: u8,                    // 0x01（V0.1）；未知 version ⇒ 拒
    pub chain_id: u64,                  // LE；genesis 固定值
    pub height: u64,                    // LE；parent.height < height
    pub parent_hash: [u8; 32],          // 单父 block_hash（genesis 父 = 零哈希）
    pub finality_reference: Option<[u8; 32]>, // 前序 finalized block_hash（指向过去，无循环）
    pub transaction_root: [u8; 32],     // 交易集合承诺（P7-2 冻结算法）
    pub state_root: [u8; 32],           // 执行结果承诺（SMT，8D）
    pub validator_set_hash: [u8; 32],   // 当前 validator set 承诺（P7-2 冻结算法）
    pub timestamp: u64,                 // LE；提议时间（consensus 不依赖时序，确定性）
}
```

## 5. BlockBody（冻结）

```rust
pub struct BlockBody { pub txs: Vec<TransactionV1> }
```
- V0.1 无收据 root（receipts 执行派生，留 future）。

## 6. BlockHash（冻结）

```
block_hash = SHA-256( canonical_block_header(header) ‖ canonical_block_body(body) )
```
- 覆盖 = canonical_header + canonical_body（**不含 signature / 不含 block_hash 自身**）。
- **BlockHash ≠ Signature Coverage**（signature 覆盖 header 承诺字段，见 §8）；两者独立、无循环依赖：
  - block_hash 不依赖 signature（header 不含 signature）；
  - signature 不依赖 block_hash（覆盖 header 字段，不含 block_hash）；
  - state_root 由执行产生（不依赖 block_hash）；执行输入 = txs + 父状态 ⇒ 无循环；
  - finality_reference 指向过去 ⇒ 无循环。

## 7. Canonical Encoding（冻结）

- **Header**（定长，crypto-serialization §3/§6 字段顺序）：
  ```
  version(1) ‖ chain_id(8LE) ‖ height(8LE) ‖ parent_hash(32) ‖ finality_ref(1 tag + 32)
  ‖ transaction_root(32) ‖ state_root(32) ‖ validator_set_hash(32) ‖ timestamp(8LE)
  ```
  - finality_ref tag：`0x00` = None / `0x01` = Some + 32B（§4 Option）。
- **Body**：`count(4LE) ‖ [ len(4LE) ‖ canonical_tx ]*`（§2 长度前缀）。
- **Block** = canonical_header ‖ canonical_body。
- **唯一表示**：定长 header + 严格长度 ⇒ roundtrip `decode(encode(b))==b`（§8）；无 alternate（§7）。

## 8. Signature Coverage（冻结）

- **proposer signature** = Ed25519（`verify_strict`），覆盖 **header 承诺字段**（ADR-0009 §3 顺序）：
  ```
  version ‖ chain_id ‖ height ‖ parent_hash ‖ finality_reference
  ‖ transaction_root ‖ state_root ‖ validator_set_hash ‖ timestamp
  ```
- **不签**：block_hash 自身、block body 交易列表（由 transaction_root 承诺）、signature 自身。
- **域分离**：`DomainId::Block = 0x03`（已注册）；`signed_bytes = alg(1) ‖ dom(0x03) ‖ chain_id(8LE) ‖ len(4LE) ‖ canonical_header`；`message_hash = SHA-256(signed_bytes)`。
- proposer 身份绑定：签名用 proposer 共识公钥（从 validator set 按 `ValidatorId` 查）；`ValidatorId = SHA-256(pubkey)`（与 vote V-5 模式一致）。
- **A11 边界**：本 ADR 只冻结 serialization/signature；**不新增 proposer authority 语义**（A11 保持 DEFERRED）。

## 9. Validation Rules（冻结）

- ① 结构（decode）→ ② 签名（header 承诺，DomainId::Block）→ ③ `transaction_root`（body 承诺）
  → ④ `state_root`（执行后重算比对，`verify_block_state_root` 8D）→ ⑤ 链式（`parent.height < height`）。

## 10. Rejection Rules（冻结）

- 长度不符 / 未知 version / 未知字段 / trailing bytes / 非 canonical 表示 / 签名无效 / 承诺不符 ⇒ 拒（不猜测、不 fallback）。
- 单父链：`parent.height >= height` ⇒ 拒。

## 11. Security Boundary

- 承诺完整性：tx_root / state_root / block_hash 三层承诺防篡改。
- 签名防伪造：`verify_strict` + `DomainId::Block` 域分离 + 身份绑定。
- DoS：`max_block_bytes`（genesis 8MB）上限（网络/验证层强制）。
- 无循环依赖（已证 §6）。

## 12. Determinism

- `block_hash` = 确定性函数（canonical 唯一）。
- `timestamp` 为 metadata，**不进入 consensus transition 输入**（MF-12）。
- 验证/执行/提交全确定性。

## 13. Compatibility

- 新类型/API 新增（`Block` / `BlockHeader` / `BlockBody` / `encode` / `decode` / `block_hash` / `verify_block`）——**不修改**任何已冻结类型。
- 复用 `DomainId::Block`（已注册）、`execute_block` / `apply_block` / state root（8D）等。
- 依赖方向：Block 类型归 `nova-core`；验证归 execution/Node；存储归 storage。

## 14. Alternatives Rejected

| 方案 | 否决原因 |
|---|---|
| 多父 Block（Block 内 parents 数组） | V0.1 引入 Block 链式与 DAG 因果两层歧义；多父由 consensus 引用层表达更清晰 |
| BlockHash 覆盖含 signature | 引入签名↔哈希循环依赖（签名需 block_hash 而 block_hash 需签名） |
| 无 chain_id / 无 DomainId 域分离 | 跨链重放 / 域混淆风险 |
| Body 直接嵌交易无 tx_root | 无交易集合承诺，无法高效验证/同步 |

## 15. Future Extension Rules

- 收据 root / 多父 / 动态 validator_set_hash / 新 version 字段：须**新 ADR / Protocol Review**（不改本 ADR 冻结语义）。
- 新 version = 协议升级（不得向后兼容悄悄新增字段）。

## 16. Implementation Detail（不属于协议冻结）

- 具体 merkle 树实现（tx_root / validator_set_hash 算法——P7-2 冻结，但内部节点结构为 impl detail 可调）。
- `max_block_bytes` 的强制位置（网络/验证层）为实现选择。
- decode 错误变体命名（BlockError 扩展）为 impl detail，但**新增错误变体触发 ADR 评估**。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：ADR-0042 Block Format V1（单父 V0.1；Header/Body/block_hash/canonical/signature/validation/rejection + 冻结约束） | 用户授权创建 P7-1 Block Format ADR（仅写 ADR，不实现） |
| 2026-08-31 | **FROZEN（ACCEPTED）**：P7-1 ADR Independent Review 10 项全 PASS（BlockHeader 顺序 / 单父 / BlockHash / Canonical / Signature / Validation Order / Commitment / Authority / Layer / Freeze Readiness）；Protocol Defect NO / Security Defect NO / 0 findings。冻结约束生效：未经新 ADR / Protocol Review 不得改变 field/order/encoding/hash coverage/signature coverage/validation semantics | 用户授权 P7-1 ADR Independent Review → PASS → ADR-0042 FROZEN（独立 documentation commit） |
