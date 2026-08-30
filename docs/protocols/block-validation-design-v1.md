# Nova Chain — Block Validation Design V1（P7-3）

- **Status**: **FROZEN**（P7-3 Block Validation 实现设计；Design Review 通过，2026-08-31）
- **Date**: 2026-08-31
- **Scope**: P7-3 Block Validation 实现设计——验证顺序（ADR-0042 §9）① 结构 → ② proposer signature →
  ③ transaction_root → ④ state_root → ⑤ height/parent；边界与 D1~D6 已裁决决策点。
- **协议基线**: ADR-0042 FROZEN + Signature Amendment FROZEN（Git 3a0b520 / d9eb7e8）

## 0. 目标

把 ADR-0042 §9 冻结的验证链落地为**分层、自包含、可组合**的验证函数，严格遵守：
`decode ≠ semantic`、`proposer signature ≠ authority/membership proof`、`A11 = DEFERRED`。

## 1. 验证顺序（ADR-0042 §9，冻结，不得改变）

```
① 结构（decode）
② proposer signature（header 承诺，DomainId::Block）
③ transaction_root（body 承诺）
④ state_root（执行后重算比对，verify_block_state_root 8D）
⑤ 链式（parent.height < height）
```

- 任一 FAIL ⇒ Reject（不 fallback、不猜测，ADR-0042 §10）。
- 顺序语义：签名先于承诺（先证明 proposer 认可 header，再校验 body/执行承诺），
  承诺先于链式（先验证本 block 自洽，再验证与父关系）。

## 2. 现有基础设施（FACT，已核实）

| 步骤 | 现有资产（可用） | 缺失 |
|---|---|---|
| ① 结构 | `decode_block`（nova-core `block.rs`，P7-2 已冻结：length/version/tag/trailing 拒绝） | — |
| ② 签名 | `DomainId::Block = 0x03`（crypto `domain.rs`）；`build_signed_bytes`/`hash_signing_message`/`Signature::from_bytes`/`verify_message_hash`（V-5 五步模式，`vote.rs` 参考）；`ValidatorSet::info` 查公钥（consensus `validator.rs`） | block proposer signature 验证函数（未实现） |
| ③ tx_root | `canonical_transaction_bytes`（crypto `transaction.rs`）；`encode_block_body`（core） | `transaction_root` 计算算法（ADR §16 = impl detail，需冻结）+ 验证函数 |
| ④ state_root | `execute_block`（execution `block.rs`）；`calculate_state_root`/`verify_block_state_root`（storage `state_root.rs`，8D 已冻结） | 组合（编排层） |
| ⑤ height/parent | `BlockHeader.parent_hash`/`height`（core） | parent context 接口（Block 无 parent 数据，需外部传入） |

依赖方向（冻结，不可破坏）：
`nova-node → network/consensus/crypto`（**无 execution/storage**）
`nova-consensus → core/crypto`（C-1：禁 consensus→execution/storage/network）
`nova-execution → core/crypto`；`nova-storage → core/crypto`

## 3. 分层设计（草案）

### 3.1 ① 结构（nova-core，已有）
- 复用 `decode_block`（P7-2）。`verify_block` 接受已 decode 的 `&Block` 或 wire bytes。
- 空 body 合法（`txs` 可空）；长度/version/tag/trailing 已在 decode 拒绝。

### 3.2 ② proposer signature（**已裁决 D2 / D3**）
```
signed_bytes  = alg(Ed25519=0x01) ‖ dom(Block=0x03) ‖ chain_id(8LE) ‖ len(4LE) ‖ canonical_header
message_hash  = SHA-256(signed_bytes)      （hash_signing_message）
verify        = verify_message_hash(proposer_vk, message_hash, Signature::from_bytes(sig))
```
- **归属：nova-core**（D3 裁决）——block signature 是 Block 协议验证的一部分；core 只做**纯密码学验证**，
  **不查询 ValidatorSet / 不依赖 consensus**。
- **proposer 身份由外部 context 提供**（D2 裁决，措辞收紧）：
  ```
  proposer identity / proposer public key
          ↓ 外部 context 提供
  Block signature verification
          ↓ 仅验证：
      signature == valid signature for the supplied proposer identity/key
          ↓ 不验证：
      membership · authority · eligibility · validator-set inclusion
  ```
- **coverage**：canonical_header（9 字段，ADR-0009 §3 / ADR-0042 §8）。
- **不签**：block_hash / body / signature 自身。
- **authority boundary（保持）**：verify 只证 `signature valid for supplied proposer identity`；
  不证 membership / authority / eligibility（A11 DEFERRED）。
- **Block 不新增 `proposer_id` 字段**（P7-2 freeze 保持）；proposer 身份由调用方提供
  （如 consensus `ProposalRef.proposer`），P7-3 **不引入 validator-set membership 层**。
- 若未来需证明“proposer ∈ current validator set”，那是**另一个验证层**（非 P7-3）。

### 3.3 ③ transaction_root（**已裁决 D4 = Merkle，完整规则冻结**）

**归属：nova-core**（与 D3 一致；block 域纯函数，依赖 `protocol_hash` + `canonical_transaction_bytes`）。

**域字节（与 state 域 0x00/0x01/0x02、crypto DomainId 0x01~0x06 均分离）**：
```
TX_EMPTY  = 0x20
TX_LEAF   = 0x21
TX_BRANCH = 0x22
```

**节点 hash（`protocol_hash` = SHA-256）**：
```
tx_leaf_hash(tx)    = protocol_hash( 0x21 ‖ canonical_transaction_bytes(tx) )
tx_branch_hash(L,R) = protocol_hash( 0x22 ‖ L ‖ R )
```

**规则（冻结，保证 canonical / deterministic，无 alternate）**：
```
空集合（0 txs）:
    transaction_root = protocol_hash(0x20)          （TX_EMPTY_ROOT 常数）

非空（n ≥ 1 txs）:
    第 0 层 = [ tx_leaf_hash(tx_i) for i in 0..n ]（block 内 tx 顺序）
    自底向上合并，直至当前层 len == 1：
        若 len == 1 ⇒ 该节点即 transaction_root（不再配对）
        否则：从左到右两两配对（i = 0,2,4,...）：
            i+1 存在         ⇒ tx_branch_hash(node[i], node[i+1])
            i+1 不存在（奇数）⇒ tx_branch_hash(node[i], node[i])（复制自身）
```
- 单元素 ⇒ root = tx_leaf_hash(tx0)（不冗余配对）。
- 同 tx 集合 + 同顺序 ⇒ 同 root；tx 顺序即 block body 顺序（确定性）。

**验证**：`verify_transaction_root(expected: &[u8;32], body: &BlockBody) -> Result<(), BlockValidationError>`
（重算 `compute_transaction_root(body)` 与 `header.transaction_root` 比对；不符 ⇒ `TransactionRootMismatch`）。

### 3.4 ④ state_root（复用 8D；**已裁决 D1 = C：独立函数 + 调用方编排**）
```
execute_block(state, txs, sender_keys, ctx, max_gas) → BlockExecutionResult{tx_transitions, gas_used_total}
tx_changes = tx_transitions 中每个 transition 的 changes
computed   = calculate_state_root(store, &tx_changes)
verify_block_state_root(&header.state_root, &computed)
```
- **编排由调用方完成**（D1 裁决）：不新增 crate 依赖；Consensus 不依赖 Execution/Storage；
  future Node runtime 负责组合 ①~⑤。
- P7-3 实现层：④ 的原子步骤**复用**既有 `execute_block` + `calculate_state_root` +
  `verify_block_state_root`（8D 已冻结），**不在 nova-core 重造**。

### 3.5 ⑤ height/parent 链式（**已裁决 D6 = ParentContext**）

**ParentContext（外部提供，Block 不自含；单父 V0.1，无多父）**：
```
pub struct ParentContext {
    pub parent_height: u64,
    pub parent_hash: [u8; 32],
}
```
**验证（同时满足，缺一不可）**：
```
block.header.height    == parent_height + 1        （height 链式）
AND block.header.parent_hash == parent_hash         （parent_hash 正确指向预期父块）
```
- **不只检查 height**：仅 `parent_height` 无法证明 `parent_hash` 指向正确；遗漏 hash 检查会允许
  “高度连续但父指向错误”的块（违反 ADR-0042 §9/§10 的 `parent` 语义）。
- 失败 ⇒ `InvalidHeightChain`（height 不连续）/ `ParentHashMismatch`（parent_hash 不符）（见 §3.6）。
- 不引入 DAG 多父；genesis 父 = 零哈希（`parent_hash == [0u8;32]`，parent_height 由 genesis 规则决定）。

### 3.6 错误模型（**已裁决 D5 = 新增 `BlockValidationError`；ADR impact review 结论：不修改 ADR-0042**）

**`BlockValidationError`（nova-core）**：
```
InvalidProposerSignature   // ② 签名验证失败（verify_strict / 畸形签名）
TransactionRootMismatch    // ③ 重算 tx_root ≠ header.transaction_root
InvalidHeightChain         // ⑤ block.header.height != parent_height + 1
ParentHashMismatch         // ⑤ block.header.parent_hash != parent_hash
```
- ④ state_root 复用 storage `BlockStateRootError::Mismatch`（8D 已冻结），不重复定义。
- **ADR impact review（D5 先决步骤）**：
  - ADR-0042 §10 rejection 语义：签名无效 / 承诺不符 / 链式非法 ⇒ 拒（**不受影响**）。
  - 新增错误仅把既有 rejection 分类编码，**不改变**哪些输入被拒 / 拒绝语义 / 验证顺序。
  - 结论：**纯错误分类（API/实现层），协议语义不变 ⇒ 不修改 ADR-0042**。
    作为 ADR-0042 §16“新增错误变体触发 ADR 评估”的评估结果，记录于本设计。

## 4. 边界（冻结，不得违反）

- decode ≠ semantic validation（`decode_block` 不验证；`verify_*` 才验证）。
- proposer signature ≠ authority / membership / eligibility proof。
- Block ≠ BlockReference ≠ QC；QC 不进 P7 pipeline。
- Consensus ≠ Execution（验证不把 consensus state 塞进 execution）。
- A11 = DEFERRED。
- DoS：`max_block_bytes`（genesis 8MB）为网络/验证层强制（ADR §11，P7-3 不实现网络强制）。

## 5. 决策点裁决（项目所有者已裁决，2026-08-31）

| # | 决策 | 裁决 | 影响 |
|---|---|---|---|
| **D1** | ④ 编排层归属 | **C：各步骤独立函数，编排由调用方完成** | 不破坏 crate 依赖方向；Consensus 不依赖 Execution/Storage；future runtime 可组合 |
| **D2** | ② proposer 公钥来源 | **外部提供 proposer identity + `VerifyingKey`；签名验证不做 membership 判断** | 保持 authority boundary；“签名有效”与“有资格提案”严格分离；Block 不增 proposer_id |
| **D3** | ② 归属 crate | **nova-core** | Block signature 是 Block 协议验证一部分；core 纯密码学验证，不查询 ValidatorSet |
| **D4** | ③ transaction_root 算法 | **B：Merkle over canonical transaction bytes**（完整规则已冻结，§3.3） | 交易集合 commitment；无 alternate；确定性 |
| **D5** | 错误模型 | **新增 `BlockValidationError`；ADR impact review 通过（纯错误分类，不改变协议语义）** | 不修改 ADR-0042（§3.6） |
| **D6** | ⑤ parent context | **`ParentContext { parent_height, parent_hash }`**：同时验证 height 链式 + parent_hash 指向 | 单父 V0.1；避免“只查 height 漏 parent_hash” |

## 6. 测试计划（已裁决后扩展）

- **② 签名**：ok / tamper header 字段（9 字段各篡改）⇒ fail / 错误 proposer 公钥 ⇒ fail /
  错误 chain_id ⇒ fail / 错误 domain（0x02 非 0x03）⇒ fail / 畸形签名长度。
- **③ tx_root**：
  - merkle 规则：空集合 root == TX_EMPTY_ROOT（常数）/ 单元素 root == leaf / 奇数节点复制自身 /
    偶数配对 / 同集合同序同 root / 顺序敏感（tx 顺序改变 ⇒ root 变）。
  - 验证：ok / body 篡改 ⇒ `TransactionRootMismatch`。
- **④ state_root**：ok / 执行结果与 header 不符 ⇒ mismatch（复用 8D）。
- **⑤ height/parent**：ok（height == parent_height+1 且 parent_hash 匹配）/ height 不连续 ⇒
  `InvalidHeightChain` / parent_hash 不匹配 ⇒ `ParentHashMismatch`（证明“只查 height 漏 hash”被拒）。
- **顺序**：② 失败 ⇒ ③④⑤ 不执行（顺序保证）。
- **回归**：P7-2 signature roundtrip / hash exclusion（signature 改 ⇒ block_hash 不变）/ decode 边界
  全保持 PASS。
- **安全**：hash exclusion 回归保持；merkle canonical 确定性（无 alternate）。

## 7. 禁令（冻结后仍适用）

- 不改 ADR-0042 / P7-2 冻结实现（Block / encoding / block_hash）——除非新 ADR。
- 不新增 `proposer_id` / `parent_height` / `parent_hash` 等字段到 Block / BlockHeader（违反 P7-2 freeze；
  parent 信息经 `ParentContext` 外部传入）。
- 签名验证**不得**查询 ValidatorSet / 做 membership / authority / eligibility（A11 DEFERRED）。
- 不改 Consensus / QC / Network 冻结。
- 不实现网络层 `max_block_bytes` 强制（ADR §11 归属网络/验证层）。
- **D4 merkle 规则 / D6 ParentContext 一经冻结，不得改变**（除非新 ADR / Protocol Review）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-3 Block Validation 实现设计 V1（DRAFT——验证顺序 / 分层设计 / 边界 / 开放决策点 D1~D6 / 测试计划 / 禁令） | 用户授权 P7-3 Block Validation 开始（FACT AUDIT 完成 → 实现设计，待 Review） |
| 2026-08-31 | **D1~D6 裁决落地**：D1=C（独立函数 + 调用方编排，§3.4）/ D2=外部 proposer identity + VerifyingKey（签名验证不做 membership，措辞收紧，§3.2）/ D3=nova-core（§3.2）/ D4=B Merkle（完整 leaf/branch/empty/odd 规则冻结，TX_EMPTY=0x20/TX_LEAF=0x21/TX_BRANCH=0x22，§3.3）/ D5=新增 BlockValidationError（ADR impact review：纯错误分类不改变协议语义 ⇒ 不改 ADR-0042，§3.6）/ D6=ParentContext{parent_height,parent_hash}（同时验证 height 链式 + parent_hash 指向，§3.5）；测试计划扩展（merkle 规则 / parent_hash mismatch） | 项目所有者裁决 D1~D6 |
| 2026-08-31 | **DESIGN FROZEN（P7-3 Block Validation）**：Design Independent Review **10/10 PASS / 0 findings**；冻结内容（不得改变除非新 ADR / Protocol Review）：验证顺序（①结构→②签名→③tx_root→④state_root→⑤height/parent）/ D1=C（独立函数+调用方编排）/ D2=外部 proposer identity + VerifyingKey（签名验证不做 membership）/ D3=nova-core / D4=Merkle 完整规则（TX_EMPTY=0x20/TX_LEAF=0x21/TX_BRANCH=0x22；leaf/branch/empty/odd 规则；无 alternate）/ D5=BlockValidationError（ADR impact review：不改 ADR-0042）/ D6=ParentContext{parent_height,parent_hash}（height 链式 + parent_hash 指向）。**不写代码；P7-3 Implementation NOT AUTHORIZED** | Design Independent Review 通过 → 项目所有者授权 Design FROZEN（独立 documentation commit） |
