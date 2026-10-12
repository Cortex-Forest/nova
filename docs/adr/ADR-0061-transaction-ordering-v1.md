# ADR-0061: Transaction Ordering for Block Production v1

- **Status**: FROZEN
- **Freeze Date**: 2026-09-06（STEP 10-19-4：完整审查通过后冻结；正文自即日起为 consensus-critical 规范）
- **Date**: 2026-09-06
- **STEP**: 10-19-4（Transaction Ordering ADR 冻结；BlockBuilder 前置）
- **Scope**: PHASE 3 — Block Production / `BlockBody.transactions` canonical ordering（构建期确定性全序）
- 关联：ADR-0021（Nonce & Replay，**FROZEN**）、ADR-0019（Transaction Schema，**FROZEN**）、
  ADR-0042（Block Format，**FROZEN**）、ADR-0023（State Transition，**FROZEN**；G-J changes 序）、
  ADR-0030（State Root，**FROZEN**；C-4 不排序/不合并）、ADR-0015（Genesis Canonical，**FROZEN**；
  `address_payload_bytes` 35B canonical）

## Context

冻结事实（当前代码/ADR）：

- **BlockV1 已冻结**（core/src/block.rs，ADR-0042）：`BlockBody { txs: Vec<TransactionV1> }`；
  `header.transaction_root` 承诺该列表；`block_hash = SHA-256(canonical_header ‖ canonical_body)`。
- **`transaction_root` 已冻结**（ADR-0042 §11）：`compute_transaction_root` 严格按 `body.txs`
  顺序构造 Merkle（TX_EMPTY=0x20 / TX_LEAF=0x21 / TX_BRANCH=0x22；leaf = canonical tx bytes）。
- **`execute_block` 按输入 vector 顺序执行**（execution/src/block.rs，STEP 8D）：逐 tx
  `apply_transaction`；成功 ⇒ changes 应用 overlay + gas 累加；失败 ⇒ **skip**（Model A；
  无 change / 无 receipt / 区块继续）。执行期 nonce 校验依赖 overlay 当前账户 nonce。
- **Nonce 语义已冻结**（core/transaction/nonce.rs + ADR-0021）：`classify_nonce(tx_nonce,
  account_nonce)`：`<` ⇒ TooLow（consensus Invalid）；`==` ⇒ Current（执行前提）；`>` ⇒ Future(gap)
  （仅供本地 Mempool Policy 判断；执行层拒绝 ⇒ skip）。`apply_transaction` 仅 `Current` 可执行。
- **Block validity 已冻结**（ADR-0021 §7 + `validate_block`）：同一 block 内同 sender 的 nonce
  **必须严格递增且唯一**；含 `(sender, nonce)` 重复 ⇒ **Block Invalid**（`NonceConflict`）。
  但**未冻结**：从候选交易集合派生出 `BlockBody.transactions` 全序的 **canonical ordering 算法**
  （尤其跨 sender 顺序）——该规则属 BlockBuilder 前置，本 ADR 冻结。
- **Mempool 未实现**（DEFERRED；ADR-0021 §8 明确 Mempool Policy 为本地非 consensus，采集/排序/
  广播留 Mempool STEP）。因此 consensus ordering 不得依赖 Mempool 输入顺序。
- **BlockBuilder 尚未实现**（GAP-BLOCK-1，P0）；ProposerService 现用 placeholder commitment
  （仅装配/测试）。

**缺口**：`BlockBody.transactions` 的 canonical ordering 规则（跨 sender 全序 + 构建期算法）未冻结。
transaction ordering 是 **consensus-critical**：

- ordering 改变 ⇒ `transaction_root` 改变 ⇒ `block_hash` 改变（同一 tx 集合、不同顺序 ⇒ 不同 Block）。
- ordering 改变 execution 结果（成功交易集合 / 账户余额 / 跨账户 transfer 可见性 / burned_supply）⇒
  `state_root` 改变 ⇒ `block_hash` 改变。

故须在 BlockBuilder 实现前，将 ordering 冻结为**确定性纯函数规则**。

## Decision

### §1. 唯一正式规则（FROZEN）

> **`BlockBody.transactions` 的 canonical ordering = 按 `(sender, nonce)` 全序升序排列**
> （primary key = sender canonical payload bytes，secondary key = nonce）：

```
key(tx) = ( address_payload_bytes(tx.sender)  // [u8; 35]，ADR-0015 §2 canonical（与 genesis 排序同 key）
          , tx.nonce )                        // u64，升序
ordered = sort(candidate_transactions, key asc)
```

- 这是**唯一**正式 ordering 规则。不得保留多个同时生效规则。
- 排序是**纯函数**（候选集合 → 有序列表），不依赖任何外部状态/时序。

### §2. Canonical Algorithm

```
input:
    candidate_transactions     // 无序集合；语义上 (sender,nonce) 必须唯一（见 §7）

uniqueness（block validity，已冻结 ADR-0021 §7，validate_block）:
    ∀ tx 两两：(sender, nonce) 唯一；违反 ⇒ 该候选集不可构造合法 Block（Block Invalid，
    不得产出）。排序算法假定输入已满足唯一性（合法集内 key 天然无 tie-break）。

order:
    key(tx) = (address_payload_bytes(tx.sender), tx.nonce)      // 35B ‖ u64；无本地字节序歧义（两者均 canonical LE/固定宽）
    ordered_transactions = candidate_transactions 按 key 升序稳定全序

output:
    ordered_transactions   // 即 BlockBody.txs（BlockBuilder 依此顺序组装）
```

- 无 tie-break key：同 `(sender, nonce)` 重复在合法候选集内不存在（ADR-0021 §7 ⇒ Block Invalid），
  故无需 txid / 其它决胜。
- **validate 与 sort 的先后**：唯一性为 block validity（先决，不产出重复 block）；排序为纯函数。
  两者组合恒等于「对唯一候选集按 key 排序」——先后不改变结果。执行失败（sig/balance/nonce
  等）在 execute_block 内逐 tx 判定（skip），不参与排序。

### §3. Same-Sender Rule（FROZEN）

- 同 sender 多交易：`nonce` **严格递增升序**（5 → 6 → 7）。
- 依据：ADR-0021 §7（block 内同 sender nonce 严格递增唯一）+ `execute_block` 顺序执行 + overlay
  （前一成功 tx 使账户 nonce+1，下一 Current 可执行）。
- 若候选含连续 nonce 前缀，则（余额/其它校验通过时）自账户当前 nonce 起的连续项全部成功。
- **强制**：排序算法保证同 sender 按 nonce 升序；Block 内同 sender 出现顺序 = nonce 升序。
  这是构建期强制（本 ADR），与 ADR-0021 §7 的 block validity 互补。

### §4. Cross-Sender Rule（FROZEN）

- 不同 sender 的全局顺序 = `address_payload_bytes(sender)` 35B **字典序升序**
  （字节序：`version(1) ‖ address_type(1) ‖ network_id(1) ‖ key_hash(32)`，ADR-0015 §2）。
- 该 key 与 `TransactionV1` canonical encoding 中 `sender` 字段使用同一函数
  （`address_payload_bytes`）⇒ **排序 key 与承诺字节一致**（ORDER-3）。
- 该排序 key 与 Genesis 的 validator/account canonical 排序同源（identity.rs
  `sort_by_key(|a| address_payload_bytes(&a.address))`）——既有 canonical 排序先例。
- **跨 sender 顺序同样 consensus-critical**：跨账户 transfer（A→B）会改变 B 的 balance，进而
  影响 B 作为 sender 的后续交易成败。故必须冻结全局全序，而非仅 sender 分组。

### §5. Invalid Transactions（FROZEN）

- **集合级非法**：`(sender, nonce)` 重复 ⇒ 不允许进入 Block（Block Invalid，ADR-0021 §7）。
- **单 tx 执行失败**（signature / replay / nonce(TooLow/Future) / balance / gas / overflow）⇒
  **允许进入 Block**，execute_block 逐 tx skip（Model A：无 change / 无 receipt / 无 state 影响；
  区块继续）。此为既有冻结执行语义（STEP 7G/8D），本 ADR 不新增过滤。
- 排序**不**按「是否将成功」预判（不可预知且无必要）：候选按 key 全序排列，成败由执行期判定。
- 候选来源（哪些 tx 进入候选集）由未来 Mempool/BlockBuilder 决定（DEFERRED），本 ADR 只冻结
  集合→顺序的映射。

### §6. Nonce Gaps（FROZEN）

- 若同 sender 候选含 gap（如 `nonce=5, nonce=7`，而 6 不在候选且不在链上）：
  - 排序仍按 nonce 升序（5 先于 7）。
  - 执行期：5 成功 ⇒ overlay nonce=6；7 相对 6 为 Future ⇒ **skip**（无 state 影响，
    **不导致 Block Invalid**）。此为 execute_block Model A 既有冻结语义。
- **consensus 不强制** Builder 拒绝 gap / 截断到连续前缀；「自链上 current nonce 起取连续前缀」
  为 Mempool/BlockBuilder 的本地策略（DEFERRED，防浪费的非共识优化）。
- 冻结：ordering 算法**不填补、不剔除** gap —— 仅把给定候选按 key 升序排列。

### §7. Empty Block（DEFERRED 记录）

- 何时产出空块（无 tx）属 BlockBuilder 决策，本 ADR 不冻结（**DEFERRED**）。
- 空 body 的 `transaction_root = TX_EMPTY_ROOT = protocol_hash(0x20)` 已冻结（ADR-0042 §11）；
  与 ordering 无耦合。

### §8. Merkle Relation（FROZEN）

```
transaction_root = Merkle(ordered_transactions)          // compute_transaction_root，ADR-0042 §11
```

- `compute_transaction_root` 第 0 层 = `leaf(tx_i)`，**依 `body.txs` 顺序**；两两配对，奇数复制。
- **ordering 改变 ⇒ `transaction_root` 改变**（同一 tx 集合、不同顺序 ⇒ 不同 root）。

### §9. State Root Relation（FROZEN）

```
state_root = post-execution root of ordered_transactions  // execute_block 依序执行 → changes → storage（ADR-0030）
```

- `execute_block` 严格按 block 内顺序执行；成功集 / 余额 / burn 依赖该顺序。
- **ordering 改变 ⇒（可能）不同成功集 ⇒ 不同 `state_root`**（ADR-0030 C-4：state root 计算
  不重排 changes——changes 依执行序应用，与顺序冻结一致）。

### §10. Block Hash Relation（FROZEN）

```
ordered_transactions → transaction_root → BlockHeader.transaction_root
ordered_transactions → BlockBody.txs → canonical_block_body
BlockHeader + BlockBody → canonical Block → block_hash = SHA-256(canonical_header ‖ canonical_body)
```

- `block_hash`（ADR-0042 §6）覆盖 header + body；body 编码按 `body.txs` 顺序。
- **ordering 改变 ⇒ body 改变 且 transaction_root 改变 ⇒ `block_hash` 改变**。
- 链路：`same tx set + different order ⇒ different transaction_root ⇒ different block_hash`。

### §11. Determinism（FROZEN）

- **ORDER-1**：same valid transaction set + same protocol state + same protocol parameters
  ⇒ same canonical transaction order。（排序为集合的纯函数。）
- **ORDER-2**：排序**不依赖**：HashMap iteration / filesystem / arrival time / local clock /
  network latency / peer order / random / thread scheduling / machine-specific behavior。
- **ORDER-3**：排序 key（`address_payload_bytes(sender)`）与 tx canonical encoding 中 sender
  字段字节一致（同一函数）⇒ key 稳定性与承诺一致。
- **ORDER-4**：合法候选集内 `key` 唯一（同 `(sender,nonce)` 重复 ⇒ Block Invalid）⇒ 无 tie-break
  歧义；无需 txid / 时间戳决胜。
- **ORDER-5**：空集 ⇒ 空 body（`transaction_root = TX_EMPTY_ROOT`）；单元素 ⇒ 其自身为序。
  （集合基数不改变算法输出。）

### §12. ConsensusState 边界（FROZEN）

`ConsensusState = { round, finality }` 结构**不变**。**不增加**：
`transaction_order` / `mempool` / `pending_transactions` / `block_builder_state` 等字段。
Ordering 是 BlockBuilder 构建期纯函数输入-输出映射，**不进入 ConsensusState**。

### §13. ADR-0042 / 冻结 ADR 兼容性（FROZEN）

本 ADR **不修改**：

- `BlockHeader`（9 承诺字段，含 `transaction_root` 语义）；
- `compute_transaction_root` / TX_EMPTY/LEAF/BRANCH 算法；
- `block_hash` 定义与覆盖范围；
- proposer signature（DomainId::Block）与 canonical Block encoding；
- `canonical_transaction_bytes` / txid / Transaction signature；
- nonce 语义（classify_nonce / ADR-0021）；
- Execution 规则（apply_transaction / execute_block / validate_block / Model A skip / burn）。

本 ADR **仅定义**：`BlockBody.transactions` 的 canonical ordering（候选集合 → 有序列表）。

与既有 ADR 的互补关系：

- ADR-0021 §7：block validity —— 同 sender nonce 严格递增**唯一**（consensus，Block Invalid）。
- ADR-0061（本 ADR）：构建期全序 —— 从候选集合派生**跨 sender canonical 全序**。
- ADR-0023 G-J：单 tx `AccountChange` 顺序（sender → receiver → burn）——执行层，与本 ADR 正交。
- ADR-0030 C-4：state root 计算不排序/不合并 changes（依执行序）——与本 ADR 一致。
- ADR-0021 §8：Mempool Policy 为本地非 consensus；本 ADR 不依赖其排序。

### §14. Non-Goals（FROZEN）

本 ADR **不定义 / 不实现**：

- Mempool（采集 / 去重 / 广播 / 本地排序 / Policy 阈值）；
- BlockBuilder implementation（WHEN/WHO/候选来源/空块策略 —— 后续 STEP）；
- Block Sync / Gossip / Discovery；
- Network scheduling / 到达序作为任何共识输入；
- Fee market / Validator rewards / Economics（fee-burn 之外的经济去向仍 DEFERRED）；
- Finality / QC / Fork Choice / DAG candidate ordering（那些是多区块层排序，与本 ADR 的单块内
  交易排序正交）；
- 不添加 async runtime、不新增经济参数、不改 Genesis / ConsensusState / NetworkEnvelope /
  ValidatorSafety / StateStore / Storage。

## Alternatives（已评估）

| 方案 | 结论 |
|------|------|
| **OPTION D — Sender+Nonce canonical（本推荐）**：`(address_payload_bytes(sender) 35B asc, nonce asc)` | 与账户 nonce 链语义天然一致；同 sender 5→6→7 全成功；跨 sender 由 canonical 地址字节定全序（与 genesis 排序同 key）；ORDER-1 成立；ADR-0021 §7 重复 ⇒ Block Invalid ⇒ 无需决胜 key；与 execute_block skip 语义完全兼容 |
| OPTION A — Sender+Nonce（朴素） | 方向正确但未冻结 key 定义与重复语义；本 ADR 以 D 形式严谨化（key = ADR-0015 §2 canonical bytes；重复 = Block Invalid）——D 即 A 的冻结形式 |
| OPTION B — TxID 字典序 | ORDER-1 成立且简单；但 txid（SHA-256(canonical payload ‖ sig)）与 nonce 无单调关系 ⇒ 同 sender 高 nonce 可先于低 nonce ⇒ 有效交易被系统性 skip（虽确定性但不自然、浪费）；与 ADR-0021 §7「同 sender nonce 严格递增」精神冲突（仅唯一仍 valid，但顺序非升序）→ **不选** |
| OPTION C — Explicit Input Order（保留 Builder 输入序） | 依赖外部输入顺序 ⇒ 无 Mempool 时退化为 arrival/本地序 ⇒ **ORDER-1 不成立**；Mempool 是本地非 consensus（ADR-0021 §8），不能作为 consensus ordering 依赖 → 不可作为唯一 consensus 规则。可作为未来 Mempool→候选集的采集序，但 block 内顺序一律由本 ADR 纯函数派生 |

## Consequences

- **正面**：BlockBuilder 可得确定性、可复算、可审计的单块交易全序；`transaction_root` /
  `state_root` / `block_hash` 对「同集合不同顺序」完全敏感；无 Mempool 亦可构造 canonical block。
- **成本**：跨 sender 顺序由地址字节决定（人为但 canonical）；同 sender 候选若含 gap，high-nonce
  项将被执行期 skip（Model A，无 state 影响；Mempool 本地优化可避免，DEFERRED）。
- **不改变**：BlockV1 / transaction_root / block_hash / signature / canonical encoding / Execution /
  nonce 语义 / ConsensusState / burn / gas / storage / 网络层。

## Security Impact

- 防顺序操纵歧义：ordering 为集合纯函数，proposer 无法在不改变集合的情况下选择任意顺序。
- 防 nonce 重排：同 sender 强制 nonce 升序（5→6→7），杜绝 high-nonce 先于 low-nonce 导致的
  状态不确定性（skip 语义下仍 deterministic，但全序保证最优成功集）。
- 防双花 / 重放：nonce 唯一 + 升序 + replay 检查（ADR-0021）组合不变。
- 防 tie-break 注入：同 `(sender,nonce)` 重复 ⇒ Block Invalid（非决胜），无 txid 排序侧信道。
- 确定性跨实现：key 用 canonical 35B 地址字节 + u64 LE，无浮点 / 无本地序 / 无时间 / 无随机。
