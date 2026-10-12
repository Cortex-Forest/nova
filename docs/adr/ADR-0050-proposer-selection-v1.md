# ADR-0050: Proposer Selection Protocol V1

- **Status**: **FROZEN**（2026-09-03 Freeze Execution；STEP 10-13C —— Owner 授权。Proposer Selection Protocol V1 设计正式冻结；仅协议文档冻结，未实现任何设计；DomainId::Proposer 注册仍 deferred）
- **Date**: 2026-09-03
- **Deciders**: Nova Chain 架构组（Owner 决策）
- **Scope**: Proposer Selection 协议（Deterministic ValidatorSet-bound Weighted Selection V1）—— 确定
  每个 `(chain, height, round)` 的 proposer。纯协议设计，不实现。
- **前置**: ADR-0033（C-5/C-6）、ADR-0034（ValidatorSet/quorum/V-1~V-3）、ADR-0036（Witness，W-6）、
  ADR-0037（Round/Lock，B-3/B-5）、ADR-0038（QC/Finality）、ADR-0039（Checkpoint）、ADR-0041
  （ProposalRef Canonical Serialization，FROZEN）、**ADR-0049（Liveness/Pacemaker，FROZEN —— 本 ADR 之
  §3.6 exact algorithm DEFERRED 的正式载体）**、consensus-spec-v1.md（FROZEN）
- 说明：编号 0050 经全仓库核验（file/title/text reference 全空）确认空闲。ADR-0049 **保持 FROZEN 且不被
  本 ADR 修改**；本 ADR 只是把 ADR-0049 §3.6 标记为 DEFERRED 的精确算法设计成协议文档。

> **术语/治理对齐（PHASE 6G-A — ADR-0068；不改变本 ADR 的任何算法语义）**
>
> 本 ADR 正文出现的 `DomainId::Proposer = 0x07`（§13 / §20 等）**仅为历史提案措辞**：
> 该注册从未获得授权（本 ADR 头部自述注册为 deferred），且与 ADR-0005 注册表 / ADR-0043（FROZEN）
> 的 `0x07 = Contribution` 冲突。经 **ADR-0067** 修复后：
> - `0x07` 在 **DomainId（签名域）** 命名空间恢复为 `Contribution`；
> - proposer 选择的**哈希域前缀**改由**独立命名空间** **ADR-0068** 的 `HashDomain::Proposer = 0x07` 承载。
>
> **本 ADR 的算法内容完全不变**：`ProposerSeedInput`（57B 布局）、`ProposerSeed`、
> `x = LE_u128(H(seed)[0..16]) mod total_weight`、首累计权重选择规则、ValidatorId 排序、
> 权重计算 —— **均不发生任何变化**（前缀字节仍为 `0x07`，故字节级不变）。
> 本对齐**仅为术语/治理澄清**，**不**构成对 proposer selection 的重新设计。

---

## 1. Context

ADR-0049（FROZEN）冻结了 Proposer Selection 的**协议要求**：deterministic · ValidatorSet-bound ·
independently recomputable · height/round-bound · no local randomness · WitnessSeed ≠ ProposerSeed ·
weight-compatible；但 **exact algorithm = DEFERRED**。STEP 10-13（Design Review）比较了
Round-Robin / Weighted Deterministic / VRF / Finality-derived 四候选，结论：V1 采用
**Weighted Deterministic Selection**（VRF 延后）。本 ADR 将该设计正式化为协议草案。

Nova V0.1 架构事实（仓库实况）：`ValidatorId = SHA-256(consensus_public_key)`（derive Ord）；
`voting_weight = bonded_stake`；`quorum = ceil(total_weight × 2/3)`；静态 genesis ValidatorSet（无
rotation）；`chain_id` Genesis 配置；`network_id` future deployment 值（PENDING）。

## 2. Problem Statement

需要一个能同时满足 ADR-0049 全部约束、可在所有 honest validator 独立复算、stake 公平、防 grinding、
fork 一致、与锁/最终性/法定人数边界兼容的 proposer 选择协议。

## 3. Goals

- 确定性：同输入同 proposer。
- ValidatorSet-bound：proposer ∈ 当前有效 ValidatorSet。
- 独立复算：仅凭 chain context + height + round + ValidatorSet。
- stake 比例公平：长期 P(v_i) ≈ w_i / Σw。
- 防 grinding：proposer 不能控制 seed 输入。
- 低实现复杂度（V0.1 优先简单可验证，不引入 VRF）。

## 4. Non-Goals

```
· validator rotation / epoch / dynamic ValidatorSet（future ADR）
· VRF / randomness beacon / unpredictable proposer（future ADR）
· validator admission / staking Sybil resistance（ValidatorSet/economic protocol）
· 任何新经济权重模型（reputation/activity/creator/local/random weight）
· 修改 quorum / finality / lock / ProposalRef / WitnessSeed
· implementation（Rust / test vectors）
```

## 5. Protocol Requirements（源自 ADR-0049 FROZEN，不改写）

```
PS-1 Deterministic            —— 同 (chain, height, round, ValidatorSet) ⇒ 唯一 proposer
PS-2 ValidatorSet-bound       —— proposer ∈ 当前有效 ValidatorSet；禁 arbitrary/unregistered
PS-3 Independently recomputable —— 仅凭 chain context+height+round+ValidatorSet；无本地状态/随机/clock/arrival
PS-4 Height/Round-bound       —— seed 至少含 height+round（防同 height 所有 round 同 proposer，除非明确理由）
PS-5 No local randomness      —— 禁 rand()/thread_rng()/entropy/wall clock/arrival order
PS-6 No WitnessSeed reuse     —— ProposerSeed ≠ WitnessSeed；禁复制 witness selection procedure
```

## 6. Proposer Selection Algorithm（V1 核心）

```
Recommended V1: Deterministic ValidatorSet-bound Weighted Selection

seed = H(ProposerDomain ‖ chain_id ‖ height ‖ round ‖ validator_set_reference)
x    = LE_u128(H(seed)[0..16]) mod total_weight

validators 按 validator_id 升序（canonical）；cumulative weight 前缀和：
  v1: [0, w1)
  v2: [w1, w1+w2)
  ...
  vn: [Σw_{<n}, total_weight)
proposer = first validator whose cumulative_weight > x
```

- 边界（协议语义）：
  - `x = 0` ⇒ 落入第一位 validator 区间（含 0）。
  - `x = total_weight − 1` ⇒ 可选中最后一位 validator（区间右开，cumulative 严格 > x 成立）。
  - `total_weight == 0` ⇒ **proposer selection invalid / no proposer**（不偷偷指定默认 proposer）。

## 7. Seed Construction

```
ProposerSeed(chain_id, height, round, validator_set_id) =
    H( ProposerDomain ‖ chain_id ‖ height ‖ round ‖ validator_set_id )
```
- 输入绑定 `chain_id + height + round + validator_set_id`；其中 `validator_set_id` 为既有冻结概念
  （QuorumCertificate 字段；ADR-0038 F-11 = genesis_hash；见 §8/§13/§21）。V0.1 下
  `validator_set_reference = validator_set_id = genesis_hash`。
- **不含** branch-specific `previous_finality_reference`（防 branch-dependent proposer / finality circular
  dependency / grinding；§22）。
- H = 现有 protocol_hash 原语（SHA-256 域哈希）。**本 ADR 不新定义 hash primitive**。

## 8. Protocol Concepts ≠ Rust Types

以下为本 ADR 定义的**协议概念**，**不代表已存在 Rust 类型/实现**：
```
· ProposerDomain          —— 概念：proposer 选择的域分隔常量（候选 DomainId::Proposer = 0x07；见 §13）
· validator_set_reference —— 协议概念：映射到既有冻结 `validator_set_id`（QuorumCertificate 字段，
                              [u8;32]；ADR-0038 F-11：V0.1 = genesis_hash）。V0.1 不引入新 set 序列化；
                              future rotation ⇒ 独立 validator_set_hash（F-11 迁移路径）
· ProposerSeed            —— 概念：上述种子构造的输出
```
不得声称这些类型已被实现；对应实现/注册 = deferred（§35）。

## 9. Chain ID

```
chain_id = REQUIRED（seed 输入）
既有编码（继承，不发明）：chain_id: u64 → canonical 8B LE
  · Genesis canonical encoding（identity.rs：chain_id.to_le_bytes()）
  · signed_bytes 布局（domain.rs / ADR-0009：… ‖ chain_id(8B LE) ‖ …）
原因：chain domain separation · 防不同链相同 proposer schedule · 与 Genesis 配置的 chain identity 一致。
chain_id 不由 genesis hash 推导（保持既有设计，不重新定义）。
```

## 10. Network ID

```
network_id = NOT REQUIRED for V1 proposer selection
理由：chain_id 已承担协议链域隔离；network_id 部署值尚未最终确定；不把 deployment metadata 不必要地
引入核心 proposer schedule。未来若需 network-specific proposer schedule ⇒ 独立 ADR。
```

## 11. Height / Round Semantics

- `height` 与 `round` 均为 seed 的协议输入 ⇒ `(height, round)` 确定 proposer。
- 要求：
  ```
  same chain_id + same height + same round + same ValidatorSet ⇒ same proposer
  round + 1 ⇒ 确定性新 proposer（不依赖本地随机/wall clock/timeout duration/P2P arrival）
  ```

## 12. Witness Seed Separation

```
ADR-0036 WitnessSeed = H(previous_finality_reference ‖ height)   （W-3）
ADR-0050 ProposerSeed = H(ProposerDomain ‖ chain_id ‖ height ‖ round ‖ validator_set_id)
（V0.1：validator_set_id = genesis_hash）
二者 MUST NOT reuse same domain or selection procedure。
禁止 ProposerSeed = WitnessSeed；禁止复制 Witness deterministic_select 为 proposer selection。
```

## 13. Domain Separation

现有 DomainId（domain.rs）：Transaction=0x01 · ValidatorVote=0x02 · Block=0x03 · Governance=0x04 ·
Address=0x05 · Witness=0x06。
```
DomainId::Proposer = 0x07 —— proposed registry allocation
Status = PROPOSED / pending implementation registry update（crates/crypto/src/domain.rs 未实现，不改）
```
> 若 Owner 认为 DomainId 注册应单独 ADR 处理，亦明确此依赖（见 §35 Registry Deferred）。

## 14. ValidatorSet Definition

- V1 使用**当前有效 ValidatorSet**，协议语义 `ValidatorSet(height, round)`。
- V0.1 现状：`ValidatorSet = static genesis ValidatorSet`（`ValidatorSet::from_genesis`）。
- 未来 validator rotation / epoch ⇒ **Deferred to future ADR**（本 ADR 不设计 rotation）。

## 15. Validator Ordering（canonical）

```
ValidatorId ascending（ValidatorId = SHA-256(pubkey)，32B，derive Ord）
冻结协议级排序；ValidatorSet ordering MUST NOT depend on local container/insertion/genesis 文件排列/P2P arrival。
```

## 16. Weight

```
voting_weight = bonded_stake（与 quorum 同源，ADR-0034 V-2/V-3）
禁止：reputation / activity / creator score / local / random weight；不得重新设计经济模型。
```

## 17. Weight Mapping

```
total_weight = Σ voting_weight
x = LE_u128(H(ProposerSeed)[0..16]) mod total_weight
proposer = first validator（validator_id 升序）whose cumulative_weight > x
边界：x=0 ⇒ 第一位区间含 0；x=total_weight−1 ⇒ 最后一位可被选中；total_weight=0 ⇒ invalid / no proposer。
```

## 18. Weight Fairness

- 长期：P(v_i) ≈ w_i / Σw（与 voting weight 成比例）。
- **不作**精确比例保证：单个有限 (height,round) 样本不是严格 stake 比例；不得声称"每 N block 必然严格
  按 stake 比例分配"。

## 19. Hash Output / Integer Semantics

```
取 H(seed) 固定长度输出，建议 first 16 bytes → unsigned little-endian u128：
LE_u128(H(seed)[0..16])，再 mod total_weight。
```
- 需复核现有 hash primitive 真实输出长度（SHA-256 = 32B ⇒ [0..16] 取前 16B 有效）。若 primitive 细节
  未冻结 ⇒ 标记为 **Draft-level serialization detail**（不假装已实现）。

## 20. Canonical Serialization（Micro-Fix #2 落定）

`ProposerSeedInput` 唯一字段顺序（**不得 reorder / omit / duplicate / append optional / 插入
timestamp·proposer·ProposalRef·previous_finality_reference·WitnessSeed**）：
```
1. ProposerDomain              1 byte        （DomainId::Proposer = 0x07，proposed）
2. chain_id                    8 bytes LE    （继承既有 u64 编码：Genesis canonical + signed_bytes）
3. height                      8 bytes LE    （u64）
4. round                       8 bytes LE    （u64）
5. validator_set_id           32 bytes       （既有 genesis_hash digest 原始字节，ADR-0038 F-11）
```
- 总长度（定宽，无歧义）：`1 + 8 + 8 + 8 + 32 = 57 bytes`。
- 结构示例（仅布局说明，**不伪造 hash/digest**；正式 test vectors 属未来实现）：
  ```
  ProposerSeedInput =
      [ProposerDomain 0x07]
      ‖ [chain_id 8B LE]
      ‖ [height 8B LE]
      ‖ [round 8B LE]
      ‖ [validator_set_id 32B]
  ProposerSeed = H(ProposerSeedInput)   // H = 既有 protocol_hash（SHA-256，32B 输出）
  ```
- 编码要求：no ambiguity · fixed-width（定长）· 显式顺序 · no JSON · no whitespace-dependent ·
  no platform-dependent · no Rust Debug formatting · no map iteration order。
- `height`/`round`：u64 LE（禁 decimal string / JSON number / platform-endian / variable-width）。
- `validator_set_id`：32B 原始 digest 字节（复用既有 genesis_hash canonical representation；不重新定义 hash）。

## 21. Validator Set Reference（Micro-Fix #1 落定）

- **validator_set_reference = validator_set_id**（既有冻结概念，非新发明）：
  - `QuorumCertificate.validator_set_id: [u8;32]`（finality.rs L52）
  - 校验：`qc.validator_set_id == expected_genesis_hash`（finality.rs L233）
  - ADR-0038 **F-11（FROZEN）**：`validator_set_id = genesis_hash`（V0.1 唯一确定，无 OR）
- **V0.1 定义**：
  ```
  V0.1 uses a static Genesis ValidatorSet.
  validator_set_reference = validator_set_id = genesis_hash
  genesis_hash = 既有 compute_genesis_hash 输出（SHA-256 canonical genesis，32B）
  ```
- **validator_set_reference ≠**：ValidatorSet serialization/array · HashMap · insertion index ·
  validator count · total voting weight · proposer ID · previous_finality_reference · WitnessSeed。
- **未来兼容**：epoch / validator rotation 引入时，validator_set_id 迁移到独立 `validator_set_hash`
  （ADR-0038 F-11 迁移路径）；本 ADR 不设计 epoch/rotation/activation height/transition。
- 此项已由 Micro-Fix 落定（原 freeze prerequisite 闭合）→ PS-F6/F8 可判 PASS。

## 22. Fork Consistency

```
两竞争分支同 chain_id + height + round + ValidatorSet ⇒ 同一 proposer（必须成立）。
ProposerSeed V1 MUST NOT include branch-specific previous_finality_reference。
理由：防 branch-dependent proposer · 防 proposer schedule ↔ finality circular dependency · 减 grinding 面。
```

## 23. Grinding Analysis

- 攻击面（tx ordering / proposal body / nonce / optional fields / signature timing / P2P timing /
  timeout timing）均**不能**改变 seed 输入（chain_id/height/round/validator_set_id 全为协议决定、proposer 不可控）。
- V1 要求：`ProposerSeed` 不得依赖 proposer-controlled content ⇒ 无 grinding 通道。

## 24. Predictability

```
V1 proposer selection is predictable to parties that know the ValidatorSet and protocol inputs. 这不是 bug。
V1 选择：deterministic verifiability 优先于 cryptographic unpredictability。
· Predictability 主要产生 targeted DoS / liveness risk
· timeout → next round 提供 proposer rotation（round ∈ seed）
· 不影响 quorum · 不影响 safety
未来若需 unpredictable proposer ⇒ VRF / randomness beacon = Future ADR。
```

## 25. Sybil

- proposer probability 与 `bonded_stake` 绑定：单纯增加 validator identities 而不增加有效权重，**不**线性
  增加 proposer probability。
- V1 **不**声称自行解决 validator admission / staking Sybil resistance —— 属 ValidatorSet / economic
  protocol（deferred）。

## 26. Round Change

```
timeout → checked_successor → round+1 → 新 proposer 确定性计算
Timeout ≠ Vote ≠ QC ≠ Finality ≠ TimeoutCertificate
V1 不引入 TimeoutCertificate / RoundChangeCertificate / PacemakerCertificate（ADR-0049 §3.13 FROZEN）。
```

## 27. LockedState

```
Proposer Selection ≠ Lock Override Authority
Proposer change / Round change / Timer expiration MUST NOT unlock LockedState。
ADR-0037 为 lock semantics authority；本 ADR 不重定义 lock override。
```

## 28. Finality

```
Proposer Selection ≠ Finality Authority
Finality 仍只经 valid PrecommitQC → Finality（F-8）。
Proposer selection 仅选择谁可提议；不得自动产生 vote / QC / finality。
```

## 29. Quorum

```
quorum = ceil(total_weight × 2 / 3)（ADR-0034 V-3）
Proposer selection MUST NOT modify quorum；proposer weight 不得改变 voting quorum calculation。
```

## 30. Edge Cases

```
· Empty ValidatorSet（total_weight=0）→ invalid / no proposer（不指定默认）
· Single Validator → proposer = 该 validator
· Zero-weight validator（若协议允许）→ 不获 proposer probability；若 ValidatorSet 已禁 zero weight ⇒ 引用现有规则
· Extremely large weight → 避免 integer overflow / cumulative overflow / 不一致算术（Draft 不实现代码）
· Duplicate ValidatorId → 依赖 ValidatorSet validity：invalid set 不进入 proposer selection
```

## 31. Security Boundaries

```
Proposer Selection cannot:
  create vote · create QC · create finality · reduce quorum · unlock LockedState ·
  mutate DAG validity · bypass ValidatorSet validity
```

## 32. Implementation Boundary

本 ADR 为 **PROTOCOL DESIGN**，非 IMPLEMENTATION。后续实现（crates/consensus · crates/crypto ·
tests · test vectors）须另行 Owner 授权；本轮不修改。

## 33. Test Vector Requirement（未来实现必须）

```
same inputs → same proposer · different round → deterministic proposer · different height →
deterministic proposer · different ValidatorSet → deterministic proposer · weight proportional ·
x=0 boundary · x=total_weight−1 boundary · single validator · empty validator set · fork consistency ·
domain separation · WitnessSeed non-reuse
（本轮不创建 test vectors）
```

## 34. Compatibility

```
ADR-0034 = quorum weight compatibility（PASS）
ADR-0036 = Witness separation（PASS；WitnessSeed ≠ ProposerSeed）
ADR-0037 = Round / LockedState compatibility（PASS）
ADR-0038 = QC / Finality compatibility（PASS）
ADR-0039 = Checkpoint compatibility（PASS）
ADR-0041 = ProposalRef compatibility（PASS；proposer 仅 ValidatorId，不改 ProposalRef）
ADR-0049 = Liveness / Pacemaker compatibility（PASS；ADR-0049 保持 FROZEN，未被本 ADR 修改）
```

## 35. Deferred / Future Work

```
Implementation deferred : Rust implementation · helper functions · integer handling · test vectors
Registry deferred       : DomainId::Proposer = 0x07 实际注册（crates/crypto 更新；或独立 registry ADR）
Node deferred           : proposer scheduling · proposal broadcast · networking
Future protocol ADR     : validator rotation · epochs · dynamic ValidatorSet · VRF proposer ·
                          unpredictable proposer · randomness beacon
```

## 36. Freeze Criteria（未来 Freeze Gate）

```
PS-F1  Algorithm deterministic        PS-F2  ValidatorSet-bound
PS-F3  Height-bound                  PS-F4  Round-bound
PS-F5  Independently recomputable    PS-F6  Canonical serialization
PS-F7  Canonical Validator ordering  PS-F8  Weight mapping deterministic
PS-F9  Zero/edge cases defined       PS-F10 Domain separation
PS-F11 Witness separation            PS-F12 Fork consistency
PS-F13 Round-change compatibility    PS-F14 LockedState compatibility
PS-F15 Finality compatibility        PS-F16 Quorum preservation
PS-F17 Grinding resistance           PS-F18 Sybil/weight behavior
PS-F19 Chain-id separation           PS-F20 No local randomness
每项可判：PASS / OPEN / BLOCKED / DEFERRED
```

## 37. References

```
ADR-0033（Consensus Architecture）· ADR-0034（ValidatorSet/Vote）· ADR-0036（Random Witness）·
ADR-0037（BFT Round/Lock）· ADR-0038（Finality/QC）· ADR-0039（Checkpoint）· ADR-0041（ProposalRef
Canonical Serialization）· ADR-0049（Liveness/Pacemaker，FROZEN）· consensus-spec-v1.md（FROZEN）
```

## Change Log

### 2026-09-03
- Initial Proposer Selection Protocol V1 draft.
- Recommended deterministic ValidatorSet-bound weighted selection.
- No implementation performed.
- No consensus-spec modification.
- ADR-0049 remains FROZEN and unmodified.

### 2026-09-03（Micro-Fix，STEP 10-13B-FIX）
- Micro-Fix #1：validator_set_reference 绑定既有冻结 validator_set_id（QuorumCertificate 字段；ADR-0038
  F-11 = genesis_hash；V0.1 = genesis_hash）；不再为未绑定概念。
- Micro-Fix #2：ProposerSeedInput canonical 字节布局冻结（1+8+8+8+32 = 57B 定宽；字段顺序冻结；
  chain_id/height/round = LE u64；validator_set_id = 32B digest）。
- 算法 / 安全 / 兼容性未改变；Status 保持 PROPOSED；未实现任何代码。

### 2026-09-03（Freeze，STEP 10-13C）
- Freeze: ADR-0050 Proposer Selection V1 design frozen after STEP 10-13B-R2 review（PS-F1~F20 all PASS）。
- 协议内容 / 算法 / seed / ValidatorSet / chain_id / domain 语义未变；仅 Status PROPOSED→FROZEN；未实现。
