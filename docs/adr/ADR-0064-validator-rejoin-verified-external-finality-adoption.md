# ADR-0064 — Validator Rejoin / Late-Join Catch-up via Verified External Finality Adoption

## Status

**Proposed**

> This ADR does not modify the frozen consensus implementation or consensus specification.
>
> External finality is adopted only after independent verification and canonical-chain
> connectivity checks, and it is committed exclusively through the existing durable
> canonical commit path.

## Context

P1-A.1–P1-A.6 已把生产节点路径推进到「可安全运行、且具备 liveness」的状态：

- 正常 validator flow（本地提案 → 本地 Prevote/Precommit → 冻结 transition ⑥）可产生 finality；
- P0 双节点真实 TCP 到 height 2 已验证；
- P1-A.3 production loop（有界 step）已存在；
- P1-A.4 已把**入站** consensus command 的 Driver 失败限定为「拒绝 + 计数 + 继续」；
- P1-A.5 已把**本地/派生**路径的 `DriverError::QcVerification(FinalityError::UnknownTarget)`
  限定为「不适用 + 计数 + 继续」；
- P1-A.6 已加入 round timeout pacemaker（ADR-0049 的 node 层落地）。

**残留缺口（本 ADR 解决）**：*迟到加入 / restart-behind-tip* 的节点无法仅靠本地投票恢复**历史**
finality。

- block 可以同步（既有 `SyncBlockRequest` / `SyncBlockResponse`；ADR-0062 目标 = `local_head + 1`）
  并进入 DAG / BlockStore（`register_remote_canonical_block`）；
- 但 `finalized_reference` 只由「本地观察到的 quorum votes」推进（冻结 transition ⑥）；
- 历史高度的 votes / QC 一旦错过即时广播便**无法再取得**（无 relay / 无 pull），
  而 round context 固定在旧高度 ⇒ 该节点**永久停在旧 height**、且退出后续共识参与。

## Decision

采用 **Verified External Finality Adoption**：

> 节点仅在收到一个**已经通过现有 QC verification**、并且与本地 **canonical-next block 完全匹配**
> 的 PrecommitQC 后，才允许通过 **frozen finality applicability/update 原语**推进
> `finalized_reference`。

必须明确（否定式）：

```
external QC != new consensus authority
external QC != direct commit
external QC != direct head mutation
external QC != new voting rule
```

`external QC is untrusted evidence until independently verified.`

## Zero Wire Change

本 ADR **不新增任何 wire 类型**：

- 不新增 `MessageType` / `NetworkEvent` / request type / response type / wire version /
  handshake capability；
- 复用既有：`SyncBlockRequest`（请求）、`SyncBlockResponse`（block）、**`ConsensusQc`（QC 响应）**；
- QC 响应**不需要新的 `request_id`**：QC 被当作 **untrusted evidence**，而不是
  request/response authority；其最终接受条件由**接收端独立验证**决定（错配的 QC 只会被拒绝，
  且采纳路径幂等 / 单调 ⇒ 无副作用）。

理由（架构约束）：`NetworkService::classify` 对 `MessageType` 为**穷举**匹配，而
`crates/node/src/wiring.rs` 的 handler 对未知 `NetworkEvent` 走 `_` 兜底并丢弃 payload；
新增消息类型将**强制**修改 wiring（未授权范围），且会引入 wire 兼容性问题。复用既有三条通路
是最小、最保守、且完全向后兼容的方案。

## Frozen Consensus Boundary

```
consensus crate 不修改
consensus-spec-v1.md 不修改
network crate 不修改
wiring 不修改
D8 不修改
driver 不修改
```

采纳序列与 frozen transition ⑥（`crates/consensus/src/integration.rs`）**逐行同源**：

```text
verify_qc(qc, set, genesis_hash, dag)            // 唯一 QC 密码学验证原语（不重实现任何部分）
  → check_finality_applicability(qc, finalized, dag)
  → update_finalized_reference(&mut finality, qc, applicability)
```

三者均为 frozen **public** API；本 ADR 只新增 **node 层薄 facade**，不新增共识规则。

## D8 Boundary

- 同步目标**仍为 `local_head + 1`**（`sync_scheduler.rs` 不修改；ADR-0062 语义不变）。
- **不做**区间 / multi-block sync；追赶是 `H → H+1 → H+2 …` 的重复。
- 触发复用**既有** `MissingAncestorIntentLedger` → `sync_orchestrate` →
  `schedule_from_missing_ancestor`（**不新增** correlator / dispatcher / scheduler / 发送路径）。
- `intent_ledger.rs` 不修改（沿用既有 `BlockInboundSource` 变体）。

## New node-layer facade

`crates/node/src/assembly.rs` 仅新增：

```rust
pub fn adopt_verified_external_finality(
    &mut self,
    qc: &QuorumCertificate,
) -> AdoptionOutcome
```

内部只复用 `check_finality_applicability(...)` + `update_finalized_reference(...)`；
`Advance` ⇒ `finalized_reference = qc.target`（并镜像既有 `last_precommit_qc` 捕获规则），
其余 ⇒ `Idempotent` / `Stale` / `Conflict` / `Rejected(NotPrecommitQc)`，**零状态变更**。

**不得**重新实现：quorum / validator weight / signature verification / duplicate validator
detection / validator-set verification / finality ordering。**不得**直接修改 `ChainHead`。

## QC history

`storage_dir/qc_history/{height:020}.qcf`（**由高度直接派生路径** ⇒ **零目录扫描**）。

Artifact（严格）：

```text
magic(4) ‖ version(1) ‖ network_id(1) ‖ chain_id(8 LE) ‖ genesis_hash(32)
  ‖ height(8 LE) ‖ reference(32) ‖ qc_len(4 LE) ‖ qc(encoded) ‖ checksum(32)
```

强绑定（写入与读取**双向**强制）：

```text
height == qc.context.height + 1
reference == qc.target
qc.context.vote_type == Precommit
```

写入：`temporary file → write → sync → close → atomic rename`；临时名**不含**正式高度名
（崩溃残留的 `*.tmp*` 永不被查询路径读取）。

同高度语义：

```text
identical QC      → OK / idempotent（no-op）
conflicting QC    → ERR / FAIL CLOSED / NEVER OVERWRITE
```

读取必须全部通过（任一失败 ⇒ `Err`，**绝不 panic**）：magic / version / network_id / chain_id /
genesis_hash / height / qc_len / maximum artifact size / checksum / QC decode / Precommit /
`context.height + 1 == height` / `qc.target == reference`。

## Retention

```text
QC_HISTORY_RETENTION = 4096
```

写入 height `H` 后确定性淘汰 `H - QC_HISTORY_RETENTION`（单文件删除；**非**全目录扫描 GC）。

## Effective catch-up limit

```text
MAX_SYNC_WALK = 64                       （responder 取块回走上限；本轮不修改）
effective catch-up distance
  = min(QC_HISTORY_RETENTION, MAX_SYNC_WALK)
  = min(4096, 64)
  = 64
```

**Known limitation**：有效追赶距离 = **64 高度**。超过该窗口 ⇒ **FAIL CLOSED**：
不得猜测 QC、不得跳高度、不得直接接受 block、不得直接修改 head、不得构造 fake finality、
不得从其它高度借用 QC。

## Tip hint

启用（**每 block sync response ≤ 1 条**；与"请求高度对应 QC"合计 ≤ 2 条）：

- 来源必须是本地 `qc_history` 的 **tip**（`qc_history.get(tip_height)`；**直接路径**查询）；
- **不得**扫描 `qc_history/`、不得遍历所有 QC、不得寻找"最合适的 QC"；
- 对端收到后**仍必须 `verify_qc`**；`UnknownTarget` 按既有 P1-A.5 语义被容忍；
- tip hint 只是 **progress hint**，**不是 commit authorization**，不得因它直接 commit。

## Runtime ordering

```text
1. take inbound commands
2. InboundQc: verify_qc + acquire_lock
              target unknown ⇒ bounded pending（verified=false）
3. take block inbound
4. register_remote_canonical_block
5. adopt_pending_external_finality          （≤ 2 / step）
6. persist finality fact
7. persist QC history
8. existing finality commit bridge
9. advance_to_height
10. egress drain
```

**persist-before-broadcast**：物理发送在 step 末（10）；持久化（6/7）在其之前。
**禁止** `broadcast → persist`。

## Pending QC

```text
pending_external_qc
  - bounded：maximum 8 entries
  - deduplicate by target
  - no unbounded Vec growth / no retry storm / no blocking wait
```

- target 尚未进入 DAG ⇒ **buffer**（`verified = false`）；
- block 到达后 ⇒ 经**既有** driver 门面（`verify_qc` + `acquire_lock`）重新验证后重试采纳；
- 超过生命周期 / 发生 conflict / 前置检查失败 ⇒ **drop + count + fail closed**（不得无限保存）。

## Serve limits

```text
SYNC_REQUEST_CAP             = 64      （不变）
MAX_SYNC_RESPONSES_PER_STEP  =  4      （不变；每 block sync response 最多回 1 block）
Established-only                       （不变；不修改认证逻辑）
```

## Max message size

QC 编码 = `93 + n_validators × 136` 字节；发送前必须校验 `≤ max_msg_bytes`；
超限 ⇒ **skip + 计数**（`qc_serve_skipped`），**不截断**。

## Safety invariants

```text
S1  QC 必须通过现有 verify_qc
S2  QC 必须是 PrecommitQC
S3  qc.context.height + 1 == block.height
S4  qc.target == block.hash
S5  block 必须是 local canonical head + 1（不能跳高度）
S6  block.parent_hash == local_head.block_hash
S7  finalized reference 只能 Advance / Idempotent / Stale / Conflict（不能 rollback）
S8  QC adoption 不直接写 ChainHead
S9  canonical commit 仍只能经过现有 durable bridge
S10 所有 reject 必须 fail closed
```

## Crash consistency

| Case | 场景 | 结果 |
|---|---|---|
| A | QC persisted → crash → restart | QC history **remains serviceable** |
| B | `broadcast → persist` | **禁止**；正确顺序为 `persist → then broadcast`（由 step ordering 保证） |
| C | 重复写（same height + same reference） | **idempotent** |
| D | 冲突（same height + different reference） | **reject / never overwrite** |
| E | finality fact 已 durable、commit 尚未完成 | 重启依靠**既有**恢复机制（`restore_finality_fact` + DAG rebuild + WAL）恢复一致状态 |

补充：QC history 写入失败**不** halting consensus（它是**对端服务能力**，不参与本地 safety /
finality / commit 不变式）；失败按观测计数并在下一 step 重试（本地 fail-closed 语义由存储 API
保证：冲突不覆盖、损坏拒绝服务）。此设计同时避免新增 `RuntimeError` 变体（该类型为 bin 的
穷尽匹配类型，新增变体将强制修改 bin）。

## Backward compatibility

### New → Old

老节点收到附发的 `ConsensusQc` ⇒ 走**既有** inbound QC path（verify + acquire_lock；
**无 canonical 变更**）。不会因为新增功能而要求新 wire version。

### Old → New

老节点**不会**提供历史 QC ⇒ 新节点可能无法超过其可获取窗口
（`min(QC_HISTORY_RETENTION, MAX_SYNC_WALK) = 64`）。这是设计上的**明确 limitation**。

### Mixed network

不得假设所有 peer 都支持 A7。节点必须 **best effort + fail closed**。

## Rejected / conflicting QC behavior

- 无效 QC（签名 / quorum / 结构）⇒ driver 拒绝（P1-A.4 语义：拒绝 + 计数 + 继续）；
- target ∉ DAG ⇒ 有界 pending（既有 P1-A.5「不适用」语义）；
- 高度关系不符 / 非 canonical-next / 无 durable block ⇒ adopt 前置检查拒绝 + drop + 计数；
- conflict（同高不同 reference）⇒ 存储层 `Err`、永不覆盖；finality 层不 rollback。

## Test Matrix

| # | 测试 | 位置 |
|---|---|---|
| T1 | Real late join（A/B 到 H2；C head=0 追赶） | `crates/node/tests/d10_p1_a7_rejoin_catchup.rs` |
| T2 | Restart behind tip（C 重启后继续追赶） | 同上 |
| T3 | Invalid QC ⇒ reject | 同上 |
| T4 | Wrong target（∉ DAG）⇒ 有界 pending，零采纳 | 同上 |
| T5 | Wrong height ⇒ 采纳前置检查拒绝 | 同上 |
| T6 | Wrong parent / 非 canonical-next ⇒ 拒绝，不跳高度 | 同上 |
| T7 | Conflicting finalized reference ⇒ 拒绝，绝不 rollback | `assembly.rs` facade 单测 + 冻结 `check_finality_applicability` |
| T8 | Duplicate QC ⇒ idempotent / dedup | 同上（A7 测试） |
| T9 | Duplicate persistence ⇒ idempotent | `qc_history` 单测 |
| T10 | Missing / expired historical QC ⇒ fail closed | `qc_history` 单测（缺高度 / 超 retention）+ A7 测试（零采纳） |
| T11 | QC request DoS / bounds | A7 测试（pending ≤ 8；serve 上限不变） |
| T12 | Crash consistency（A–E） | `qc_history` 重开单测 + T2 + 既有 restart/E2E 回归 |
| T13 | Full regression（P0 / A3 / A4 / A5 / A6 / restart） | 既有测试套件 |

`qc_history` 单元测试覆盖：encode/decode、checksum、wrong network、wrong chain、wrong genesis、
wrong height、wrong reference、oversized QC、malformed QC、duplicate、conflict、retention、
corrupt file。

## Consequences

- 落后 / 迟到 / restart-behind-tip 节点可在**不修改 consensus / network / D8 / wiring / driver**
  的前提下追赶（真实 TCP 已证）。
- 有效追赶窗口为 64 高度（见 Known limitation）。
- 存储代价：`retention × (固定头 + QC) + 文件系统开销`，恒定有界。
- 采纳路径的**唯一** commit 授权仍是既有 durable commit bridge；`QC != commit`。
