# Nova Chain — Consensus Integration Boundary Verification V1（10-12）

- **Status**: **FINAL**（STEP 10-12；Consensus Integration Boundary Verification 完成，2026-08-30）
- **依据**: `consensus-external-integration-contract-v1.md`（10-11，FROZEN）+ ADR-0033~0040 + `consensus-spec-v1.md`（FROZEN）+ STEP 10-9（FROZEN）+ 实际代码/依赖图。
- **本报告是审计产物，不修改任何冻结契约/代码**；仅记录 Verification 结果。

---

## 1. Objective

验证 10-11 定义的跨层边界（L1~L5）与当前仓库事实一致，且未来 Network / Storage / Execution / Node 接入时**不存在已知的** ownership / verification / dependency / logical-input-output / replay-dup-malformed / determinism / RoundTimeout / N-4 / Storage / PHASE-7 / Execution / Node 冲突。

**方法纪律**：允许 Verification **推翻 Proposal 结论**；不因 Proposal 预判"无缺陷"而只做确认。Determinism / Replay-Duplicate-QC / Cargo dependency 三项均以**实际代码与依赖图**重新验证。

---

## 2. Repository Evidence（实际重新验证）

### 2.1 Cargo Dependency Graph（`cargo tree --workspace` 实际输出）

```
nova-consensus → nova-core → nova-crypto
nova-execution → nova-core, nova-crypto
nova-network   → nova-core, nova-crypto
nova-storage   → nova-core, nova-crypto
nova-node      → （零依赖）
nova-rpc       → （零依赖）
nova-wallet    → （零依赖）
```

- **无 `Consensus → Network/Storage/Execution/Node` 反向边**；C-1（Consensus → core/crypto 单向）完全保持。✅

### 2.2 Determinism Sources（grep 实际扫描 `crates/consensus/src/*.rs`）

- `SystemTime` / `Instant` / `rand` / `thread_rng` / `static mut` / `OnceLock` / `LazyLock` / `Mutex` / `Atomic*`：**零匹配**（生产代码）。
- 生产代码 `expect`/`unwrap` 仅 2 处**不可达断言**（已独立审计为 non-blocking）：
  - `checkpoint.rs:157`（`encode_checkpoint` qc_len u32 截断，H-1 修复，>4GiB 不可达）；
  - `fork_choice.rs:143`（`select_root`，非空 DAG 必有 root，10-8 H-1）。
- 其余 `unwrap`/`expect` 均在 `#[cfg(test)]`（`KeyPair::generate` 等测试 helper）。
- **无隐藏全局状态 / 迭代顺序 / 时间 / 非 canonical context**。✅

### 2.3 Replay / Duplicate / QC（追踪冻结实现与测试）

| 项 | 冻结实现 | 测试证据 |
|---|---|---|
| Replay（旧 height/round） | `round.rs process_vote` 上下文守卫（10-5.1 修复 A） | `round::tests::process_vote_*`；`integration::tests::t2/t18` |
| Duplicate（同 validator 同 target） | `VoteAccumulator::record` 去重（B-2） | `round::tests::vote_accumulator_dedup_and_aggregate`；`integration::tests::t3` |
| Malformed | `verify_vote`（V-5）/ `verify_qc`（F-6a） | `vote::tests::vote_verify_rejects_tampering`；`finality::tests::verify_qc_rejects_*` |
| Out-of-order / context mismatch | 上下文守卫 | `integration::tests::t2/t18` |
| Already-finalized | 终态守卫（10-5.1 修复 B） | `integration::tests::t5` |
| QC manipulation | `verify_qc`（F-6a 五层） | `finality::tests::verify_qc_rejects_*` |
| Determinism（replay 同结果） | MF-12 纯函数 transition | `integration::tests::t9/t23`；proptest |

---

## 3. Verification Matrix

| Boundary | Contract（10-11） | Current Repository Fact | Expected Future Integration | Conflict | Classification |
|---|---|---|---|---|---|
| L1 Network | 逻辑消息 1:1 + N-4 + Network owns transport | `MessageType` 七类无 consensus；`network → core+crypto` | Network 发逻辑消息构造 `ConsensusEvent`（Vote 用 `DomainId::ValidatorVote`） | **无** | ENFORCED（边界）+ DEFERRED（消息接入=Network Phase） |
| L2 Proposal/Block | 只消费 `ProposalRef`/`BlockReference` | `core/block.rs` 仅 `BlockExecutionResult`；无 BlockHeader/block_hash | PHASE 7 Block Spec 冻结后提供 | **无** | ENFORCED（消费类型）+ DEFERRED（Block Spec=PHASE 7） |
| L3 Execution | Consensus 不执行/不判 validity/不产 receipt/WASM/mempool | `execution → core+crypto`；无 coupling | `BlockExecutionResult` 独立下游 | **无** | ENFORCED（C-1）+ DEFERRED（Execution Phase） |
| L4 Storage | Consensus 交付语义；Storage 负责 encoding | `storage → core+crypto`；无 ConsensusState coupling | Storage Phase 负责 ConsensusState encoding/持久化 | **无** | ENFORCED（语义）+ DEFERRED（encoding=Storage Phase） |
| L5 Node | Node=orchestration owner；Consensus=transition owner | node 骨架（Config）；零依赖 | Node Phase 实现 receive→consensus→route | **无** | DEFERRED（Node Phase） |

---

## 4. 逐项验证结果

### C1~C7 — Network
- C1 Network owns transport/wire/envelope ✅（`network/src/` 有 message/transport/gossip/sync；无 consensus 语义）
- C2 Consensus owns logical verification ✅（`integration.rs` V-5/verify_qc/guards）
- C3 无 `Consensus→Network` 反向 ✅（cargo tree）
- C4 无新 DomainId ✅（10-11 未新增；无 domain.rs 改动）
- C5 Vote 用既有 `DomainId::ValidatorVote` ✅（`vote.rs` `canonical_vote_payload`/`verify_vote`）
- C6 arrival/peer/timing 不进入 deterministic input ✅（§2.2：无时间/随机/全局状态；transition 输入仅 (state, context, event)）
- C7 `RoundTimeout` = Node-local event ✅（B-3 / spec §8 / §5；`ConsensusEvent::RoundTimeout` 本地构造；network 无 Timeout 消息）

### D — Proposal/Block
Consensus 只消费 `ProposalRef`/`BlockReference`；**无** BlockHeader/block_hash/receipt/state-root/body/encoding 提前引入（PHASE 7 保持）✅

### E — Execution
Consensus 不拥有 tx 执行/validity/receipt/WASM/mempool；Execution 不反向改变 Consensus semantics（无 coupling）✅

### F — Storage
Consensus→Storage 只交付语义/replay 对象/deterministic transition；**无 ConsensusState encoding 偷渡进 Consensus** ✅

### G — Node
Node=orchestration owner（未来）；Consensus=deterministic transition owner；Node 未实现编排 = **DEFERRED 非 defect** ✅

### H — Replay / Duplicate / Malformed
全部映射到冻结语义（§2.3 表），无新规则 ✅

### I — Determinism
`same logical input + same canonical state + same relevant context ⇒ same result`——**PASS**（§2.2：生产代码无 peer/arrival/timing/connection/gossip 隐含输入）✅

### J — Dependency
`Consensus → core/crypto`；零反向（§2.1 cargo tree）✅

### K — N-4
Network domain 独立于链上 domain；未新增 DomainId；Vote domain 未被重定义；Consensus 不拥有 wire signature semantics；envelope 非 Consensus primitive ✅

---

## 5. Findings

| Finding ID | Severity | Boundary | Evidence | Classification | Protocol Impact | Required Action |
|---|---|---|---|---|---|---|
| F-INFO-1 | INFO | L1/L5 | Network/Storage/Execution/Node 当前均不依赖 Consensus | **DEFERRED / NOT DEFECT / NOT BLOCKING** | 无 | 各上层 Phase 接入时加入 → Consensus 依赖并验证 |
| F-INFO-2 | INFO | L5 | Node 骨架无 orchestration | **DEFERRED / NOT DEFECT / NOT BLOCKING** | 无 | Node Phase 实现编排 |
| F-INFO-3 | INFO | L4 | Storage 无 ConsensusState persistence hook | **DEFERRED / NOT DEFECT / NOT BLOCKING** | 无 | Storage Phase 8E 收口 |

> **说明**：以上 3 项为未来阶段预期状态，**非缺陷**；不为"清零 Findings"而隐藏或升级。

---

## 6. 结论

```
Protocol Defect: NO
ADR Required: NO
Code Changes: 0
Frozen Contract Changes: 0
Frozen Spec Changes: 0
Blockers: 0
```

**10-12 Verification 结论**：10-11 定义的跨层边界与仓库事实**一致**；未来各层接入**无已知冲突**；Determinism / Replay-Duplicate-QC / Dependency 经实际代码与依赖图重新验证均 PASS（**未被 Proposal 结论推翻，亦未发现新缺陷**）。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-30 | 初稿：Consensus Integration Boundary Verification V1（FINAL）——实际读取依赖图（cargo tree）+ 确定性来源扫描 + replay/dup/QC 实现追踪；5 边界全 PASS；F-INFO-1~3 = DEFERRED/NOT DEFECT/NOT BLOCKING | STEP 10-12 VERIFICATION PROPOSAL APPROVED → EXECUTION |
