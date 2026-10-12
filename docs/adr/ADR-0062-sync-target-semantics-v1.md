# ADR-0062: Sync Target Semantics v1

- **Status**: PROPOSED（设计冻结；待 Owner 批准后接线实现）
- **Date**: 2026-09-07
- **STEP**: 10-19-10-B7-A1-D8-1.5（Sync Target Protocol Decision）
- **Scope**: PHASE — Network / Block Sync（outbound request target 语义；**只冻结语义，不实现**）
- 关联：ADR-0054（Node Lifecycle）、ADR-0055（NetworkService）、ADR-0059（Network Security /
  Handshake / Established session）、STEP 10-19-10-B1（MissingAncestorIntentLedger）、
  B2/B3/B4（SyncRequestCorrelator：correlation/timeout/retry）、B5（SyncRequestScheduler）、
  B6（SyncOutboundDispatcher）、D8-1 READ-ONLY RECON

## Context

### 1. Problem

D8-1 RECON 发现生产阻塞：`FutureMissingAncestor` verdict 只携带
`{ observed_height, observed_block_hash, local_head_height }`（+ source/count）。本地
**无法安全推导**其 parent 链中缺失 block 的精确 hash：

- 禁止 `observed_height + 1` 当 ancestor hash target（observed block 的 parent 链可能缺多个
  block，`H = L + N`，N 可 > 1）；
- 禁止把 `observed_block_hash` 当 sync target（本地已收到该 future block，请求它无益；
  其缺失的是祖先区间，不是它本身）。

→ 需要一个明确、安全的 **Sync Target 语义**，使
`FutureMissingAncestor → SyncRequestIntent → SyncBlockRequest` 的映射可判定。

### 2. Existing limitation

- `MissingAncestorIntent`（B1）只含 observed future block 的事实；无精确缺失祖先 hash、
  无缺失区间、无 peer。
- `SyncRequestScheduler::schedule_from_missing_ancestor` 当前**恒 `Unschedulable`**
  （`target_from_missing_ancestor` 恒 `Err`）—— 诚实拒绝，不伪造 target。
- 无生产 RequestId 生成者；无 LogicalTick 驱动（timeout）；无真实 outbound dispatcher
  adapter；response 路径无 correlation resolve、不 persist / 不 commit（见 D8-1）。
- 本 ADR 只冻结 **target 语义**；RequestId / timeout / dispatcher / persist 接线属后续步骤。

## Decision（建议，待批准）

### 3. SyncBlockRequest semantics（沿用现有 wire）

现有 wire（network::sync，**不修改**）已支持本决策所需形态：

```
SyncBlockRequest {
    request_id: RequestId,          // 16B canonical correlation id（caller-owned）
    height: u64,                    // 目标高度（LE 8B）
    block_hash: Option<[u8; 32]>,   // 可选精确 hash
}
```

- `request_id`：只作关联，不作信任依据。
- `block_hash = Some(hash)` ⇒ **精确请求**：“请求指定高度、指定 hash 的 block”（本地已有
  可信 hash 来源时使用）。
- `block_hash = None` ⇒ **height-based 请求**：“从指定 height 开始获取可验证 block”。
  这不是“接受远端任意 block”—— 远端返回后仍须按 §6 全量验证。

### 4. Height semantics

`SyncRequest.height` 定义为：

```
SyncRequest.height = local_head_height + 1
```

即 **“本地 canonical head 之后第一个待同步高度”** —— 不是 “observed block 的 parent 高度”，
也不是 observed block height 本身（observed block 自身已在本节点，无请求价值）。

本地能可靠计算 `local_head_height + 1`（head 是本地 canonical 单一源）；因此高度 target
**可安全构造**，无需伪造。远端返回后要求**逐块验证连续性**（§6），防远端跳链。

若未来本地能证明“第一个真实缺失高度 ≠ head+1”（例如缺失区间有独立可信来源），再单独设计；
本 ADR 不假装能计算“第一个缺失高度”而只冻结 head+1。

### 5. Optional block_hash semantics

- `Some(hash)`：**hash-pinned 精确请求**。用于已有可信 hash 来源的路径
  （例如已知某高度 canonical hash、或未来 response 内链回指）。高度与 hash 二者必须自洽。
- `None`：**height-anchored 请求**（§4：head+1 起）。不携带对 target hash 的预设，靠
  §6 响应验证建立信任。
- 禁止：`FutureMissingAncestor` 的 `observed_block_hash` 不能作为 `Some` target（§1）；
  禁止用 `head+1` 猜测任何 hash。

### 6. FutureMissingAncestor mapping

```
FutureMissingAncestor { observed_height: H, observed_block_hash: X, local_head_height: L }
        ↓
SyncRequestIntent {
    request_id,                       // caller 生成
    peer,                             // 确定性 peer selection（B5）
    target = SyncRequestTarget {      // = SyncBlockRequest 语义
        height: L + 1,                // head 后第一待同步高度（非 H、非 X、非 parent(X)）
        block_hash: None,             // 不伪造 ancestor hash
    },
}
```

- 语义表达：“本地需要从 `L+1` 开始补齐历史链”，由响应验证逐步建立对祖先链的信任；
  直到响应块链回指至本地 head（或与 observed future block 汇合）为止。
- B1 intent 是 **height-based 触发**；`Some(hash)` 路径只用于其它可信 hash 来源。

### 7. Response validation

`SyncBlockResponse.blocks`（可含一个或多个 block；wire = count + len-prefixed block wires）
返回块必须满足：

- **chain identity 一致**：`chain_id`（network_id / genesis context 一致）；
- **height 连续**：块内高度逐块 `+1` 递增；
- **parent_hash 连续**：`block[i+1].header.parent_hash == block[i] 的 canonical hash`；
- **首块可连接本地 canonical head**：`blocks[0].height == head.height + 1` 且
  `blocks[0].header.parent_hash == head.block_hash`；
  若首块无法连接本地 head ⇒ **Reject / Invalid，不得 commit**；
- 每块经既有 `validate_block_inbound` 全量规则（§Security 参考）：size / decode / version /
  chain_id / canonical block hash 重算 / ordering / transaction_root / proposer signature /
  state_root 等 —— **不得 bypass existing inbound validation**。

本 ADR **不实现 range sync 语义**（多块高度窗口抓取策略），只冻结“返回 blocks 连续性 +
可连接 head + 全量验证”的最小接收前提。

### 8. Canonical Commit boundary

- **Sync Response ≠ 自动 commit**。
- 设计流程：
  ```
  SyncBlockResponse
      ↓ decode
      ↓ correlation check（request_id）
      ↓ validate every block（既有 inbound 规则）
      ↓ check chain continuity（height / parent_hash）
      ↓ check canonical predecessor（首块可连接本地 head）
      ↓ only then 进入既有 NodeBlockAdapter 授权边界（未来 commit 授权层）
  ```
- 本 ADR **不实现** `NodeBlockAdapter.apply_block` 的 Sync caller，也不宣称
  `CanonicalNextCandidate` = finality-authorized。仅冻结未来接入原则：验证 → 连续 → 可连接
  → 之后才可进入 commit 授权边界；commit 授权仍属共识/finality 层职责（不在本 ADR）。

### 9. Security invariants

1. 不信任 remote-provided height。
2. 不信任 remote-provided block hash（canonical hash 一律本地重算）。
3. 不因 request_id 匹配就接受 response（仍须 §7 全量验证）。
4. 不允许 response 跨 chain（chain_id / genesis context）。
5. 不允许 parent discontinuity。
6. 不允许 height regression。
7. 不允许 duplicate height with conflicting hash。
8. 不允许把 observed block hash 当作缺失 ancestor hash。
9. 不允许使用 height+1 猜 hash（height+1 只是高度 target，不是 hash target）。
10. 不允许 bypass existing inbound validation。
11. 首个可连接块必须 parent == 本地 head（无 head 则无可验证起点 ⇒ 不 commit）。

### 10. Scheduler responsibility

- **不负责猜 ancestor hash**。
- 只负责：`SyncRequestIntent` → peer selection → request scheduling（deterministic；
  exclude attempted；bounded FIFO）。
- target resolution 由 intent target 语义提供（本 ADR §3-§6）：
  - B1 `FutureMissingAncestor` → 将来产生 **height-based** `SyncRequestIntent`
    （target = { height: head+1, block_hash: None }）；
  - 已知精确 block hash → 可产生 **hash-based** `SyncRequestIntent`
    （target = { height, block_hash: Some(hash) }）。

### 11. Correlator responsibility

- 未来 request 生命周期：
  ```
  RequestId generated
      ↓ SyncRequestCorrelator.register(request_id, target, deadline_tick)
      ↓ SyncBlockRequest sent
      ↓ remote response
      ↓ request_id resolve
      ↓ validate response
  ```
- response 的 request_id 不存在（未知 / 已 resolve / RetryEligible / 过期）⇒ 按既有错误
  语义 Reject / Ignore（response-after-expiry 绝不 accept）。
- 本 ADR **不实现** RequestId generator（生成 seam 归未来步骤；与 SessionNonce 类似原则）。

### 12. Dispatcher responsibility

- 未来链路：
  ```
  SyncRequestIntent
      ↓ Scheduler
      ↓ SyncBlockRequest
      ↓ Correlator.register（register-before-send）
      ↓ Dispatcher
      ↓ NetworkService.enqueue_outbound（Established peer）
  ```
- Dispatcher 不负责：target inference、consensus、finality、commit。只把已调度 intent 经
  既有 NetworkService outbound 边界送出（Established-only gate 由 NS 执行）。

### 13. BlockStore non-requirement

- 当前 `BlockStore` 是 **hash-keyed**（`put/get/contains`）；无 `get_by_height` /
  `get_range` / ancestor index。
- 本 ADR **不新增 storage index、不修改 BlockStore**。
- 本决策（head+1 height-based target + 响应验证）**不依赖**高度/区间索引。
- 未来若实现 range sync / 本地高度枚举，再单独设计 storage 需求。

### 14. Future extension for range sync

- 本 ADR 只冻结最小语义（单请求高度起点 + 可选 hash + 响应连续性验证）。
- 未来 range sync 若需要（多高度窗口、按区间请求、本地高度索引、ancestor traversal），
  属**新的协议决策**，需单独 ADR；不在本 ADR 扩展。
- 任何扩展不得削弱 §8 commit 边界与 §9 security invariants。

## Consequences

- B1 seam（`schedule_from_missing_ancestor` 恒 `Unschedulable`）在新 target 语义落地后可由
  上层 caller 构造 height-based intent（head+1，block_hash=None）入 scheduler —— 但本 ADR
  不实现该 caller。
- 本 ADR 冻结语义，不产生 Rust 改动；实现接线（Runtime 编排 / dispatcher adapter /
  RequestId / timeout / response resolve）属后续 D8-2 及以后步骤，逐次授权。
