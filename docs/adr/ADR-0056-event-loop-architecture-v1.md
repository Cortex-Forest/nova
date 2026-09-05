# ADR-0056: EventLoop Architecture v1

- Status: FROZEN (STEP 10-18C, 2026-09-05)
- Related: ADR-0054（Node Lifecycle）、ADR-0055（NetworkService）、STEP 10-18A / 10-18 IMPLEMENT（待授权）
- Scope: node-local 统一事件调度层；不改变 consensus/crypto/safety 语义

## Context

Nova Node 需要统一事件调度层，收敛四类事件来源：
- Network events（入站 message）
- Timer events（round timeout / retry / maintenance）
- Consensus internal events（vote produced / QC ready / finality advanced）
- Block events（block executed / state updated）

需要统一的原因是避免**隐式状态路径**：
- Network 直接调用 Consensus（跳过验证/单一 choke）
- Timer 直接修改 Consensus（绕过 round transition 守卫）

这些会形成绕过 canonical transition 与安全门面的旁路。EventLoop = 把这些来源统一为显式事件流 → 单一 dispatch → 明确 handler，保证所有对共识/安全的访问都经既有门面（verify_vote_input / verify_qc / transition / produce_vote）。

## Decision

`EventLoop = dispatch layer`：
- 负责：event receive、validation routing、handler dispatch。
- 不负责：state ownership（不拥有 ConsensusState / VoteLedger / SafetyStore / private key；不拥有网络状态）。

## Event Model
```
enum NodeEvent {
    Network(NetworkEvent),
    Timer(TimerEvent),
    Internal(InternalEvent),
    Block(BlockEvent),
}
```
每个事件：source → validation（envelope/结构/verify 门面）→ handler（driver/consensus/network/block）→ owner。

## Event Sources
```
Network: Proposal / Vote / QC / Sync
Timer  : RoundTimeout / Retry / Maintenance
Internal: VoteGenerated / QCReady / FinalityAdvanced
Block  : BlockExecuted / StateUpdated
```

## Ownership
- EventLoop owned by NodeRuntime。
- EventLoop **can hold**：channels、senders、handles。
- EventLoop **禁止持有**：private key、SafetyStore、VoteLedger、ConsensusState（ConsensusState owner = ConsensusNode；safety owner = ValidatorActor/SafetyStore）。

## Processing Flow
```
Inbound : Network → EventLoop → Validation → Driver → Consensus
Outbound: Consensus → EventLoop → NetworkService
```
（同步单线程 drain→dispatch；不引入 async runtime。Node 层验证门面位于 EventLoop→Driver 之间，consensus 语义从不在 EventLoop 内裁决。）

## Crash Recovery
- EventLoop：**NO persistence**（无任何落盘状态）。
- Restart：recreate EventLoop（无恢复负担）。
- Recovery sources（持久状态全在既有 owner）：SafetyStore（validator-local，fail-closed restore）、Chain Storage（block/head，bootstrap 恢复）；consensus round 不持久化（经对等重建）。

## Shutdown
顺序：
1. stop EventLoop（停止 drain；不再发起新 driver 调用）
2. stop NetworkService（断开 peers）
3. drop Driver（释放 actors/consensus）
4. close Storage

## Non Goals
本 ADR 不实现：
- async runtime（tokio 等集成）
- thread model（多线程/并发调度细节）
- production scheduler（优先级/背压/QoS 调度）
- consensus algorithm（EventLoop 只 dispatch，不实现共识逻辑）
以上均为后续独立授权实现。

---

> DRAFT（STEP 10-18A）。待 Owner 审查后 DESIGN FREEZE → 单独授权 IMPLEMENT。
