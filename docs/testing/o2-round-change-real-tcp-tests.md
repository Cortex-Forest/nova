# O2 Round Change — 真实多进程 TCP 集成测试（契约与验证状态）

> **范围**：本文档只记录 `crates/node/tests/` 下两个 **O2 Round Change 真实多进程 TCP** 集成测试的
> 现行断言契约与最近一次验证结果；**不**重述协议规范（以 ADR-0066 / ADR-0070 / ADR-0072 / ADR-0073 /
> ADR-0074 与 `crates/consensus/src/round_change.rs` 为准）。
>
> **验证基准**：`HEAD = 57b43a5`（`main`），验证日期 2026-10-15；断言契约与当时工作区中的
> `crates/node/tests/o2_round_change_real_tcp_d1_apply.rs`、`o2_round_change_real_tcp_e2e.rs` 一致。

## 1. 测试清单与用途

| 目标（integration test target） | 测试名 | 用途 |
|---|---|---|
| `o2_round_change_real_tcp_e2e` | `o2_abandon_attestation_reaches_peer_over_real_tcp` | 证明 `0x0E`（AbandonAttestation）经**真实 TCP** 到达对端并入池，从而使**跨节点**达到 quorum 并组出 `0x0D`（RoundChangeCertificate），且对端**收到并处理**该证书 |
| `o2_round_change_real_tcp_d1_apply` | `o2_d1_applied_observed_on_real_observer_process` | 证明**非 validator 观察者**经真实 TCP 收到 `0x0D` 后，冻结语义下的 D1 适用路径可在该真实进程上被观测为 **`Applied`**（`rc_authority >= 1`） |

两个目标都启动**真实子进程**（真实 TCP、真实签名/握手），不复用同进程内的 actor 模拟。

## 2. 现行断言契约（要点）

### 2.1 E2E（`o2_abandon_attestation_reaches_peer_over_real_tcp`）

- **(1) `converged`（有界等待条件）**：所有子进程同时满足
  `rc_certs >= 1 && abandon_broadcast >= 1 && abandon_produced >= 1 && rc_authority + rc_rejected >= 1`。
  - 加入 `rc_authority + rc_rejected >= 1` 的原因：断言 (5) 要求"对端 `0x0D` 已到达并被处理"，
    而原来的等待条件未覆盖该事件，曾出现**等待条件满足但事件尚未到达**的竞态。
  - 该等待**有界**（`O2_WINDOW`）；超时即失败，**不**做无条件重试。
- **(2) `abandon_produced >= 1`**：本进程计时器**真实到期**。
- **(3) `abandon_broadcast >= 1`**：本进程 `0x0E` 已进入出站队列并 flush。
- **(4) `rc_certs >= 1`（关键证据）**：池内**组出证书** ⇒ 达 quorum 2W ⇒ 在 2 节点拓扑下**必然**意味着
  远端 `0x0E` 经真实 TCP 到达、decode、冻结验签并入池（自身仅 1W）。
- **(5) `rc_authority + rc_rejected >= 1`**：对端 `0x0D` **到达并被处理**（应用 **或** 合法 `Stale`）。
  该式**不**区分"应用"与"拒绝"，因此**不能**单独作为"状态已应用"的证据。
- **(6) `abandon_rejected == 0`**：入站 `0x0E` 无畸形 / 验签失败 / 身份不符 / 跨高度重放。
- **(7) `timeout_split[0] >= 1`**：`timeout_split = [Applied, Ignored, Rejected]` 为**单调累计**计数，
  仅在 round-timeout 冻结转移返回 `Applied` 时递增 ⇒ 证明"该节点自己的 round 真实前进过（停滞被打破）"。
  - **边界**：该断言**只**证明**本地 pacemaker** 的 round 前进；**不代表**对端 attestation 到达、
    证书组装或状态应用 —— 后者由 (2)(3)(4)(5)(6) 承担。
  - 取代了旧的 `max_round >= 1`：`round` 是**当前**值且在高度推进时归零，按 100 step 采样会系统性地
    漏掉瞬态（属观测粒度问题，不是协议性质）。
- **(8) 不跳轮**：同高度相邻样本的 `round` 增量 ≤ 1（冻结单步后继）。
- **该测试不声称证明"状态应用"**：E2E 容忍合法 `Stale` 处理；"应用"性质由 D1 测试承担。

### 2.2 D1（`o2_d1_applied_observed_on_real_observer_process`）

- **(1)(2)(3)** 观察者形态：`validator_enabled == false`、`abandon_produced == 0`、`rc_certs == 0`
  （非 validator、无本地签名、不自行组装证书）。
- **(4) `rc_authority >= 1`（核心）**：`rc_authority` 仅在 `RoundChangeApplication::Applied` 分支自增
  （`crates/node/src/runtime.rs`）⇒ 至少发生一次**成功应用**。而 `Applied` 只有在完整 `verify_certificate`
  （结构 / `validator_set_id` / 顺序去重 / 逐条验签 / `is_quorum`）通过、且冻结
  `round_timeout()` 转移返回 `Applied`、且转移后 round 恰为 `+1` 时才返回。
- **(5) 拒绝分类契约**：`rc_rej = [Malformed, Stale, WrongHeight, Quorum, Identity, Other]`，
  要求 `Malformed == Quorum == Identity == Other == 0` 且 `rc_rejected == Stale + WrongHeight`。
  - 取代了旧的 `rc_rejected == 0`：旧的 `rc_rejected == 0` 把"观察者恰好只收到一份证书"这一**拓扑/观测假设**
    写成了协议契约，而 `Stale`（`to_round <= local_round`）与 `WrongHeight`（高度不符）都是**冻结语义下合法**
    的拒绝；观察者自身的 pacemaker 会独立推进其 `(height, round)`。
  - `rc_rej` 为**严格解析**：字段缺失或格式不合法 ⇒ 该样本无效（**不**默认成零）。
- **(6)(7) 生产路径与归因**：A/B 侧确有真实 EXPIRE attestation 与 quorum 证书组装；P1/P2/P3 见下。
- **P1 单调**：观察者 `height` 不回退；同高度内 `round` 不回退。
- **P2 归因**：`rc_authority` 首次 ≥ 1 的样本必须与前一样本在 `(height, round)` 上**不同**。
- **P3 归因（现行）**：`rc_authority` 累计**单调**，且**每一次增加**都必须伴随 `(height, round)` 变化。
  - **取代**了旧的 `rc_authority == 1` 与"首个非零样本恰为 1"。旧断言的前提"整轮仅一张证书"**不是**协议性质：
    证书按**每个** `(height, from_round)` 上 2W 见证重合而独立产生，而本场景中 A/B 会**多次**到期
    ⇒ 同一轮运行内**可合法地应用多张不同证书**（实测曾出现 `rc_authority == 2`，且拒绝全部为 `Stale`）。
  - **同一张证书的重复应用在冻结语义下结构性不可能**：首次应用后 `local_round == to_round`，任何后续副本必然
    在 `verify_certificate` 的 round 回退检查处被判 `Stale`（零副作用）。该性质由 (4)(5) 与 P3 归因循环共同覆盖。
- **P4 覆盖（现行）**：先**有界等待**（最长 120 秒）直到 `max(A.head, B.head) >= O.head`，再做**容差 0** 的断言
  `ab_max >= O.head`。详见 §3。
- **P5 目标/终局**：A/B 必须跨过 round-0 停滞（`head >= 1`）；`finalized <= head`；两者均已达到 finality。

## 3. P4 的证明范围限制（重要）

`head_height` 是**durable chain head**（`block_production().head().height`）。节点的 periodic status 行
**按各自的 `steps % 100 == 0`** 打印，而 D1 测试在此前版本中于"观察者首次 `applied`"后**立即**采集并终止
⇒ 验证者的**最后一条采样**可能落后其真实 durable head（高度在停滞被打破后会成批推进）；此外验证者会先
**构建/持久化**区块再使其成为自身 durable head，而 sync responder 从该存储供块，故跟随者可能先于验证者
自身的提交而推进。

因此：

- 旧断言 `O.head <= max(A.head, B.head) + 1` 是**跨时刻**的采样比较，其失败**不能**证明协议违规。
- 现行 P4（有界收敛 + 容差 0）**证明的是**："观察者的 durable head 已被验证者所提供的 height **覆盖**"
  ⇒ 观察者不是链推进的来源；若观察者**持续**领先（例如凭空推进），在窗口耗尽后仍会失败。
- 现行 P4 **不证明**：同一逻辑时刻的 head 关系、状态转换的原子性、不存在瞬时领先、全局共识安全性。
  它是一项**收敛/覆盖**性质，而**不是**安全性或最终性证明。
- **仍存的可观测性缺口**：目前 status 面缺少足以验证"同一逻辑时刻"关系的字段（例如单调的
  "历史最高 head"或共享逻辑时钟）。若要严格验证该性质，需要**另行授权**的生产侧可观测性补充；
  本文档不通过放宽断言来掩盖该缺口。

## 4. 最近验证结果（2026-10-15，HEAD `57b43a5`）

使用 `cargo test --locked --offline`，隔离构建目录（不在仓库内），每个目标独立运行 3 次（每次为**新进程**）：

| 目标 / 套件 | 命令 | 结果 |
|---|---|---|
| D1 | `cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_d1_apply -- --nocapture` | **3/3 通过**（`1 passed; 0 failed`，用时 50.80s / 42.02s / 50.55s） |
| E2E | `cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_e2e -- --nocapture` | **3/3 通过**（`1 passed; 0 failed`，用时 20.22s / 12.45s / 18.85s） |
| `nova-consensus` 单元测试 | `cargo test --locked --offline -p nova-consensus --lib` | **178 passed / 0 failed**（175.65s） |
| `nova-node` 单元测试 | `cargo test --locked --offline -p nova-node --lib` | **301 passed / 0 failed**（1.41s） |
| `runtime_tests` | `cargo test --locked --offline -p nova-node --test runtime_tests` | **13 passed / 2 failed**（0.18s）— 见 §5 |

D1 三次运行中观察者侧均为：`rc_authority = 1`、`rc_rejected = 1`、`rc_rej = [0,1,0,0,0,0]`（唯一拒绝为合法 `Stale`），
且 P4 的收敛条件在采集前已满足。E2E 三次运行中 A/B 均为 `rc_certs = 1`、`rc_rejected = 1`、`timeout_split = [1,0,0]`。

## 5. `runtime_tests` 中观察到的失败（证据状态）

在本次运行（`cargo test --locked --offline -p nova-node --test runtime_tests`）中观察到 **13 passed / 2 failed**，
两项失败均位于 `crates/node/tests/runtime_tests.rs`，原始输出如下（逐字摘自运行日志）：

- `rt_28_validator_id_mismatch_startup_fails`（`runtime_tests.rs:307:5`）：
  `validator_id mismatch ⇒ validator 启动 fail closed（got SafetyJournalMissing）`
  ⇒ 启动确实 fail-closed 失败，但返回的错误是 `SafetyJournalMissing` 而**不是**用例期望的
  `NodeRuntimeError::Validator(_)`。
- `rt_29_runtime_processes_consensus_command`（`runtime_tests.rs:340:5`）：
  `assertion \`left == right\` failed`、`left: None`、`right: Some(ProposalRef { block_hash: [170;32], proposer: ValidatorId([...]) })`
  ⇒ `process_consensus_command(Proposal)` 返回 `Ok`，但随后的 canonical 状态断言未通过
  （`state.round.proposal` 仍为 `None`）。

**证据状态（谨慎表述）**：

- 该文件在本次验证中**未被修改**（其 SHA-256 与基线一致），且该目标与本轮 O2 测试属于**不同的
  integration test target** ⇒ 结构上不受本轮测试文件改动影响。
- **早前记录**：`docs/testnet/akash-deployment-v1.md` §19.2 已在 2026-10-14 记录同一失败位置与
  相同失败形态（含 `left: None` / `right: Some(ProposalRef{...})`），并注明该文件与 `runtime.rs`
  哈希与当时基线一致，将其标为 **PRE-EXISTING FAILURE**（该轮**未修**，属超范围）。
- **本轮未做独立基线对照**：本轮**没有**在"完全干净的工作区"上单独运行 `runtime_tests`。
  因此准确表述是：**本次运行观察到该两项失败；有早前记录 + 本轮未修改相关文件作为支持，但缺少本轮
  独立基线对照运行，尚不能仅凭本次运行独立确认"既有"这一结论。**
- **与早前记录的一处不一致（如实记录）**：§19.2 将两项失败一并描述为"左值/右值不匹配、**与 journal 无关**"，
  而本轮原始日志显示 `rt_28` 的失败消息为 `got SafetyJournalMissing`（即与 safety journal 的存在性检查**有关**）。
  该不一致未被进一步追查（需授权修改该测试文件后定位）。
- **未验证的机制假设**（仅供后续定位参考，本轮**未**验证）：`rt_28` 只预建了 `safety.journal`，而
  运行时在 `validator_safety_init = false`（既有 journal 场景）下要求 `safety.journal` 与
  `block-safety.journal` 同时存在，缺失其一即 fail-closed 返回 `SafetyJournalMissing`；
  `rt_29` 提交的 `ProposalRef` 可能因缺对应本地区块而在准入/应用路径被拒绝或挂起。
  两者均为**假设**，未在本轮获证。
- 本轮**未**修改这两个用例，也**未**对该目标做任何断言弱化。

## 6. 限制与未决事项

1. 上述目标测试通过，**只表示所述测试契约在所述范围内已修正并通过验证**，**不**表示共识协议整体安全性已证明，
   **不**表示 P-6（持久卷 / Mount Guard 等）已完成，**不**表示 Testnet 或 Mainnet 已具备发布条件。
2. P4 无法在纯测试范围内验证"同一逻辑时刻"的 head 关系（见 §3），该缺口保持**未解决**。
3. `runtime_tests` 的两项失败仍**未修复**（其文件未获授权修改）；本节仅记录观察与根因分析。
4. 本文档不记录任何临时证据目录、机器专属路径或本机环境细节。

## 7. 复现命令

```bash
cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_d1_apply -- --nocapture
cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_e2e -- --nocapture
cargo test --locked --offline -p nova-consensus --lib
cargo test --locked --offline -p nova-node --lib
cargo test --locked --offline -p nova-node --test runtime_tests
```

---

## 附：2026-10-18 R13 复跑记录

| 目标 | 命令 | 结果 |
|---|---|---|
| `o2_round_change_real_tcp_e2e` | `cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_e2e` | exit 0，**1 passed / 0 failed**（25.48 s） |
| `o2_round_change_real_tcp_d1_apply` | `cargo test --locked --offline -p nova-node --test o2_round_change_real_tcp_d1_apply` | exit 0，**1 passed / 0 failed**（59.83 s） |

> 本节于 R13 追加，仅记录新的执行结果；上文 §1–§2 的断言契约与 2026-10-15 基线描述**保持原样、未改写**。
> 本文档记录的是**仓库内测试证据**，不构成 Akash 真实网络部署或验收。
