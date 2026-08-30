# Nova Chain — Block Network Propagation / Sync Design V1（P7-5）

- **Status**: **FROZEN**（P7-5 Block 网络传播/同步实现设计；Design Review 通过，2026-08-31）
- **Date**: 2026-08-31
- **Scope**: 完整 Block 格式接入网络层——`GossipBlock` 消息 + `validate_gossip_block`（结构验证）+
  `SyncBlockResponse` 完整 Block 格式（`BlockPayload` 填充）；网络层不接语义验证（归消费方 nova-runtime）。
- **协议基线**: ADR-0032 N-1~N-7；STEP 11-2（wire discriminator 扩展先例）；P7-2 Block 格式 / P7-3 验证 / P7-4 nova-runtime。

## 0. 目标

把 P7-2 完整 Block wire（`encode_block` = header‖body‖signature(64B)）接入 nova-network：
- **传播**：新增 `GossipBlock` 消息 + 结构验证（envelope 签名 + `decode_block`）。
- **同步**：`SyncBlockResponse` 的 `BlockPayload` 填充完整 Block wire。
- **边界**：网络层只做 wire + **结构**验证（N-5：不执行、不解析语义）；语义验证（P7-3/4：
  signature / tx_root / state_root / height/parent / commit）由消费方调用 `nova-runtime` 管线。

## 1. 范围与边界

| 纳入 | 排除 |
|---|---|
| `BlockPayload` = 完整 Block wire（`encode_block` 输出） | 不实现语义验证（signature/tx_root/state_root/height/parent） |
| 新增 `GossipBlock` 消息类型 + 结构验证 | 不实现 Gossipsub 调度（N-3） |
| `validate_gossip_block`（envelope 签名 + size + `decode_block` 结构） | 不实现完整状态同步 / fork resolution（N-6） |
| `SyncBlockResponse` 完整 Block 格式 | 不实现网络层→runtime 依赖（N-1） |
| 测试（roundtrip / 结构拒 / 错误分类） | 不接 consensus / execution / storage |

## 2. 现有资产（FACT，已核实）

| 资产 | 现状 | 归属 |
|---|---|---|
| `MessageType` | 10 类（0x01~0x0A）；TryFrom 注册 | nova-network（ADR-0032 N-4） |
| `validate_gossip_tx` | envelope 签名 + size + `decode_transaction`（结构，不执行） | nova-network gossip.rs（N-5） |
| `validate_consensus_envelope` | type 限定 + size（11-3 先例） | nova-network message.rs |
| `SyncBlockResponse` | `BlockPayload(Vec<u8>)` 占位；count(4LE)+len(4LE)+bytes | nova-network sync.rs（N-6） |
| `encode_block` / `decode_block` | 完整 Block wire = header‖body‖signature(64B)；结构拒绝（length/version/tag/trailing） | nova-core（P7-2） |
| `nova-runtime` | 分层步骤（②③④⑤⑥ 语义验证 + commit） | nova-runtime（P7-4） |

依赖方向（冻结）：`nova-network → core/crypto`（N-1 禁 execution/storage/consensus）；
**nova-network 不依赖 nova-runtime**（runtime 依赖 storage，间接违反 N-1）。

## 3. 设计（**已裁决 F1~F5**）

### 3.1 F1 = A：新增 `GossipBlock` 消息类型（0x0B）
- `MessageType::GossipBlock = 0x0B`（wire discriminator；payload = block wire，Network 不解析语义）。
- 同 STEP 11-2 先例（Consensus 三型扩展，仅注册值 ≠ 协议语义）。
- `TryFrom<u8>` 增 `0x0b`；`decode` 拒未知 type（现有逻辑自动覆盖）。
- **不引入 consensus 语义**（GossipBlock 仅扩展 message discriminator）。

### 3.2 F2：`BlockPayload` 语义 = 完整 Block wire（批准）
- `BlockPayload(Vec<u8>)` 填充 `nova_core::block::encode_block(&Block)` 输出
  （header‖body‖proposer_signature(64B)；**无额外前缀**——SyncBlockResponse 外层已有 len 前缀）。
- 提供构造辅助 `BlockPayload::from_block(&Block) -> Result<Self, BlockCodecError>`（wire 编码）。
- 保持 `Vec<u8>` 承载（wire 层；不引入 Block 结构依赖到 sync.rs 语义）。

### 3.3 F3：`validate_gossip_block`（结构验证，不执行；批准）
```
verify_message(vk, envelope)          // N-4 envelope 签名
check_size(payload.len())             // N-5 size
decode_block(&payload)                // 结构（length/version/tag/trailing 拒绝）；P7-2
返回 Result<Block, NetworkError>      // 成功 ⇒ 结构合法 Block
```
- 语义验证（signature/tx_root/state_root/height/parent）**不在此**——消费方调用 nova-runtime（F5）。
- 失败映射：envelope 签名 ⇒ `InvalidSignature`；size ⇒ `InvalidLength`；结构 ⇒
  `InvalidBlockStructure`（F4）。

### 3.4 F4：新增 `NetworkError::InvalidBlockStructure`（批准 + ADR impact review 通过）

- **新增变体**：`NetworkError::InvalidBlockStructure`——结构验证失败（`decode_block` 拒绝：
  length/version/tag/trailing）的分类编码。
- **ADR impact review（F4 先决步骤）**：
  - ADR-0032 N-4/N-5/N-6 边界不变：envelope 签名覆盖 / sender 不签 / 网络层不执行、不解析语义。
  - `NetworkError` 是 nova-network 自有错误模型（N-1 独立错误，不混用其他层）。
  - 新增变体仅把 `decode_block` 的既有结构拒绝分类编码为网络层错误；**不改变**哪些输入被拒 /
    N-5/N-6 语义。
  - 结论：**纯错误分类（API/错误模型层），协议语义不变 ⇒ 不修改 ADR-0032**
    （项目先例：P7-3 D5 / P7-4 E3）。

### 3.5 F5：语义验证衔接（批准：消费方调 nova-runtime；network 不依赖）
- `SyncBlockResponse` 结构不变（count+len+bytes）；`BlockPayload` 内容 = 完整 Block wire。
- 接收方：`decode` → 每个 `BlockPayload` 可 `decode_block` 结构验证；**语义验证（P7-4 runtime）由
  消费方（Node）串联**——**nova-network 不依赖 runtime/execution/storage**（N-1）。

## 4. 边界（冻结，不得违反）

- 网络层**不执行**（N-5）：validate_gossip_block 只结构验证。
- 网络层**不解析语义**：proposer authority/membership/eligibility、tx_root、state_root、
  height/parent、execution、storage commit、QC、consensus 语义——**全部归消费方 nova-runtime**。
- **不新增** network→runtime/execution/storage 依赖（N-1）。
- `GossipBlock` 仅扩展 message discriminator，**不引入 consensus 语义**。
- 不实现 Gossipsub 调度（N-3）/ 完整状态同步（N-6）。
- `BlockPayload` 只承载 wire bytes（不引入 Block 结构到 sync 语义层）。
- A11 DEFERRED；QC 不进本 STEP。

## 5. 决策点裁决（项目所有者已裁决，2026-08-31）

| # | 决策 | 裁决 | 影响 |
|---|---|---|---|
| **F1** | 新增 `GossipBlock`（0x0B） | **A：批准新增**（wire discriminator 扩展，11-2 先例；不引入 consensus 语义） | 新消息类型 + `TryFrom` 注册 |
| **F2** | `BlockPayload` 语义 | **批准：完整 Block wire（`encode_block` 输出），无额外前缀** | Block 格式接入同步 |
| **F3** | `validate_gossip_block` 结构验证 | **批准：nova-network 执行 envelope 签名 + size + `decode_block` 结构**（不执行） | N-5 边界保持 |
| **F4** | 结构失败错误 | **批准新增 `NetworkError::InvalidBlockStructure`；ADR impact review 通过（纯错误分类，不改 ADR-0032）** | 错误模型扩展 |
| **F5** | 语义验证衔接 | **批准：消费方调 nova-runtime；network 不依赖 runtime/execution/storage（N-1）** | 依赖边界保持 |

## 6. 测试计划（已裁决后）

- `MessageType::GossipBlock` 注册 roundtrip / 未知 type 拒。
- `BlockPayload::from_block`（wire == `encode_block` 输出）/ 手动构造。
- `validate_gossip_block`：ok（合法 wire）/ envelope 签名篡改 ⇒ `InvalidSignature` / size 超限 ⇒
  `InvalidLength` / 结构非法（截断/trailing）⇒ `InvalidBlockStructure`。
- `SyncBlockResponse` 完整格式 roundtrip（count+len+block wire）/ 坏长度拒。
- 回归：nova-network 既有测试（message/gossip/sync）全 PASS。
- 安全：结构验证不执行（无副作用）；错误分类明确（F4）。

## 7. 禁令（冻结后仍适用）

- 不改 ADR-0032 N-4/N-5/N-6 核心语义（F4 ADR impact review 已通过：仅错误分类，不改 ADR）。
- 不改 P7-2/3/4 冻结函数。
- 不新增 network→runtime/execution/storage 依赖（N-1）。
- 网络层不执行 / 不解析语义（N-5；proposer authority/membership/eligibility、tx_root、state_root、
  height/parent、execution、storage commit、QC、consensus 全归消费方 nova-runtime）。
- `GossipBlock` 仅扩展 discriminator，不引入 consensus 语义。
- **F1~F5 一经冻结，不得改变**（除非新 ADR / Protocol Review）。
- 不实现 Gossipsub / 完整同步 / Node 全量。

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-5 Block 网络传播/同步实现设计 V1（DRAFT——范围 / 现有资产 / F1~F5 / 边界 / 测试计划 / 禁令） | 用户授权 P7-5（FACT AUDIT 完成 → 实现设计，待 Review） |
| 2026-08-31 | **F1~F5 裁决落地**：F1=A 新增 `GossipBlock=0x0B`（wire discriminator 扩展，11-2 先例，不引入 consensus 语义）/ F2=批准 `BlockPayload` = 完整 Block wire（`encode_block` 输出，无额外前缀）/ F3=批准 `validate_gossip_block`（envelope 签名 + size + `decode_block` 结构，不执行）/ F4=批准新增 `NetworkError::InvalidBlockStructure`（ADR impact review：纯错误分类，不改 ADR-0032）/ F5=批准消费方调 nova-runtime（network 不依赖 runtime/execution/storage，N-1） | 项目所有者裁决 F1~F5 |
| 2026-08-31 | **DESIGN FROZEN（P7-5 Block 网络传播/同步）**：Design Independent Review **10/10 PASS / 0 findings**；冻结内容（不得改变除非新 ADR / Protocol Review）：`GossipBlock=0x0B` / `BlockPayload` = 完整 Block wire / `validate_gossip_block`（结构验证不执行）/ `NetworkError::InvalidBlockStructure`（ADR impact review 通过）/ 消费方调 nova-runtime（network 不依赖 runtime/execution/storage）。**不写代码；P7-5 Implementation NOT AUTHORIZED** | Design Independent Review 通过 → 项目所有者授权 Design FROZEN（独立 documentation commit） |
