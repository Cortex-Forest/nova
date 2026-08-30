# Nova Chain 协议文档

## 状态

- PHASE 1 — Project Foundation（PASS）。
- PHASE 2 — Protocol Design（进行中）：
  - Cryptography（STEP 1-5）：已实现并冻结（`crypto-serialization-v1.md` / `crypto-test-vectors-v1.md`）。
  - Genesis / Transaction / State / Storage（STEP 6-8）：已实现并冻结（`genesis-v1.md` 等）。
  - Network（STEP 9）：已实现（nova-network：NodeId / MessageEnvelope / MessageType / transport /
    gossip / sync）。
  - Consensus（STEP 10）：**FINAL FROZEN** + 已实现（nova-consensus；ADR-0033~0040 +
    `consensus-spec-v1.md`）。
  - STEP 11（Network ↔ Node ↔ Consensus 集成）：**11-1~11-7 FINAL FROZEN**（Envelope 验证 / Node
    组装 / RoundTimeout / Vote / Proposal 端到端可验证；`ADR-0041` ProposalRef serialization FROZEN）。
    QC ingestion / A11：**DEFERRED**（独立后续 Track）。
- RPC：`NOT IMPLEMENTED`（等各自 Phase）。
- 完整 Block 格式 / block_hash：**PHASE 7 DEFERRED**。

## 已冻结协议规范

| 规范 | 状态 | 内容 |
|------|------|------|
| `crypto-serialization-v1.md` | Frozen | 字节序（LE）/ 长度（u32 LE）/ 定长 bytes / Option / Enum / 字段顺序 / 禁止表示 / 签名流水线 |
| `genesis-v1.md` | Frozen | GenesisV1 schema、嵌套类型、校验规则、`genesis_hash`、链身份三职责分离 |
| `crypto-test-vectors-v1.md` | Frozen | Address / Domain / Signature / Genesis 向量规范 |
| `consensus-spec-v1.md` | Frozen | 唯一权威共识规范：BFT round / vote / QC / finality / checkpoint / fork choice / data model / determinism / replay / security / traceability（STEP 10-10 FINAL FROZEN） |

## 草稿协议规范（Draft）

（当前无草稿协议规范；`consensus-spec-v1.md` 已 FINAL FROZEN，见上表。）

## 未来协议规范（每项须先成规范再实现）

- Transaction Spec（字段/编码/签名范围/hash 范围）→ 已实现（STEP 7）。
- Block Spec（Block Hash 生成方式）→ **PHASE 7 DEFERRED**（完整 Block 格式未定义）。
- Network Protocol Spec（Message ID/Version/Encoding/Max Size/Timeout）→ 部分实现（STEP 9）+ STEP 11 集成中。
- RPC API Contract（API Contract First）→ 未实现。
- Consensus Specification → 已冻结（`consensus-spec-v1.md`）。

所有协议变更必须先经 ADR（Master Prompt §4/§7/§83）。
