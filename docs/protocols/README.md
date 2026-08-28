# Nova Chain 协议文档

## 状态

- PHASE 1 — Project Foundation（PASS）。
- PHASE 2 — Cryptography（进行中）：以下协议已冻结（Frozen，待批准）：
  - `crypto-serialization-v1.md`（统一 canonical 编码 / 签名流水线）
  - `crypto-test-vectors-v1.md`（确定性测试向量规范）
  - `genesis-v1.md`（Genesis schema V1：嵌套类型 ValidatorInit / AccountInit /
    ProtocolParamsV1 / EconomicsParamsV1 已按 ADR-0014/0015/0016 冻结）
- 共识 / 交易 / 区块 / 网络 / RPC：均为 `NOT IMPLEMENTED`（等各自 Phase）。

## 已冻结协议规范

| 规范 | 状态 | 内容 |
|------|------|------|
| `crypto-serialization-v1.md` | Frozen | 字节序（LE）/ 长度（u32 LE）/ 定长 bytes / Option / Enum / 字段顺序 / 禁止表示 / 签名流水线 |
| `genesis-v1.md` | Frozen | GenesisV1 schema、嵌套类型、校验规则、`genesis_hash`、链身份三职责分离 |
| `crypto-test-vectors-v1.md` | Frozen | Address / Domain / Signature / Genesis 向量规范 |

## 草稿协议规范（Draft）

| 规范 | 状态 | 内容 |
|------|------|------|
| `consensus-spec-v1.md` | Draft | BFT Round 当前规则（height/round/proposal/prevote/precommit/quorum/finalization boundary）、Byzantine model、honest validator assumption、safety argument、liveness 边界、scope boundary（STEP 10-5.1 创建） |

## 未来协议规范（每项须先成规范再实现）

- Consensus Specification（PoS 安全模型 / DAG↔BFT 桥接 / Finality 条件）→ 草稿已建，见 `consensus-spec-v1.md`
- Transaction Spec（字段/编码/签名范围/hash 范围，Master Prompt §9）。
- Block Spec（Block Hash 生成方式，Master Prompt §23）。
- Network Protocol Spec（Message ID/Version/Encoding/Max Size/Timeout，Master Prompt §21）。
- RPC API Contract（API Contract First，Master Prompt §94）。

所有协议变更必须先经 ADR（Master Prompt §4/§7/§83）。
