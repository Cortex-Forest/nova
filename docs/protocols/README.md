# Nova Chain 协议文档

## 状态

- PHASE 1 — Project Foundation。
- **尚无任何协议规范落地**（共识/交易/区块/网络均为 `NOT IMPLEMENTED`）。

## 未来协议规范（每项须先成规范再实现）

- Consensus Specification（PoS 安全模型 / DAG↔BFT 桥接 / Finality 条件）。
- Canonical Serialization Specification（统一编码 / endianness / versioning，Master Prompt §22）。
- Transaction Spec（字段/编码/签名范围/hash 范围，Master Prompt §9）。
- Block Spec（Block Hash 生成方式，Master Prompt §23）。
- Network Protocol Spec（Message ID/Version/Encoding/Max Size/Timeout，Master Prompt §21）。
- RPC API Contract（API Contract First，Master Prompt §94）。

所有协议变更必须先经 ADR（Master Prompt §4/§7/§83）。
