# ADR-0003: Validator Signature / Aggregation Scheme

- **Status**: Proposed（待批准）
- **Date**: 2026-08-25
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography

## Context

共识验证者投票需要签名。需评估 **BLS12-381**（支持签名聚合）是否真的适合 V0.1，
不能因为"BLS 支持聚合"就默认采用。评估维度：validator voting、aggregate signatures、
proof of possession（PoP）、rogue-key 保护、序列化、验证性能。

## Decision（建议，待批准）

1. **V0.1：Validator 签名使用 Ed25519**（与账户签名一致；简单、快速、无配对复杂度）。
2. **BLS12-381：标记为 `PLANNED`**——当验证者规模扩大、需要 O(1) 聚合签名时，
   经**新 ADR** 引入（本 ADR 已预先定义其引入条件与安全前置）。
3. 若未来引入 BLS12-381，**强制前置条件**：
   - Proof of Possession（PoP）必须强制（防 rogue-key 攻击）；
   - 明确 Domain Separation Tag（ADR-0005）；
   - 批量验证（multi-pairing）优化必须实现（否则验证性能不可接受）；
   - 库选型 `blst`（Supranational，经过审计，Ethereum Consensus 使用）；
   - 密钥生成需处理聚合公钥偏置风险。

## BLS12-381 评估（为什么不默认采用）

| 维度 | 评估 |
|------|------|
| 聚合收益 | 真实：n 个签名 → 1 个 96B 聚合签名，最终性轮次带宽 O(n)→O(1) |
| V0.1 验证者规模 | 初期 20-50 个验证者，聚合收益有限；O(n) Ed25519 带宽可接受 |
| 验证性能 | 配对运算比 Ed25519 慢约 10-100 倍，需批量验证优化 |
| PoP / rogue-key | 必须强制 PoP，否则攻击者可构造聚合公钥偏置（rogue-key attack） |
| 序列化 | 压缩公钥 48B / 签名 96B，点压缩/解压有开销与失败路径 |
| 库成熟度 | `blst` 成熟且审计过；但复杂度高于 Ed25519 |
| 密钥管理 | 需要 PoP 密钥对分离（signing key vs proof key） |

**结论**：BLS 的聚合优势真实，但在 V0.1 目标（正确执行 / 稳定同步 / 可靠最终确认 / 可审计）下，
其复杂度（配对、PoP、序列化、密钥管理）**超过当前收益**。保留 crypto agility，
待验证者规模与带宽需求证明必要后再引入。

## Alternatives（已评估）

| 方案 | 评估 |
|------|------|
| V0.1 直接 BLS12-381 | 增加配对复杂度与实现风险，收益在小型验证者集下不显著 |
| Ed25519 多签（无聚合） | 简单、快、与账户一致；带宽 O(n)（V0.1 可接受）✅ 采纳 |
| Schnorr 聚合（MuSig） | 需交互式/非交互式聚合设计，V0.1 无必要 |
| 阈值签名（TSS） | 属后续增强，与 V0.1 目标无关，`PLANNED` |

## Consequences

- **正面**：V0.1 密码面最小化；验证者签名与账户签名统一（复用库与审计）；无配对开销。
- **成本**：最终性轮次签名带宽 O(n)（验证者增多后成为扩展瓶颈——届时由 BLS ADR 解决）。
- **可迁移**：BLS 引入是"新增聚合路径"，不改变现有 Ed25519 签名有效性（协议版本化）。

## Security Impact

- Ed25519 无聚合 ⇒ 无 rogue-key 问题；验证者密钥独立。
- 未来 BLS 引入的强制安全前置（PoP / DST / 批量验证 / blst）已在本 ADR 固化，
  防止"为聚合而牺牲安全"。
- 验证者投票必须使用独立于账户签名的域分离（ADR-0005/0010），防跨域重放；签名覆盖见 ADR-0009。
