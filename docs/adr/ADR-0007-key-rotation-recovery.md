# ADR-0007: Key Rotation / Recovery Strategy

- **Status**: Proposed（待批准）
- **Date**: 2026-08-25
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 2 — Cryptography

## Context

密钥不是永恒的。必须定义密钥生命周期：生成、存储、使用、轮换、撤销、恢复，
并明确**什么情况下允许更换密钥**。

## Decision（建议，待批准）

### 生命周期

```
Generate → Store → Use → Rotate → Revoke → Recover
```

| 阶段 | 策略 |
|------|------|
| **Generate** | 必须使用 CSPRNG（`OsRng`）；禁止普通 RNG（Master Prompt §16）；私钥从不以明文外传 |
| **Store** | 敏感密钥加密存储；内存中密钥用 `zeroize` 清零；移动端使用平台安全存储（Android Keystore / iOS Keychain）；桌面端加密文件（如 `~/.nova/` 权限 0600） |
| **Use** | 签名最小暴露；钱包签名前**明确展示**交易内容（网络/chain_id/接收方/金额/gas/data，Master Prompt §49），防恶意网页签名与钓鱼 |
| **Rotate** | 见下方"允许换 key 的条件" |
| **Revoke** | 链上记录撤销；撤销后旧 key 签名必须无效（配合 nonce/账户状态） |
| **Recover** | BIP-39 助记词 + 标准 HD 派生（不自创规则，Master Prompt §19）；无第三方托管；助记词离线备份为最高权限恢复路径 |

### 允许换 key 的条件

1. **账户签名 key 轮换**：由持有者发起，**旧 key 对新 pubkey 做授权签名**，经链上交易提交；
   新 key 生效前存在安全间隔（防抢跑）。V0.1 协议层：`PLANNED`。
2. **Validator key 轮换**：需共识协议机制（active 验证者换签名 key 不改变 stake 归属）。
   V0.1 协议层：`PLANNED`。
3. **私钥疑似泄露**：立即撤销 + 用恢复路径（助记词）派生新 key；链上标记旧 key 失效。
4. **迁移到新签名算法**（如未来后量子）：新增 `address_type`（ADR-0004），地址不变；
   需新 ADR 定义迁移协议。

### 明确不做（V0.1）

- 不做第三方托管/社交恢复（`PLANNED`，需治理与经济模型设计）。
- 不做链上自动 key 过期（需协议设计）。

## Consequences

- **正面**：明确生命周期与轮换/恢复路径；私钥本地持有、不上传（Master Prompt §18）。
- **成本**：助记词管理责任在用户（需清晰的 UX 与文档）；轮换机制 V0.1 为 PLANNED。
- **可迁移**：地址用 pubkey hash，key 轮换不改变地址。

## Security Impact

- 私钥永不离开设备；助记词为最高权限恢复路径，须离线物理备份。
- 恶意网页/钓鱼通过"签名前明确展示"缓解。
- 轮换授权需防重放：授权消息必须带 DST + chain_id + 新 key + nonce（ADR-0005 + PHASE 4）。
- 撤销记录必须链上可验证（轻节点可验证，Master Prompt §25）。
