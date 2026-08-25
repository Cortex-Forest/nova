# Nova Chain 密码学威胁模型（Cryptographic Threat Model）

- **Status**: Proposed（待批准）
- **Date**: 2026-08-25
- **Scope**: PHASE 2 — Cryptography
- 关联：ADR-0002/0003/0004/0005/0006/0007/0008/0009/0010/0011/0012、`docs/protocols/crypto-serialization-v1.md`

## 1. 威胁清单与缓解

| # | 威胁 | 影响 | 缓解（对应 ADR/机制） |
|---|------|------|----------------------|
| T1 | 私钥窃取（设备/存储） | 资产被盗 | 加密存储 + 平台 Keystore/Keychain；私钥不上传（ADR-0007） |
| T2 | 侧信道（时序/功耗） | 密钥泄漏 | 使用恒定时间实现（成熟密码库，禁止自研，ADR-0002/§H） |
| T3 | nonce 偏置 / 复用 | 私钥恢复（ECDSA） | 默认 Ed25519 确定性签名；secp256k1 强制 RFC 6979（ADR-0002） |
| T4 | 签名 malleability | 交易/投票变形重放 | Ed25519 无 malleability；secp256k1 签名归一化（ADR-0002） |
| T5 | 恶意网页 / 钓鱼签名 | 无感知授权 | 签名前明确展示交易内容（ADR-0007 §Use，Master Prompt §49） |
| T6 | 同链重放 | 重复执行 | nonce + 账户状态（PHASE 4） |
| T7 | 跨链重放 | 在另一链重放 | chain_id + DST 域分离（ADR-0005） |
| T8 | 跨网重放（mainnet↔testnet） | 测试网攻击主网 | network_id（地址，ADR-0004）+ chain_id |
| T9 | 随机数失败（CSPRNG 故障） | 密钥/签名不安全 | 强制 `OsRng`；禁止普通 RNG（ADR-0007） |
| T10 | Rogue-key 攻击（若引入 BLS 聚合） | 聚合公钥偏置 | **强制 PoP**（ADR-0003 前置条件，V0.1 用 Ed25519 无此问题） |
| T11 | 供应链（恶意依赖/投毒） | 广泛破坏 | 依赖六项审查 + Cargo.lock 锁定（PHASE 1）；密码库选型审查（§H） |
| T12 | 量子计算（远期） | 打破 ECC/DH/签名 | 非当前威胁（见安全假设）；crypto agility：address_type + pubkey hash 架构（ADR-0004） |
| T13 | 助记词泄露 / 丢失 | 账户完全失守 / 永久丢失 | 离线物理备份 + 恢复流程文档（ADR-0007） |
| T14 | 长度扩展攻击 | 承诺/签名消息歧义 | 定长 DST 前缀 + SHA-256 承诺（ADR-0005/0006） |

## 1b. 补充威胁（PHASE 2 设计评审新增）

| # | 威胁 | 影响 | 缓解（对应 ADR） |
|---|------|------|------------------|
| T15 | canonical encoding attack（编码歧义/非规范表示） | 同一对象多字节表示 ⇒ 状态分歧 | canonical 编码规范 + 唯一可解码（crypto-serialization-v1.md；ADR-0005 无歧义证明） |
| T16 | algorithm confusion attack（算法混淆） | 用错误算法验证签名 | address_type↔算法强绑定（ADR-0008）；DST 区分 |
| T17 | address type confusion（地址类型混淆） | 错误解析地址语义 | 未注册类型拒绝（ADR-0008）；解码规则（ADR-0004） |
| T18 | cross-network replay（跨网重放） | testnet tx 在 mainnet 重放 | chain_id 签名绑定 + network_id 地址校验（ADR-0010） |
| T19 | domain collision（域碰撞） | 不同对象签名消息相同 | 定长 DST + chain_id + 长度前缀 payload（ADR-0005 无歧义证明） |
| T20 | signature coverage bug（签名覆盖缺陷） | 改未签名字段不被检测 | 显式字段级签名覆盖清单（ADR-0009）+ 篡改检测测试 |
| T21 | malformed signature（畸形签名） | 实现不一致 / DoS | Canonical Signature Encoding + Strict Verification + Malformed Input Rejection（ADR-0002） |
| T22 | key/hash substitution（密钥/哈希替换） | 用攻击者密钥/哈希替换 | 公钥/哈希编码固定 + 域分离 + 地址 type 强绑定（ADR-0004/0008） |

## 2. 密钥材料生命周期（Key Material Lifecycle）

```
Generate ──► Store ──► Use ──► Rotate ──► Revoke ──► Recover
```

| 环节 | 安全要求 |
|------|---------|
| Generate | CSPRNG（OsRng）；种子 → 助记词（BIP-39）→ HD 密钥（标准派生） |
| Store | 加密存储；内存 `zeroize`；平台安全存储；私钥永不明文落盘/上传 |
| Use | 最小暴露；签名前明确展示；恒定时间；不记录密钥到日志（Master Prompt §55） |
| Rotate | 旧 key 授权签名 + 链上提交；安全间隔；地址不变（pubkey hash） |
| Revoke | 链上可验证撤销记录；旧 key 立即失效 |
| Recover | 助记词恢复（自托管）；无第三方托管 |

## 3. 安全假设（Security Assumptions）

1. **私钥保密性**：攻击者无法在设备被攻破前获得私钥；私钥持有者对其保密负责。
2. **CSPRNG 正确**：系统 RNG 未被破坏（`OsRng` 底层假设）。
3. **签名方案底层安全**：Ed25519 依赖椭圆曲线离散对数问题与随机预言模型假设；
   未来 BLS12-381 依赖 co-CDH 假设（引入时经 ADR）。
4. **无量子计算攻击者（当前）**：量子威胁为远期；当前定位为"成熟密码学优先 + 未来密码学灵活性"
   （crypto agility），**不声称"量子安全 / 不可破解 / 绝对安全"**。
5. **验证者诚实大多数**：共识层安全模型（PHASE 9/10 定义 f、quorum 等）。
6. **供应链受控**：依赖经审查、版本锁定、`unsafe` 禁用。
7. **哈希安全**：SHA-256 抗碰撞（当前公认安全强度）。

## 4. 明确不声称

- ❌ "量子安全" / "量子抗性"
- ❌ "不可破解" / "绝对安全" / "军用级"
- ❌ "100% 防攻击"

任何此类表述必须有独立密码学依据（Master Prompt §15）。

## 5. 后续（各 Phase）

- 模糊测试：transaction/serialization/block/network/consensus/WASM/RPC（Master Prompt §59-62）。
- 故障注入：kill/partition/disk corruption/clock skew（Master Prompt §63）。
- 核心模块完成后的 Threat Modeling + Security Review + 攻击面分析（Master Prompt §65）。
- 外部安全审计（独立第三方）。
