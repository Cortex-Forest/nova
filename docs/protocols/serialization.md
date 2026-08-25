# Nova Chain Serialization（总览）

- **Status**: 已由 `crypto-serialization-v1.md` **冻结**（2026-08-26）
- **权威规范**：`docs/protocols/crypto-serialization-v1.md` —— 协议代码**必须严格依赖该文件**。
- 本文档为总览/索引；若与冻结文件冲突，**以冻结文件为准**。
- 原则：**统一编码，禁止不同模块各自定义编码**（Master Prompt §22）。

## 1. 统一字节序

- **协议二进制统一使用 little-endian（LE）** 用于多字节整数。
- **例外**：bech32m 地址文本编码内部按 bech32 规范（大端整数），但地址作为"不透明字节串"处理，
  不参与协议整数解析。
- 理由：与 Rust 原生/`bincode` 默认一致，减少实现转换错误；跨平台行为确定（规范明确即可）。
- **已冻结**：全链统一 little-endian（`crypto-serialization-v1.md` §1）。

## 2. Canonical 编码规则

1. 优先使用**固定长度**字段（哈希 32B、pubkey、签名等），长度不歧义。
2. 变长数据使用显式长度前缀：`u32 LE`（4 字节）。
3. 禁止"自解释"编码（如带 tag 的变长）作为协议默认——保持确定性。
4. 编码必须**唯一可解码**（canonical）：同一对象只有一种合法字节表示（防 malleability）。

## 3. 密码学对象编码

| 对象 | 编码 | 大小 |
|------|------|------|
| 协议哈希（SHA-256） | 原始 32 字节 | 32 B |
| Ed25519 公钥 | 压缩点（y 坐标 + 符号位） | 32 B |
| secp256k1 公钥 | 压缩点（`0x02/0x03 \|\| x`） | 33 B |
| Ed25519 签名 | `R(32) \|\| S(32)` | 64 B |
| secp256k1 签名 | `r(32) \|\| s(32)`（**不用 DER**，归一化 s） | 64 B |
| 地址 | Nova Custom Address Format using Bech32m-derived encoding（`nova1...`，内部 35 B payload，见 ADR-0004） | 由 HRP+5-bit+checksum 确定 |
| 密钥材料 | 私钥 32 B；助记词按 BIP-39（不落盘） | — |

## 4. 地址编码（ADR-0004 NovaAddressPayload）

```
address_version(1) || address_type(1) || network_id(1) || key_hash(32)  →  35 bytes
```
经 **Bech32m-derived** 编码（HRP 网络特定，ADR-0011）为文本；校验码复用 Bech32m BCH 校验机制，
但**不声称 BIP-350 兼容**（Nova Custom Address Format）。

## 5. 签名消息构造（冻结，ADR-0005）

```
signed_bytes = algorithm_id(1B) || domain_id(1B) || chain_id(8B LE)
               || payload_length(4B LE) || payload(canonical)
message_hash = SHA-256(signed_bytes)
```
- 字段顺序固定，禁止重排；`algorithm_id` 进入 signed bytes（ADR-0012）。
- `payload` 为签名覆盖字段的 canonical 编码（ADR-0009）；链身份见 ADR-0010/0011。
- 权威定义见 `crypto-serialization-v1.md` §10。

## 6. 一致性要求

- 所有 P2P 消息、RPC 参数、Storage key/value、序列化测试夹具（API Contract First，
  Master Prompt §94）必须遵循 `crypto-serialization-v1.md`。
- 任何模块不得引入自己的编码约定；偏离须经 ADR。

## 7. 待办（PHASE 4 前）

- 定义 transaction 的逐字段 canonical 编码（PHASE 4 + ADR）。
- 定义 block / vote 的 canonical 编码（PHASE 7/9/10 + ADR）。
- 为编码/解码建立 property + fuzz 测试（PHASE 2 起对密码学对象）。
