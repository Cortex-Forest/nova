# nova-crypto

YAZIMAO 密码学基础设施（PHASE 2；哈希 / 域分离 / 签名 / 地址 / Genesis / 交易序列化**已实现**）。

## 状态

- **已实现**：`hash`（STEP 2；`protocol_hash` = SHA-256、`content_hash` = BLAKE3，ADR-0006）、
  `domain`（STEP 3；ADR-0005 / ADR-0010）、`signature` + `key`（STEP 4；Ed25519、OS CSPRNG 无 fallback，
  ADR-0002 / ADR-0003 / ADR-0012）、`address`（STEP 5；Bech32m-derived，ADR-0004）、
  `identity`（STEP 6A/6B；Genesis canonical 编码 / 校验，ADR-0014 ~ ADR-0016）、
  `transaction`（STEP 7C/7D；ADR-0019 / ADR-0020）。
- 算法与边界由 ADR 评审确定（ADR-0003 / ADR-0006 / ADR-0012 / ADR-0013），**不自研算法**。

## 纪律

- 禁止自研算法（Master Prompt §16）。
- 必须使用成熟密码库 + CSPRNG。
- 生产代码禁止 `unsafe`。

## 测试

```bash
cargo test -p nova-crypto
```
