# nova-crypto

Nova Chain 密码学基础设施（**PHASE 1 占位**）。

## 状态

- `NOT IMPLEMENTED`（无任何密码学逻辑）。
- 选型待 **ADR-0003**：Ed25519 / secp256k1 / BLS12-381 / hash / CSPRNG。

## 纪律

- 禁止自研算法（Master Prompt §16）。
- 必须使用成熟密码库 + CSPRNG。
- 生产代码禁止 `unsafe`。

## 测试

```bash
cargo test -p nova-crypto
```
