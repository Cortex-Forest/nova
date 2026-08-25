# nova-wallet

Nova Chain 钱包核心（**PHASE 1 占位**）。

## 状态

- `NOT IMPLEMENTED`（无任何钱包逻辑）。
- 待对应 PHASE（PHASE 15）+ ADR（HD Wallet / 密钥管理 / 签名）。

## 纪律

- 私钥本地保存、默认不上传服务器（Master Prompt §18）。
- HD Wallet 遵循标准，不自创规则（Master Prompt §19）。
- Wallet 与 Node 职责分离（Master Prompt §98）。

## 测试

```bash
cargo test -p nova-wallet
```
