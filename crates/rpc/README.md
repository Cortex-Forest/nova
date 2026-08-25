# nova-rpc

Nova Chain RPC / API 层（**PHASE 1 占位**）。

## 状态

- 当前仅定义 API 版本常量 `API_VERSION = "v1"`。
- RPC 服务 / 统一接口契约：`NOT IMPLEMENTED`（待 ADR-0011 + PHASE 13）。

## 纪律

- API Contract First（Master Prompt §94）。
- 公共 RPC 与 Validator 管理 API 分离（Master Prompt §43）。
- 版本化：`/api/v1` → `/api/v2`，禁止破坏旧 API（Master Prompt §44）。

## 测试

```bash
cargo test -p nova-rpc
```
