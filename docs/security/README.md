# Nova Chain 安全文档

## 状态

- PHASE 1 — Project Foundation。
- 本阶段无业务逻辑，安全重点在工程基线与供应链。

## 已落实（PHASE 1）

- 零第三方运行时依赖（无供应链攻击面）。
- 无硬编码密钥/助记词/token；`.gitignore` 兜底（`*.pem`/`*.key`/`*.mnemonic`/`secrets/` 等）。
- CI 权限最小化：`contents: read`；无自托管 runner。
- `unsafe_code = "forbid"`（workspace 级）。
- `Cargo.lock` 提交锁定（可复现、防依赖投毒）。

## 待落实（后续 Phase）

- 每核心模块完成后的 Threat Modeling + Security Review + 攻击面分析（Master Prompt §65）。
- 模糊测试（transaction/block/network/consensus/WASM/RPC，Master Prompt §59-62）。
- 故障注入（kill/partition/disk corruption 等，Master Prompt §63）。
- 安全审计报告分级：CRITICAL/HIGH 不得进入下一阶段（Master Prompt §66）。

## 依赖审查流程（每次新增依赖）

1. 用途 2. 必要性 3. 安全风险/CVE 4. license 5. 维护状态 6. 可否不用（Master Prompt §67）。
