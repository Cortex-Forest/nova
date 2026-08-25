# ADR-0001: Project Foundation — Cargo Workspace 与工程基线

- **Status**: Accepted
- **Date**: 2026-08-25
- **Deciders**: Nova Chain 架构组
- **Scope**: PHASE 1 — Project Foundation

## Context

Nova Chain 需从零建立生产级 Rust Monorepo，作为后续 24 个 Phase（Crypto → … → Mainnet）的地基。
PHASE 1 只建立工程基础，禁止提前实现任何区块链核心功能。

需决策的工程问题：仓库结构、crate 命名、统一版本管理、依赖策略、代码质量工具、
错误处理与日志原则、Feature Flags 机制、配置系统骨架、License。

## Decision

1. **Cargo Workspace + `crates/` 分层结构**：根 `Cargo.toml` 为 workspace，成员为
   `crates/{core,consensus,crypto,execution,network,node,rpc,storage,wallet}`。
   说明：此结构与 Master Prompt §92 的"推荐扁平目录"不同——本阶段以任务书
   （PHASE 1）为权威指令，差异在此记录留痕；如需调整目录，经新 ADR 修订。

2. **统一 `nova-*` 命名**：所有 package 使用 `nova-core`、`nova-consensus` 等前缀。
   理由：避免与标准库 `core` 混淆；依赖声明与日志（`nova::<crate>::<module>`）更清晰；
   降低 dependency confusion 风险。

3. **统一版本管理**：`version/edition/license/rust-version` 全部经 `workspace.package`
   统一管理，各 crate 用 `.workspace = true` 继承。**禁止各 crate 自定版本。**

4. **Workspace Dependency Policy**：所有公共依赖统一声明在 `[workspace.dependencies]`，
   crate 通过 `foo.workspace = true` 引用。**禁止各 crate 自行升级依赖版本。**

5. **`Cargo.lock` 必须提交并锁定**：生产构建使用锁定的依赖版本（Master Prompt §68）。

6. **PHASE 1 零第三方运行时依赖**：crypto/共识/WASM/P2P/DB/钱包 SDK 一律留到对应 Phase
   并在引入前做六项审查（用途/必要性/安全风险/license/维护状态/可否不用）。

7. **依赖方向**：`Application(node,rpc,wallet) → Services(consensus,execution,network) →
   Protocol(core,storage) → Infrastructure(crypto)`，单向无环。
   PHASE 1 各 crate 之间不建立 Cargo 依赖（均为空占位）。

8. **四版本分离**：Software `0.1.0` / Protocol `0.1` / Database `1` / API `v1`，
   各自独立定义，禁止混用。

9. **错误处理基线**：统一 `Result<T,E>`；生产代码禁止 `unwrap()/expect()/panic!`；
   仅允许明确不可恢复的内部不变量失败（须注释理由 + 代码审查）。

10. **日志基线**：structured logging 约定（levels: error/warn/info/debug/trace；
    模块名 `nova::<crate>::<module>`；事件名 `nova.<crate>.<event>`）；禁止生产 `println!`。

11. **Feature Flags 机制**：占位定义 `devnet/testnet/mainnet`（空 feature），
    本阶段不实现任何网络逻辑。

12. **配置系统骨架**：`nova-node` 中定义 `Config`（空结构）+ `ConfigLoader` trait；
    不实现任何具体参数（共识/网络参数归入 Genesis/Governance Parameters）。

13. **License**: **Apache-2.0**（宽松、Rust 生态主流，利于依赖合规；可经新 ADR 改为 MIT）。

14. **工具链与 lints**：`rust-toolchain.toml` 锁定 stable + rustfmt/clippy；
    `[workspace.lints.rust] unsafe_code = "forbid"`（Master Prompt §53）。

## Alternatives（已评估并否决）

| 方案 | 否决原因 |
|------|---------|
| 扁平目录（Master Prompt §92 字面） | 与 PHASE 1 任务书冲突；本阶段以任务书为准，差异已留痕 |
| 多仓库（各产品独立 repo） | 破坏"接口/版本/发布流程统一"（Master Prompt §100） |
| 本阶段即引入 `tracing`/`anyhow` 等依赖 | 无消费方；"不因小功能引入依赖"（Master Prompt §67） |
| 本阶段即建立 crate 间 Cargo 依赖 | 空占位无需要；避免无谓维护负担 |
| crate 名直接用 `core` | 与标准库 `core` 混淆（用户评审意见，已采纳 `nova-core`） |

## Consequences

- **正面**：统一构建/测试/CI/文档；依赖方向从第一天被约束；零依赖降低攻击面；可复现构建；
  统一命名使日志与依赖清晰。
- **负面/成本**：PHASE 1 产出"骨架多于功能"，无可演示业务；未来新增依赖须逐个走六项审查。
- **迁移/回滚**：本阶段无业务代码，结构变动成本极低；后续调整目录经新 ADR。

## Security Impact

- 零外部依赖 ⇒ 本阶段无供应链攻击面。
- 无硬编码 secrets；`.gitignore` 兜底密钥/助记词/token 禁止入库。
- CI 权限最小化（`contents: read`）；`Cargo.lock` 提交锁定版本。
- 依赖方向单向无环，降低未来架构腐化风险。
- `unsafe_code = "forbid"` 强制零 unsafe。
