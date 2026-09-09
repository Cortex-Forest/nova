# ADR-0063 — Internal Crate Naming Retention

- 状态：ACCEPTED
- 日期：2026-09-09
- 关联：YAZIMAO PHASE 2（Public Brand Migration）、PHASE 3B（Rust Type Rename）、PHASE 3C（Internal Crate/Package Naming Audit）
- 范围：INTERNAL ENGINEERING NAMING DECISION（非协议冻结；非品牌决策变更）

---

## Status

```
ACCEPTED
```

---

## Context

项目对外公开品牌为 **YAZIMAO（鸭子毛）**，内部开发代号为 **Nova**。

已完成：

- PHASE 2：公开品牌文案 / README / description / module doc 已由 Nova → YAZIMAO（commit `3797bbe`）。
- PHASE 3B：Rust 内部类型重命名 `NovaError → YazimaoError`、`NovaAddressPayload → YazimaoAddressPayload`、`NovaAddress → YazimaoAddress`（commit `f2fa7f7`）。
- PHASE 3C：对内部 Cargo package / Rust crate 命名做了只读影响审计，确认 `nova-*` 属于**内部工程命名层**，与品牌层、协议层相互独立。

当前仍存在：

- 7 个 D8 tracked modified（`crates/network/src/security.rs`、`session.rs`、`crates/node/src/runtime.rs`、`sync_correlator.rs`、`sync_dispatch.rs`、`sync_scheduler.rs`、`crates/node/tests/configured_handshake_tests.rs`）
- 17 项 untracked（D8 E2E、ADR、Genesis、Simulation）
- PHASE 2 / PHASE 3B 的 2 个已提交 commit

---

## Decision

```
YAZIMAO is the public product / protocol-facing brand.

Nova remains the internal engineering codename.

All existing nova-* Cargo package names and nova_* Rust crate names
are retained for the current development lifecycle.

No crate/package rename is performed in the current phase.
```

即：

- **当前保留 `nova-*` 作为内部 Cargo crate/package 名称。**
- **不在当前开发阶段执行 `nova-* → yazimao-*`。**
- **未来首次正式发布 / 对外发布前，若 Owner 仍认为有必要，再进行一次完整、独立、可验证的 crate rename migration。**

---

## Workspace 现状（审计时点）

当前内部 crate / package 集合：

```
nova-core
nova-crypto
nova-consensus
nova-execution
nova-network
nova-node
nova-rpc
nova-runtime
nova-storage
nova-wallet
nova-test-vectors
nova-fuzz
```

其中：

- 10 个主要 workspace members（`crates/{core,crypto,consensus,execution,network,node,rpc,runtime,storage,wallet}`）
- `nova-test-vectors`（`tests/vectors`，含 `gen_*` dev 工具）
- `nova-fuzz`（独立 cargo-fuzz package，非 workspace member；fuzz target 二进制名不含 nova）

workspace metadata：`[workspace.metadata.nova]`（software/protocol/database/api 版本）——无脚本/CI 读取方，非协议身份。

---

## 保留理由（PHASE 3C 审计事实）

### 1. 没有协议收益

Cargo package / crate name：

```
does not enter protocol bytes
```

不会改变：

```
chain_id
network_id
GenesisV1
address encoding (HRP nova/novat/novad, ADDRESS_VERSION, 35B layout, Bech32m)
wire protocol
consensus identifiers
signature domains (DOMAIN_TAG / HANDSHAKE_TAG)
golden vectors
```

### 2. 当前 rename 会干扰 D8

D8 当前仍在开发。crate rename 会触碰 D8 未提交文件中的 `use nova_*` 引用面：

```
runtime.rs
sync_correlator.rs
sync_dispatch.rs
sync_scheduler.rs
configured_handshake_tests.rs
```

（以及其它 D8 相关测试）。因此当前迁移没有必要且会带来 D8 工作区冲突。

### 3. 当前没有外部发布压力

```
No external consumers were identified in the local repository audit.

Actual crates.io publication status was not verified.
```

> 说明：本地配置中除 `fuzz/Cargo.toml` 显式 `publish = false` 外，其余 crate 未设置 `publish` 字段；仓库未设 `repository`/`homepage`。**不得**据此宣称“从未发布”。发布状态为未联网验证。

### 4. 品牌已经足够清晰

- PHASE 2（Public Brand Migration）：公开文案、README、description、module doc → YAZIMAO。
- PHASE 3B（Rust Type Rename）：类型 `YazimaoError` / `YazimaoAddress` / `YazimaoAddressPayload`。

因此 **YAZIMAO 已经是公开品牌**，而 `nova-*` / `nova_*` 属于内部工程命名。

---

## Rename 成本（审计时点观察值，非永久承诺）

以下数量为 **audit-time observations and may change as the codebase evolves**：

```
≈908 nova_* Rust import references
≈30 Cargo dependency declarations
Cargo.lock workspace references
README / crate README references (e.g. `cargo test -p nova-*`)
fuzz / vector tooling references
D8 未提交工作区存在交叉引用
```

---

## 协议身份继续冻结（不得因品牌迁移修改）

以下绝对不能被品牌 / crate rename 触碰：

```
b"Nova/network-message/v1"
b"Nova/network-handshake/v1"

nova
novat
novad

ADDRESS_VERSION

DomainId
AlgorithmId

chain_id
network_id

GenesisV1

wire identifiers
serialization identifiers
consensus identifiers

golden vectors

NOVASAFE
```

```
Historical protocol identity must remain intact.
```

本 ADR 是 INTERNAL ENGINEERING NAMING DECISION，**不是**对协议冻结的任何放宽或授权。

---

## 未来何时重新考虑 rename

使用事件触发（不写死日期）：

```
Reconsider before first public package release,
or before any externally consumed SDK/library publication,
or when the repository reaches a stable release boundary.
```

即：**不是现在改，而是在真正对外发布前重新评估。**

---

## 未来迁移原则（设计记录，不执行）

若未来 Owner 决定 rename（例如 `nova-core → yazimao-core`），必须作为**独立 migration phase**：

1. 先完成 D8（建立 clean working tree）
2. 建立单独 migration branch/commit
3. 修改 Cargo package names
4. 修改 Rust crate imports（`nova_*`）
5. 更新 Cargo.lock
6. 更新内部命令（`cargo test -p …`）
7. 更新非历史开发文档
8. 保留历史 ADR / protocol identity
9. 保留 protocol bytes
10. 保留 HRP（nova/novat/novad）
11. 保留 golden vectors
12. 保留 NOVASAFE

最终验证门禁：

```
cargo fmt
cargo check --workspace --all-targets --all-features
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

---

## 防止未来误解

```
Keeping nova-* does NOT mean the public brand is Nova.

YAZIMAO remains the public brand.

Nova is retained only as an internal engineering identifier.
```

以及：

```
This ADR does NOT authorize changing protocol identifiers.
```

历史 ADR / 协议规范 / 审计文档中出现的 `Nova`、`nova-core`、`nova-crypto` 等应保持历史准确性，不做批量改写。若需说明，可引用本 ADR 中的表述：

```
YAZIMAO is the current public brand; Nova is the historical/internal engineering codename.
```

---

## Consequences

- 短期：不产生 crate rename 工作；D8 / consensus / network 等开发不被命名迁移干扰。
- 长期：首次对外发布前存在一次一次性、全量、可验证的 crate rename 迁移窗口；迁移成本与当前做相同，但可避免与 D8 及在研模块冲突。
- 协议身份、地址编码、签名域、golden vectors、NOVASAFE 持续冻结。

---

## References

- YAZIMAO PHASE 2 — Public Brand Migration（commit `3797bbe`）
- YAZIMAO PHASE 3B — Rust Internal Type Rename（commit `f2fa7f7`）
- YAZIMAO PHASE 3C — Internal Crate / Package Naming Audit（README-only design）
