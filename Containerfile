# =============================================================================
# YAZIMAO L1 — Containerfile（G5-D.6 Container Delivery）
#
# 目标：为 `nova-node / yazimao-node` 提供可复现、最小化、**无秘密注入**的
#       Linux/amd64 容器交付链。
#
# 硬约束（Owner 批准；不得为了"让构建通过"而绕过）：
#   1. Builder 只使用 tracked `Cargo.lock` + `--locked`；**不使用** `--all-targets`。
#   2. 构建上下文**绝不**包含 seed / private key / mnemonic / keystore / genesis /
#      本地 runtime state。本文件不声明任何承载秘密的 `ARG` 或 `ENV`，
#      也不执行任何秘密读取（无 echo/cat/生成）。
#   3. 运行期身份只能来自**外部只读挂载的 seed 文件路径**（CLI 参数形式）。
#   4. 运行期不依赖 `/etc`、`/var`、`/tmp`；全部路径由编排层参数提供。
#   5. 运行进程为 **non-root**（UID/GID 10001）。
#
# 依据（G5-D.5 / G5-D.6 PRECHECK，源码级已确认）：
#   - `nova-node` 生产依赖闭包 = 47 crates，**全部纯 Rust**：无 OpenSSL / rustls /
#     native-tls / SQLite / RocksDB / zlib / curl / git2 / DNS 解析 / 子进程。
#   - **唯一构建期原生依赖** = `cc`（`blake3` 编译 C/asm）⇒ builder 必须有 C 编译器。
#     `cc` 是 build-dependency，**不是**运行期库依赖。
#   - 无 `build.rs`；无 git 依赖；无编译期环境注入（无 vergen/git/sha 注入）。
#   - runtime 需要 `--storage-dir` / `--safety-dir` 可写，且**必须允许 `fs::rename`**
#     （G5-D.4E 已证明：显式 ACL 只有 R/W 而无删除权限 ⇒ `fs::rename` 失败 ⇒
#     第 1 步即 `BackendFailure` / exit 1）。
#   - `--help` / `--version` 为纯 stdout 行为，可用于**无秘密**的交付自检。
#
# 未验证（见 G5-D.6 报告，不得声称已验证）：
#   - 本机无 Docker / buildx ⇒ 本文件**从未真实构建过**（交由 CI Linux 验证）。
#   - 基础镜像 digest pinning: **已 pin**。digest 来源 = Docker Hub registry API
#     （2026-09-25 查询，`architecture=amd64`）：
#       rust:1.96.1-bookworm        sha256:d99f7b31f49909348dc59b51f3c95d1efded1701ffb222f095aaab7de3c4abd8
#       debian:bookworm-slim        sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b
#     **未在本机执行 pull**（无容器运行时）⇒ 实际拉取/构建仍待 CI Linux 验证。
#     维护：基础镜像为安全快照，需按周期重新 pin（属运维项，不在本阶段范围）。
#   - 运行期 non-root 的实际执行、持久卷 rename 语义，均未在本阶段验证。
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder
#   · 平台固定 linux/amd64
#   · Rust 1.96.1（与仓库 `rust-toolchain.toml` 的 channel 一致）
#   · 官方 `rust:1.96.1-bookworm` 基于 `buildpack-deps:bookworm`，其中包含
#     gcc/g++/make —— 即 `cc`（blake3）所需的 C 编译器。
#     下方用一个显式的探测步骤在**构建期**断言该前提，避免在编译阶段才隐式失败。
#     本阶段**不**安装任何额外系统包（保持确定性与可审计性）。
# -----------------------------------------------------------------------------
FROM --platform=linux/amd64 rust:1.96.1-bookworm@sha256:d99f7b31f49909348dc59b51f3c95d1efded1701ffb222f095aaab7de3c4abd8 AS builder

WORKDIR /src

# 构建期断言：C 编译器存在（cc ← blake3）。不产生额外系统包。
RUN cc --version > /dev/null

# 先复制 workspace 清单（最大化依赖层缓存），再复制**最小**源码集合。
#
# 为什么这三项足以构建：
#   · 根 `Cargo.toml` 的 members 覆盖 `crates/*`（12 项）与 `tests/vectors`，
#     三者缺一 cargo 会在 workspace 解析阶段失败；`Cargo.lock` 覆盖全部 134 个包。
#   · `include_str!` / `include_bytes!` 只出现在 **test 目标**（`crates/*/tests/*.rs`，
#     指向 `tests/vectors/**`），生产 `src/` 中为 0 命中；本次只构建 `--bin`
#     目标，因此不需要任何测试向量。
#   · 生产源码对 `docs/` 的引用 = 0 命中。
#
# 明确**不**复制：`.git`、`target`、`nova-web`、`.venv`、`docs`、`simulation`、
# `fuzz`、`benches`、`scripts`、任何 `*.seed` / `*.key` / `*.pem` / `*.mnemonic`、
# 任何本地 runtime state（另见 `.dockerignore` 作为第二道防线）。
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/ ./crates/
COPY tests/vectors/ ./tests/vectors/

# 只构建交付目标：package `nova-node` / bin `yazimao-node`，并强制遵守 Cargo.lock。
# 不使用 `--all-targets`（避免把 dev-dependencies 如 criterion/clap 带入镜像构建）。
# 内联 `CARGO_TERM_COLOR` 而不是 `ENV`，使最终运行期镜像**不含任何 ENV**。
RUN CARGO_TERM_COLOR=never cargo build --release -p nova-node --bin yazimao-node --locked

# -----------------------------------------------------------------------------
# Stage 2 — runtime
#   · 最小化：只含该二进制 + 基础 C 运行库（debian-slim ≡ builder 的 bookworm，glibc 同基线）
#   · 不含 Rust toolchain / cargo / 源码 / Git / seed / key / mnemonic / genesis
#   · 不含 CA 证书包（本节点无 TLS 出站需求）、不含 curl/shell 工具依赖
# -----------------------------------------------------------------------------
FROM --platform=linux/amd64 debian:bookworm-slim@sha256:f3034a6ec3c1205360777c4aae76234998866ad18806ae62b63a3f84ccad782b AS runtime

# 固定 UID/GID：便于持久卷属主、审计与后续编排层保持一致。
RUN groupadd --gid 10001 yazimao \
 && useradd --uid 10001 --gid 10001 --no-create-home --shell /usr/sbin/nologin yazimao

# 运行期目录骨架（**只创建目录，不放置任何内容**）：
#   /storage              —— `--storage-dir`：必须可写、允许 create/write/rename/delete/fsync
#   /safety               —— `--safety-dir`：必须可写、允许 append/fsync（仅 validator 模式需要）
#   /read-only/genesis    —— genesis 公开产物挂载点（只读语义；容器内不写入）
#
# 重要：编排层若在这些路径挂载持久卷，需要保证卷对 UID/GID 10001 可写，
#       且底层文件系统支持 rename（同文件系统 rename）；否则 runtime 会在第 1 步失败。
RUN install -d -o yazimao -g yazimao -m 0750 /storage /safety \
 && install -d -o root -g root -m 0555 /read-only/genesis

# 只从 builder 复制交付二进制。`--chown=root:root` + 0755 ⇒ 任何用户可执行、仅 root 可改。
COPY --from=builder --chown=root:root /src/target/release/yazimao-node /usr/local/bin/yazimao-node
RUN chmod 0755 /usr/local/bin/yazimao-node

# OCI 元数据（静态值；不注入 revision/date 等不确定输入）。
# revision 标注（git SHA）、SBOM 与 provenance attestation 列为后续 hardening 项
# （见 G5-D.6 报告）。
LABEL org.opencontainers.image.title="yazimao-node" \
      org.opencontainers.image.description="YAZIMAO L1 node (nova-node / yazimao-node) — seed / validator / full-node runtime" \
      org.opencontainers.image.source="https://github.com/Cortex-Forest/nova" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.version="0.1.0"

# 运行身份：non-root。
USER 10001:10001

# exec-form ENTRYPOINT：不经 shell ⇒ 不存在 `sh -c` 处理秘密的路径，
# 也不读取 / 回显 / 生成任何 seed，不创建身份，不修改 genesis，不自动发现 peer。
#
# 全部运行期参数必须由外部编排层提供（源码 CLI 契约）：
#   必填 : --genesis <path> --genesis-hash <hex64> --chain-id <u64>
#          --network-id <devnet|testnet|mainnet> --storage-dir <path>
#          --network-seed-file <path>
#   validator 追加: --validator --validator-seed-file <path> --safety-dir <path>
#   可选 : --listen <ip:port> --peer <nodeid_hex@ip:port>（可重复）
#          --idle-ms <1..50>（默认 1） --run-steps <n>（默认 5000；0 = 连续运行）
#
# 秘密只以**文件路径**形式传入（`--network-seed-file` / `--validator-seed-file`），
# 内容由外部只读挂载提供；本镜像内不存在任何 seed。
ENTRYPOINT ["/usr/local/bin/yazimao-node"]

# 默认行为：仅打印用法并 exit 0 —— 用于**无秘密**的交付自检
# （`docker run --rm <image> --help`）。
# 生产编排必须显式提供完整参数以覆盖此默认值。
CMD ["--help"]

# 说明（本阶段不修改 runtime，故在此记录而非修复）：
#   · 不声明 `EXPOSE`：P2P 端口由编排层通过 `--listen` 指定并暴露。
#   · 不提供 `HEALTHCHECK`：当前 node 无已确认的 HTTP health endpoint，
#     伪造探针会引入 curl/HTTP 依赖 ⇒ health/observability 属后续 Gate。
#   · 无 Ctrl-C / SIGTERM 优雅停机（源码 `yazimao-node.rs:21`、HELP `:110`；Cargo.lock 中
#     无 ctrlc/signal-hook/nix）⇒ 容器终止走 OS 默认终止路径，持久化设计为
#     crash-consistent。此项为**已知操作限制**，本阶段不修复。
