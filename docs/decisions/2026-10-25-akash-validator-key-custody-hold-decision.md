# Akash Validator Key-Custody Hold — Stage Decision Record — 2026-10-25

| 字段 | 值 |
|---|---|
| **Record ID** | `NOVA-SDR-2026-10-25-AKASH-KEY-CUSTODY` |
| **Title** | Akash Validator 部署暂停（密钥托管未解决）阶段性决策记录 |
| **Type** | Stage Decision Record（**非规范性 / Non-Normative**；不修改任何既有 ADR、规范、源码、测试） |
| **Status** | **PROPOSED / DRAFT — 未经 Owner 批准**（本文件不构成任何实现、部署或解锁授权） |
| **Date** | 2026-10-25 |
| **Repo / Branch** | `C:\Users\Administrator\nova` · `main` |
| **HEAD at writing** | `851dfdd5d984db5ca4c6e3ebb21647a18f663e8e`（`origin/main` 同点，ahead/behind `0/0`） |
| **Related (未修改)** | `ADR-0054`（node lifecycle）、`ADR-0065`（validator safety init fail-closed）、`ADR-0013`（签名域分离） |
| **Evidence** | `%TEMP%\nova-secbound-probe-20261025T021919Z\security-delivery-verdict.md`（判定 `BLOCKED_SECURITY`）<br>`%TEMP%\nova-identity-probe-20261025T021123Z\identity-secrets-decision.md`（seed 语义与匹配结论） |

> 本记录只做一件事：把「Akash Validator 因密钥托管未解决而暂停」这一阶段性结论固定为可复查记录。
> 它**不是**协议规范、**不是** Testnet 发布批准、**不是** 任何实现的授权。

---

## 1. 已确认的 Owner 边界（本记录的前提，不再讨论）

> **不接受任何 Akash Provider 能够读取 Validator 私钥的部署方案。**

该边界排除了以下全部路线（详见证据报告 §B）：镜像层内置私钥、`env`、SDL 明文/Base64、
镜像内 `0444` 只读文件、普通持久化卷、容器启动时生成并落盘。

---

## 2. 四项阶段性结论

### 2.1 本地 disposable devnet：有限运行验证通过（有限，不等于稳定）

| 项 | 值 |
|---|---|
| 材料 | 既有一次性 devnet（`genesis` hash `76d9b719cf82ccc857c5c5c27c2aa820d14c81cd82d28c6f14615f9e4826550b`，chain 3004 / devnet / 1 validator） |
| 运行 | `--run-steps 5`，退出码 **0** |
| 结果 | `head_height=2`、`finalized_height=2`、`consensus_height=2` |
| 负控 A | 两角色共用同一 seed ⇒ exit **1** `Identity(NetworkAndValidatorIdentityMustDiffer)` |
| 负控 B | seed 与 genesis ValidatorSet 不匹配 ⇒ exit **1** `Identity(ValidatorNotInValidatorSet)` |
| observer 对照 | 不带 validator seed ⇒ exit 0，但 `head_height=0 finalized_height=none`（不产块） |

**边界**：仅证明「Windows 本地 + 指定输入」下的单节点有限执行；
**不**证明 Linux 容器、Akash 部署、长期稳定性、多节点共识或公网连通。

### 2.2 Akash Validator：密钥安全交付未解决 ⇒ 暂停部署准备

- 节点**唯一已实现**的签名载体为进程内软件私钥：
  `SeedKeyProvider`/`SeedSigner`（`crates/node/src/bin/yazimao-node.rs` L703、L727）、
  `SoftwareSigner`（`crates/node/src/signer.rs` L52）。
- HSM / remote signer / Cloud KMS **明确未实现**：
  `crates/node/src/key_provider.rs` L1-L13（"DEFERRED"）、`KeyProviderError::Unavailable` L31-L34；
  `KeyProviderConfig` 仅 `None`/`Software`（L39-L49）；CLI 无相关参数。
- 平台侧无秘密注入：官方 SDL `services` 字段仅
  `image`/`command`&`args`/`env`/`expose`/`credentials`/`params`；
  官方 Providers & Leases 文档述明 Provider 负责运行容器、manifest 含 env 与私有镜像凭据明文送达、
  部分 Provider 提供 shell 访问。

⇒ 判定 `BLOCKED_SECURITY`。**在此之前，Akash Validator 部署准备（含派生镜像、SDL 可部署化、Air 提交）暂停。**

### 2.3 远程签名器：需独立 ADR 与可信主机，当前不实施

若要重新满足 Owner 边界，唯一候选是「私钥不出可信边界、节点仅获取签名」的外部签名器。其前置条件：

1. 独立 ADR（签名授权设计：请求鉴权、身份绑定、允许签名的域/高度/轮次范围）；
2. **签名服务侧 slashing protection**（节点侧 safety journal 位于不受信的 Provider 上，
   否则恶意 Provider 可索取冲突签名 ⇒ 双签风险外溢）；
3. 一台**不受 Provider 控制**的可信签名主机（新增外部依赖）；
4. 失败语义（超时/重试/断连/重启恢复）与对共识活性影响的评估；
5. 该 ADR 通过评审后，才可在 `KeyProvider` seam 下实现并测试。

### 2.4 正式 Testnet Genesis：不在本轮范围

现有 `genesis-image/genesis.bin`（sha256 `c9a823c6…`，chain 3004 / devnet）仅为**仓库测试 fixture**，
不是正式 Testnet Genesis；其验证者公钥**没有**对应的 seed 材料存在于仓库或证据目录
（负控 `ValidatorNotInValidatorSet` 已证）。正式 Genesis 的冻结与身份材料生成均**不属于**本记录范围。

---

## 3. 重新开启 Akash Validator 部署准备的必要条件（全部满足才可）

- [ ] 出现**可验证**的安全交付能力（平台侧机密计算/秘密注入且能实测证明 Provider 不可读），**或**
- [ ] 远程签名器 ADR 获批 + 可信签名主机就位 + 实现与测试通过（含 slashing protection 与鉴权负控）；
- [ ] 具备该方案下「Provider 无法读取私钥」的**可复现验证证据**（而非文档推断）；
- [ ] Owner 对部署与费用另行明确授权。

---

## 4. 本记录不授权的事项

不授权：修改共识/协议/正式 Genesis/经济参数/验证者集合；生成或替换任何身份密钥；
构建或推送镜像；Akash 部署、租约、付费；`git add/commit/push`；实现远程签名器。

---

## 5. 证据索引（可复查，不含任何秘密）

| 证据 | 位置 |
|---|---|
| 密钥交付判定（`BLOCKED_SECURITY`，含路线矩阵与官方文档引用） | `%TEMP%\nova-secbound-probe-20261025T021919Z\security-delivery-verdict.md` |
| 运行探针日志（P1 observer / P2 validator / P3、P4 负控） | 同上目录 `P1..P4.{out,err}.log` |
| seed 语义、Genesis 匹配规则、材料清单（仅元数据） | `%TEMP%\nova-identity-probe-20261025T021123Z\identity-secrets-decision.md` |
| 镜像身份事实（digest、ELF 架构、非 root、无秘密） | `%TEMP%\nova-akash-single-release-20261024T140155Z\build-result.md` |

---

## 6. 状态汇总

```
LOCAL_DISPOSABLE_DEVNET = VERIFIED (limited: 5 steps, Windows, single node)
AKASH_VALIDATOR         = BLOCKED_SECURITY (key custody unsolved)
REMOTE_SIGNER           = NOT IMPLEMENTED (needs separate ADR + trusted host)
FORMAL_TESTNET_GENESIS  = OUT OF SCOPE (unmodified)
DEPLOYMENT              = NOT_RUN (not authorized)
```
