# Nova Chain — P7-3 Block Validation Final Freeze V1

- **Status**: **FROZEN**（P7-3 Block Validation Final Review / Freeze；2026-08-31）
- **Date**: 2026-08-31
- **Scope**: P7-3 Block Validation 实现封版（验证顺序 ①结构→②签名→③tx_root→④state_root→⑤height/parent；
  D1~D6 冻结；decode ≠ semantic；authority boundary）。

## 0. 冻结基线（固化）

```
ADR-0042 Block Format V1            FROZEN（P7-1）
ADR-0042 Signature Representation   FROZEN（Amendment，Option B）
P7-3 Block Validation Design        FROZEN（80a5bfe）
P7-3 Block Validation               FINAL / IMPLEMENTED（c630d8c）
P7-3 Final Review                   FINAL / FROZEN（本记录）
────────────────────────────────────────────────
Git 基线: HEAD c630d8c · CLEAN
Final Review Gates（重跑）: fmt / check / clippy / workspace test 全 PASS
Security: 0 Blocker / 0 High / 0 Medium / 0 Low
Protocol Defect: NO · Security Defect: NO
```

## 1. 冻结内容（不得改变除非新 ADR / Protocol Review）

| 项 | 冻结值 |
|---|---|
| 验证顺序 | ① 结构（decode）→ ② proposer signature → ③ transaction_root → ④ state_root → ⑤ height/parent（ADR-0042 §9；任一 FAIL ⇒ Reject） |
| `verify_block_signature` | ② 纯密码学验证：payload = `canonical_header`（9 header 字段）；`DomainId::Block = 0x03` 域分离；`verify_strict`；**不查询 ValidatorSet / 不做 membership / authority / eligibility**（D2/D3；A11 DEFERRED） |
| `compute_transaction_root` / `verify_transaction_root` | ③ Merkle（D4）：TX_EMPTY=0x20 / TX_LEAF=0x21 / TX_BRANCH=0x22；空=protocol_hash(0x20) 常数；leaf/branch 公式冻结；两两配对；奇数复制自身；len==1 即 root；顺序 = block body 顺序；无 alternate |
| `ParentContext` / `verify_height_parent` | ⑤（D6）：`{ parent_height, parent_hash }`；`height == parent_height+1`（checked_add 防溢出）**AND** `parent_hash == parent_hash`，缺一不可 |
| ④ state_root | 复用 8D（`execute_block` + `calculate_state_root` + `verify_block_state_root`）；编排由调用方完成（D1=C）；nova-core 不重造 |
| `BlockValidationError` | 4 变体（InvalidProposerSignature / TransactionRootMismatch / InvalidHeightChain / ParentHashMismatch）；仅分类编码，不改变 ADR-0042 rejection 语义（D5；ADR impact review 通过，不改 ADR-0042） |
| decode boundary | `decode_block` = structure only；不执行 signature/tx_root/state_root/height/parent 验证 |
| authority boundary | valid proposer signature ≠ validator membership ≠ authority ≠ eligibility；A11 = DEFERRED |
| layer boundary | Block ≠ BlockReference ≠ QC；Consensus ≠ Execution；QC 不进 P7 pipeline |

## 2. Final Review 结果

```
FACT AUDIT:       PASS（block.rs 当前内容与冻结设计一致；Git CLEAN）
协议一致性（R）:   R1~R8 全 PASS
测试证据（重跑）:  nova-core 63 passed / 0 failed（含 33 block 测试）
                  workspace 全 PASS / 0 failed
四项 Gate（重跑）: FMT / CHECK / CLIPPY / TEST 全 PASS
Security:         S1~S10 全 PASS
Git Scope:        PASS（仅 crates/core/src/block.rs，c630d8c）
```

## 3. 测试覆盖（33 block tests）

- 结构/decode 回归：roundtrip / malformed / version / tag / missing/truncated/oversized/trailing signature（P7-2，17）
- ② 签名（6）：ok / tamper header / 错误 proposer key / 错误 chain_id / 错误 domain（0x02）/ 无效签名 bytes
- ③ tx_root（6）：empty 常数 / single=leaf / pair+odd(2/3/4) / order-sensitive / verify ok / verify mismatch
- ⑤ height/parent（4）：ok / height 不连续 / parent_hash mismatch / parent_height 溢出

## 4. 边界声明

```
A11            = DEFERRED
QC             = DEFERRED（不进 P7 pipeline）
Consensus      = untouched
block_hash     = UNCHANGED（SHA-256(header‖body)，signature ∉ hash input）
P7-2 Revision  = FINAL / FROZEN
P7-3 Block Validation = FINAL / FROZEN
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-3 Block Validation Final Freeze V1（FACT AUDIT / R1~R8 / 测试重跑 / 四项 Gate 重跑 / Security S1~S10 / 冻结内容固化） | 用户授权 P7-3 Final Review / Freeze |
