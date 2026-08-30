# Nova Chain — P7-2 Block Signature Representation Revision Freeze V1

- **Status**: **FROZEN**（P7-2 Revision Final Review / Freeze；2026-08-31）
- **Date**: 2026-08-31
- **Scope**: P7-2 Signature Representation Revision 实现封版（`Block.proposer_signature` 承载 /
  wire / hash exclusion / decode boundary / authority boundary）；P7-3 Block Validation **DEFERRED**。

## 0. 冻结基线（固化）

```
ADR-0042 Block Format V1            FROZEN（P7-1）
ADR-0042 Signature Representation   FROZEN（Amendment，Option B）
P7-2 BlockHash + Canonical Encoding FINAL / IMPLEMENTED（6bdb5b1）
P7-2 Signature Representation       FINAL / IMPLEMENTED（5850288）
P7-2 Revision Final Review          FINAL / FROZEN（本记录）
────────────────────────────────────────────────
Git 基线: HEAD 5850288 · CLEAN
Final Review Gates: fmt / check / clippy / workspace test 全 PASS（重新执行）
Security: 0 Blocker / 0 High / 0 Medium / 0 Low
Protocol Defect: NO · Security Defect: NO
```

## 1. 冻结内容（不得改变除非新 ADR / Protocol Review）

| 项 | 冻结值 |
|---|---|
| Block 结构 | `Block { header, body, proposer_signature }`（无 external fallback / 无第二 signature 字段 / 无 Node-local dependency） |
| `proposer_signature` 类型 | `[u8; 64]`（Ed25519，恰好 64B，定长；非 `Vec<u8>`） |
| Block wire | `canonical_header ‖ canonical_body ‖ proposer_signature(64B)`（无长度前缀 / 无 tag / 无 alternate / 无 optional；missing/truncated/oversized/trailing ⇒ 拒） |
| `block_hash` | `SHA-256(canonical_header ‖ canonical_body)`（**signature ∉ hash input**；signature 改 ⇒ hash 不变） |
| Hash exclusion | `proposer_signature ∉ block_hash input`、`∉ canonical_header`、`∉ canonical_body` |
| Signature coverage（P7-3 用） | version ‖ chain_id ‖ height ‖ parent_hash ‖ finality_reference ‖ transaction_root ‖ state_root ‖ validator_set_hash ‖ timestamp（9 header 字段；不签 body/signature/authority/membership/eligibility/QC） |
| Decode boundary | `decode_block` = structure only；不执行 signature/tx_root/state_root/height/parent/authority/membership/QC verification |
| Signature boundary | decode ≠ verification；本轮只实现 representation/encoding/decoding，不实现 `verify_*` |
| Authority boundary | valid proposer signature ≠ validator membership ≠ authority ≠ eligibility；**A11 = DEFERRED** |
| Layer boundary | Consensus ≠ Execution；Block ≠ BlockReference；Block ≠ QC；QC ≠ P7 Block Pipeline |

## 2. Final Review 结果（R1~R19）

```
ADR Consistency（STEP 1）:
R1 Block representation      PASS
R2 Signature type [u8;64]    PASS
R3 Wire representation       PASS
R4 Hash coverage             PASS（signature ∉ block_hash input）
R5 Signature coverage        PASS（9 header 字段；无新增 body/signature/authority/...）
R6 Decode boundary           PASS（structure only）
R7 Authority boundary        PASS（A11 DEFERRED）
R8 Layer boundary            PASS

Canonical / Malleability（STEP 2）:
R9 canonical uniqueness      PASS
R10 exact signature length   PASS
R11 missing signature 拒     PASS
R12 truncated signature 拒   PASS
R13 oversized signature 拒   PASS
R14 trailing bytes 拒        PASS
R15 deterministic encode     PASS
R16 encode/decode roundtrip  PASS
R17 signature 改 → hash 不变 PASS
R18 header 改 → hash 变      PASS
R19 body 改 → hash 变        PASS
```

## 3. 测试证据（重新运行，非历史输出）

```
nova-core:        56 passed / 0 failed（含 17 block 测试：10 原有 + 7 signature 新增）
workspace:        全 PASS / 0 failed（consensus 121 / execution 105 / core 56 / storage 25 /
                  network 30 / node 12 / vectors 82 等）
```

覆盖测试：`signature_roundtrip_and_exact_64b` / `canonical_encoding_deterministic_with_signature` /
`decode_rejects_missing_signature` / `decode_rejects_truncated_signature` /
`decode_rejects_oversized_signature` / `decode_rejects_trailing_bytes` /
`signature_mutation_does_not_change_hash` / `block_roundtrip` / `modified_field_changes_hash` /
`block_hash_covers_header_and_body_not_signature`。

## 4. 四项 Gate（重新执行）

```
FMT    = PASS
CHECK  = PASS
CLIPPY = PASS
TEST   = PASS（0 failed）
```

## 5. Security Final Review（S1~S10）

```
S1 Hash exclusion                          PASS
S2 Hash integrity                          PASS
S3 Canonical uniqueness                    PASS
S4 Length safety（exactly 64B）             PASS
S5 Trailing rejection                      PASS
S6 Decode/verification boundary            PASS
S7 Authority boundary                      PASS
S8 Layer boundary                          PASS
S9 Signature/hash independence             PASS
S10 Persistence/network self-contained     PASS（wire 自包含：received block ⇒ 可 decode 出完整 header+body+signature）
```

## 6. 边界声明

```
A11            = DEFERRED
QC             = DEFERRED
Consensus      = untouched
block_hash     = UNCHANGED（SHA-256(header‖body)）
P7-3 Block Validation = WAITING AUTHORIZATION
```

---

## 变更记录

| 日期 | 变更 | 依据 |
|---|---|---|
| 2026-08-31 | 初稿：P7-2 Signature Representation Revision Freeze V1（FACT AUDIT / R1~R19 / 测试重跑 / 四项 Gate 重跑 / Security S1~S10 / 冻结内容固化） | 用户授权 P7-2 Revision Final Review / Freeze |
