//! Nova Chain 共识层（STEP 10 — Consensus；ADR-0033/0034/0035）。
//!
//! # 模块
//! - [`validator`]：**STEP 10-2**——`ValidatorId`/`ValidatorInfo`/`ValidatorSet`（ADR-0034 V-1~V-3）。
//! - [`vote`]：**STEP 10-2**——`ValidatorVote` + `verify_vote`（ADR-0034 V-4/V-5）。
//! - [`dag`]：**STEP 10-3**——`BlockReference`/`Dag`/`causal_order`（ADR-0035 D-1~D-3）。
//! - [`witness`]：**STEP 10-4**——`WitnessSeed`/`deterministic_select`/`WitnessProof`/`verify_witness_proof`
//!   （ADR-0036 W-1~W-6）。
//! - [`round`]：**STEP 10-5**——BFT Round 状态机（`RoundState`/`VoteAccumulator`/`process_vote`/
//!   `LockedState`/`RoundTimeoutConfig`，ADR-0037 B-1~B-6）。
//! - [`finality`]：**STEP 10-6.2**——QC / Finality（`QuorumCertificate`/`verify_qc`/
//!   `check_finality_applicability`/`acquire_lock`/`update_finalized_reference`，ADR-0038 F-1~F-18）。
//! - [`checkpoint`]：**STEP 10-7.2**——Checkpoint（`derive_checkpoint`/`verify_checkpoint`/
//!   `encode_checkpoint`/`decode_checkpoint`，ADR-0039 CP-1~CP-8）。
//! - [`fork_choice`]：**STEP 10-8.2**——Fork Choice（`fork_choice`，ADR-0040 FC-1~FC-14）。
//!
//! # 边界（ADR-0033 C-1 / C-3）
//! - 依赖：`consensus → core/crypto`；**禁止** `consensus → execution/storage/network`（纯计算）。
//! - **DAG ≠ Finality**：DAG 只负责传播/因果/候选排序输入；BFT/finality 归 10-5/10-6。
//! - 未实现：完整 Block 格式（PHASE 7）/ node 协调层。

pub mod checkpoint;
pub mod dag;
pub mod error;
pub mod finality;
pub mod fork_choice;
pub mod round;
pub mod validator;
pub mod vote;
pub mod witness;
