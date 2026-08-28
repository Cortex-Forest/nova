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
//!
//! # 边界（ADR-0033 C-1 / C-3）
//! - 依赖：`consensus → core/crypto`；**禁止** `consensus → execution/storage/network`（纯计算）。
//! - **DAG ≠ Finality**：DAG 只负责传播/因果/候选排序输入；BFT/finality 归 10-5/10-6。
//! - 未实现：Finality（10-6）/ Checkpoint（10-7）/ 完整 Block 格式（PHASE 7）。

pub mod dag;
pub mod error;
pub mod round;
pub mod validator;
pub mod vote;
pub mod witness;
