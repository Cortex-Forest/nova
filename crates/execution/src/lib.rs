//! Nova Chain 执行层（PHASE 3 — STEP 7G State Transition）。
//!
//! # 模块
//! - [`state_transition`]：**STEP 7G 已实现**——`apply_transaction`（ADR-0023）：完整
//!   admission（7D 签名 / 7E replay+nonce / 7F gas+balance）+ 状态转换（transfer / fee /
//!   burn / nonce+1 / 隐式创建）+ 确定性 `AccountChange`（G-J）+ 原子性（G-I）。
//! - [`block`]：**STEP 8D 已实现**——`execute_block` / `validate_block`（ADR-0029 D-2/D-3）：
//!   纯计算（影子状态）、Block Validity 两阶段（nonce 唯一 / gas 上限）、失败 tx skip。
//!
//! # 纪律（Master Prompt §12/§13/§16）
//! - 纯函数：`apply_transaction` 不直接修改 state，返回 `StateTransition`（caller 应用并 commit）。
//! - 所有金额/nonce 运算 checked；禁 panic / 回绕。
//! - **不实现**：WASM / storage / trie / state root（storage 层）/ 完整区块格式（PHASE 7）。
//! - WASM Runtime（Wasmtime 或评审等价）与确定性策略待 PHASE 12 ADR 评审后引入。

pub mod block;
pub mod state_transition;

// 注意：本阶段禁止实现任何 WASM 执行逻辑。
