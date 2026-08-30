//! Nova Chain 运行时协调层（P7-4 — Block Lifecycle）。
//!
//! - 依赖方向（E1=A 冻结）：`nova-runtime → { nova-core, nova-crypto, nova-execution, nova-storage }`；
//!   本阶段**不引入 consensus 语义**。
//! - 分层步骤 API（E2=B 冻结）：不提供单 `process_block`；调用方按序调用各步骤。
//! - 错误组合（E3=A 冻结）：[`block::BlockPipelineError`] 区分 decode / validation / execution / storage。
//!
//! # 纪律
//! - **不重造**底层冻结函数（P7-2/3、8D）；runtime 只做跨层组合、错误包装、依赖集中。
//! - Execution=calculate，Storage=commit；runtime 不把 storage 职责塞进 execution 或反之。

pub mod block;

pub use block::{
    BlockPipelineError, BlockValidationFailure, commit_block, decode_block,
    execute_and_verify_state_root, validate_block_signature, validate_height_parent,
    validate_transaction_root,
};
