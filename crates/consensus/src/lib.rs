//! Nova Chain 共识层（PHASE 1 占位）。
//!
//! 未来承载：PoS Validator Set、DAG 交易传播、BFT Finality。
//!
//! # 纪律（Master Prompt §5/§7/§6）
//! - DAG 只负责并行传播与交易组织，**不等于最终共识**。
//! - BFT 负责最终排序与状态一致。
//! - 禁止未经 Consensus Specification 批准的任何共识变更。
//! - 共识安全模型（Byzantine 上限 / Quorum / Slashing 等）必须先数学化定义（ADR-0009）。
//!
//! 本阶段**不实现任何共识逻辑**。

// 注意：本阶段禁止实现任何共识逻辑。
