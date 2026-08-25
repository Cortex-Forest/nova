//! Nova Chain WASM 执行层（PHASE 1 占位）。
//!
//! 未来承载：WASM Runtime ABI、Host Functions、Storage API、Event API。
//!
//! # 纪律（Master Prompt §12/§13）
//! - WASM 合约不得无限运行：必须 Gas / Execution / Memory / Stack / Table /
//!   Call Depth / Host Function / Transaction Size 等限制。
//! - 必须沙箱化，禁止任意文件/网络/系统调用/宿主权限/未授权随机数/非确定性时间。
//! - Gas 计算必须 deterministic（相同输入 → 相同结果/状态/gas）。
//!
//! 本阶段**不实现任何执行逻辑**。

// 注意：本阶段禁止实现任何 WASM 执行逻辑。
