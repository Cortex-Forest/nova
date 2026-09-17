//! # YAZIMAO Genesis Builder（生产工具库）
//!
//! 把 **Owner 提供的 `genesis.json`** 转换为 **canonical `genesis.bin`** + **`genesis_hash`** +
//! **`genesis_summary.json`（人工复核摘要）**，并提供只读 **`verify`** 复核路径。
//!
//! ## 职责边界（严格）
//! - **不实现** canonical 编码：一律调用 [`nova_crypto::identity::canonical_genesis_bytes`]。
//! - **不实现** hash 算法：一律调用 [`nova_crypto::identity::compute_genesis_hash`]。
//! - **不实现** 解析后的语义规则：canonical 顺序 / 重复 / 上限 / stake 记账 / supply 不变量 /
//!   protocol·economics 边界一律委托 [`nova_crypto::identity::validate_genesis`]。
//! - 本 crate 只做：**strict JSON 解析**、**canonical 排序与重排报告**、**产物写出**、
//!   **decode 回读自校验**。它**不**修改任何既有协议行为，也**不**被任何生产模块依赖。
//!
//! ## 安全纪律
//! - 拒绝私钥 / seed / mnemonic / secret / keystore 字段（硬失败，不静默忽略）。
//! - 无默认值：字段缺失即失败；**不自动生成** `genesis_timestamp`，**不自动填写**
//!   `chain_id` / `network_id`。
//! - `u128` 只接受十进制字符串（拒绝数字、浮点、指数、前导零、正负号）。
//!
//! ## 流水线
//! ```text
//! genesis.json
//!   → input::parse_genesis_json      (strict, deny unknown/sensitive fields)
//!   → normalize::normalize_lists     (canonical 排序 + reordered 报告；不静默)
//!   → preflight::check               (不变量/唯一性/派生一致性 + 委托 validate_genesis)
//!   → canonical_genesis_bytes        (nova-crypto，唯一编码来源)
//!   → compute_genesis_hash           (nova-crypto)
//!   → decode 回读 + validate_genesis_with_expected   (自校验，fail-closed)
//!   → genesis.bin / genesis_hash.txt / genesis_summary.json
//! ```

pub mod emit;
pub mod input;
pub mod normalize;
pub mod preflight;

pub use emit::{
    ARTIFACT_GENESIS_BIN, ARTIFACT_GENESIS_HASH, ARTIFACT_SUMMARY, BuildError, BuildReport,
    VerifyError, VerifyReport, build_artifacts, verify_artifacts,
};
pub use input::{InputError, parse_genesis_json};
pub use normalize::{ReorderEntry, ReorderReport, normalize_lists};
pub use preflight::{PreflightError, PreflightReport, check_preconditions};

/// 字节切片 → 小写 hex（仅格式化，不涉及任何密码学运算）。
pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(nibble_to_hex(b >> 4));
        out.push(nibble_to_hex(b & 0x0f));
    }
    out
}

/// 小写 hex → 32B（仅解析，不涉及任何密码学运算）。
///
/// 严格：长度必须 64，且只接受 `0-9a-f`（**拒绝大写**，避免同一公钥出现两种文本表示）。
pub(crate) fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    let bytes = s.as_bytes();
    for (i, chunk) in bytes.chunks_exact(2).enumerate() {
        let hi = hex_to_nibble(chunk[0])?;
        let lo = hex_to_nibble(chunk[1])?;
        out[i] = (hi << 4) | lo;
    }
    Some(out)
}

fn nibble_to_hex(n: u8) -> char {
    match n {
        0..=9 => char::from(b'0' + n),
        10..=15 => char::from(b'a' + (n - 10)),
        _ => '?',
    }
}

fn hex_to_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        _ => None,
    }
}
