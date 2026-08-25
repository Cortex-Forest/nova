//! 生成器（一次性开发工具）：为 domain / signature 向量计算 `signed_bytes` / `message_hash` 并回填。
//!
//! - 用途：生成/更新测试向量 fixture（`cargo run -p nova-test-vectors --bin gen_vectors`）。
//! - 运行时测试用 `include_str!`（编译期内嵌，确定性，不依赖文件系统顺序/网络/OS 随机）。
//! - 本工具**不含任何生产密码学实现**；仅复用 loader 的重算函数按冻结规范生成期望值。

use nova_test_vectors::domain::{build_signed_bytes, compute_message_hash};
use nova_test_vectors::hex;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for dir in ["domain", "signature"] {
        let dir_path = base.join(dir);
        let mut entries: Vec<_> = std::fs::read_dir(&dir_path)?
            .filter_map(Result::ok)
            .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
            .collect();
        entries.sort_by_key(|e| e.file_name());
        for entry in entries {
            let path: std::path::PathBuf = entry.path();
            let content = std::fs::read_to_string(&path)?;
            let mut v: serde_json::Value = serde_json::from_str(&content)?;

            // 仅对允许回填的向量计算 signed_bytes / message_hash。
            // `backfill: false`（如 inconsistent 向量）保留手工错误值以测试拒绝。
            let backfill = v
                .get("backfill")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if !backfill {
                println!("skipped (backfill=false): {}", path.display());
                continue;
            }

            let algorithm_id = v["algorithm_id"].as_u64().ok_or("missing algorithm_id")? as u8;
            let domain_id = v["domain_id"].as_u64().ok_or("missing domain_id")? as u8;
            let chain_id = v["chain_id"].as_u64().ok_or("missing chain_id")?;
            let payload_hex = v["canonical_payload"]
                .as_str()
                .ok_or("missing canonical_payload")?;
            let payload = hex::decode_strict_lower_hex(payload_hex)?;
            let signed = build_signed_bytes(algorithm_id, domain_id, chain_id, &payload)?;
            let hash = compute_message_hash(&signed);
            v["signed_bytes"] = serde_json::Value::String(hex::encode_lower_hex(&signed));
            v["message_hash"] = serde_json::Value::String(hex::encode_lower_hex(&hash));
            let out = serde_json::to_string_pretty(&v)?;
            std::fs::write(&path, format!("{out}\n"))?;
            println!("updated: {}", path.display());
        }
    }
    Ok(())
}
