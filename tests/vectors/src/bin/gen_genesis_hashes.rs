//! 回填器（一次性开发工具）：为 genesis 向量计算并回填 `expected_genesis_hash`（STEP 6A）。
//!
//! - 读取现有 JSON fixture（**不重新生成 keypair/地址**，保持确定性），构造 `GenesisV1`，
//!   用 `nova_crypto::identity::compute_genesis_hash` 计算并写回。
//! - valid：填自身 hash；tampered：填 mainnet 原 hash（篡改后不匹配 ⇒ GenesisHashMismatch）；
//!   wrong-genesis-hash：保持错误值（全 0）；其余 invalid：留空。
//! - 运行：`cargo run -p nova-test-vectors --bin gen_genesis_hashes`。

use nova_crypto::identity::compute_genesis_hash;
use nova_test_vectors::genesis::genesis_from_json;
use nova_test_vectors::hex;
use serde_json::{Value, json};

fn write_vector(path: &std::path::Path, v: Value) {
    let out = serde_json::to_string_pretty(&v).expect("json");
    std::fs::write(path, format!("{out}\n")).expect("write");
    println!("updated: {}", path.display());
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("genesis");
    let mut entries: Vec<_> = std::fs::read_dir(&base)?
        .filter_map(Result::ok)
        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    // 先计算 mainnet-valid 的 hash（tampered 向量引用它）。
    let mainnet_hash = {
        let main = std::fs::read_to_string(base.join("genesis-mainnet-valid-001.json"))?;
        let g = genesis_from_json(&main).map_err(|e| format!("mainnet parse: {e}"))?;
        compute_genesis_hash(&g).map_err(|e| format!("mainnet hash: {e}"))?
    };

    for entry in entries {
        let path = entry.path();
        let content = std::fs::read_to_string(&path)?;
        let mut v: Value = serde_json::from_str(&content)?;
        let id = v["id"].as_str().unwrap_or_default().to_string();

        match genesis_from_json(&content) {
            Ok(g) => match compute_genesis_hash(&g) {
                Ok(computed) => {
                    let h = hex::encode_lower_hex(&computed);
                    if id.contains("-valid-") {
                        v["expected_genesis_hash"] = json!(h);
                        v["note"] = json!(format!(
                            "{}; expected_genesis_hash 已回填（nova_crypto::identity）",
                            v["note"].as_str().unwrap_or_default()
                        ));
                    } else if id == "genesis-tampered-genesis-001" {
                        // 篡改后结构与原 mainnet 不同 ⇒ 填 mainnet 原 hash ⇒ 不匹配
                        let original = hex::encode_lower_hex(&mainnet_hash);
                        v["expected_genesis_hash"] = json!(original);
                        v["note"] = json!(format!(
                            "{}; expected=mainnet 原 hash（篡改后不匹配）",
                            v["note"].as_str().unwrap_or_default()
                        ));
                    } else if id == "genesis-wrong-genesis-hash-001" {
                        // 保持/设置一个明确的错误 hash（与 computed 必然不匹配）
                        let err =
                            "0000000000000000000000000000000000000000000000000000000000000000";
                        v["expected_genesis_hash"] = json!(err);
                        v["note"] = json!(format!(
                            "{}; configured hash 故意为错误值 ⇒ GenesisHashMismatch",
                            v["note"].as_str().unwrap_or_default()
                        ));
                    } else {
                        // 其余 invalid 语义非法，schema 层拒绝，expected_genesis_hash 留空
                    }
                    write_vector(&path, v);
                }
                Err(e) => {
                    // canonical 拒绝（duplicate/ordering）：schema 层已拒绝，无需填 hash
                    println!("skipped (canonical reject: {e}): {}", path.display());
                }
            },
            Err(_) => {
                // 结构非法（如 invalid-network）：schema 层拒绝，expected_genesis_hash 留空
                println!("skipped (structure invalid): {}", path.display());
            }
        }
    }
    Ok(())
}
