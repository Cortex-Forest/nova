//! 生成器（一次性开发工具）：以**实现阶段实际 codec** 生成 O2 round-change 测试向量。
//!
//! 运行：`cargo run -p nova-test-vectors --bin gen_round_change_vectors`
//!
//! # 规则（PHASE 6H-Y §17）
//! - 所有期望值由 `nova_consensus::round_change`（实际实现）产生；**禁止手工构造字节**。
//! - 私钥仅存在于本生成器进程内（确定性 dev seed，**非 production key**）；
//!   写入向量的只有**公钥**，运行期校验不需要私钥。
//! - 生成后运行期测试用 `include_str!`（编译期内嵌，确定性）。

use nova_consensus::round_change::{
    RoundChangeCertificate, RoundChangeEvidence, abandon_message_hash, abandon_signed_bytes,
    canonical_abandon_payload, encode_certificate,
};
use nova_consensus::validator::ValidatorId;
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_test_vectors::hex;
use serde_json::{Value, json};

/// 向量覆盖的 `chain_id`（devnet 编码空间，非主网参数）。
const CHAIN_ID: u64 = 1;
/// 证书针对的高度。
const HEIGHT: u64 = 7;
/// 证书聚合的 round（目标 round 由 codec 派生为 `from_round + 1`）。
const FROM_ROUND: u64 = 3;
/// `validator_set_id` 占位（真实网络 = genesis hash，ADR-0038 F-11）；本向量固定以便复现。
const VALIDATOR_SET_ID_BYTE: u8 = 0xAB;
/// 确定性 dev 种子（**测试/开发专用**；不得用于任何真实身份）。
const DEV_SEEDS: [[u8; 32]; 3] = [[0x11; 32], [0x22; 32], [0x33; 32]];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // ---- 1. 三个 dev validator，权重各 1 ⇒ T = 3，quorum = ceil(2T/3) = 2 ----
    let mut signers: Vec<(ValidatorId, [u8; 32], SigningKey)> = Vec::new();
    for seed in DEV_SEEDS {
        let sk = SigningKey::from_seed(seed);
        let pk = sk.verifying_key().to_bytes();
        let vid = ValidatorId::from_consensus_public_key(&pk);
        signers.push((vid, pk, sk));
    }
    // 证据必须严格按 validator_id 升序；公钥列表同样排序（确定性输出）。
    signers.sort_by_key(|s| s.0);

    let validator_set_id = [VALIDATOR_SET_ID_BYTE; 32];

    // ---- 2. 签名语句（全部 evidence 对同一 Abandon 语句签名）----
    let message_hash = abandon_message_hash(CHAIN_ID, HEIGHT, FROM_ROUND)?;
    let signed_bytes = abandon_signed_bytes(CHAIN_ID, HEIGHT, FROM_ROUND)?;
    let canonical_payload = canonical_abandon_payload(HEIGHT, FROM_ROUND);

    // ---- 3. evidence = 权重最小满足 quorum 的前 2 个（升序前缀）----
    let mut evidence: Vec<RoundChangeEvidence> = Vec::new();
    let mut evidence_json: Vec<Value> = Vec::new();
    for (vid, _pk, sk) in signers.iter().take(2) {
        let sig = sign_message_hash(sk, &message_hash);
        evidence.push(RoundChangeEvidence {
            validator_id: *vid,
            signature: sig.to_bytes(),
        });
        evidence_json.push(json!({
            "validator_id": hex::encode_lower_hex(vid.as_bytes()),
            "signature": hex::encode_lower_hex(&sig.to_bytes()),
        }));
    }

    // ---- 4. 证书 canonical 编码（实际 codec）----
    let cert = RoundChangeCertificate {
        validator_set_id,
        height: HEIGHT,
        from_round: FROM_ROUND,
        evidence,
    };
    let certificate_bytes = encode_certificate(&cert)?;
    let to_round = cert.to_round()?;

    // ---- 5. 组装向量（字段名按字母序；serde_json 默认 BTreeMap ⇒ 键有序）----
    let validators_json: Vec<Value> = signers
        .iter()
        .map(|(vid, pk, _sk)| {
            json!({
                "public_key": hex::encode_lower_hex(pk),
                "validator_id": hex::encode_lower_hex(vid.as_bytes()),
                "weight": 1,
            })
        })
        .collect();

    let vector = json!({
        "algorithm_id": nova_test_vectors::round_change::ROUND_CHANGE_ALGORITHM_ID,
        "canonical_payload": hex::encode_lower_hex(&canonical_payload),
        "category": "round_change",
        "certificate_bytes": hex::encode_lower_hex(&certificate_bytes),
        "certificate_len": certificate_bytes.len(),
        "chain_id": CHAIN_ID,
        "domain_id": nova_test_vectors::round_change::ROUND_CHANGE_DOMAIN_ID,
        "evidence": evidence_json,
        "expected": "VALID",
        "from_round": FROM_ROUND,
        "height": HEIGHT,
        "id": "round-change-certificate-valid-001",
        "message_hash": hex::encode_lower_hex(message_hash.as_bytes()),
        "signed_bytes": hex::encode_lower_hex(&signed_bytes),
        "source": "ADR-0066 (FROZEN) / ADR-0070 (FROZEN) / ADR-0067 (FROZEN)",
        "to_round": to_round,
        "validator_set_id": hex::encode_lower_hex(&validator_set_id),
        "validators": validators_json,
    });

    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("round_change");
    std::fs::create_dir_all(&base)?;
    let path = base.join("round-change-certificate-valid-001.json");
    std::fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&vector)?),
    )?;
    println!("wrote: {}", path.display());
    Ok(())
}
