//! STEP 3 Exit 7：接入 STEP 1 domain 测试向量，验证 `nova_crypto::domain`
//! 正式实现与冻结向量完全一致（signed_bytes / message_hash）。
//!
//! 向量文件来自 `tests/vectors/domain/`（STEP 1，已提交）；此处 `include_str!`
//! 内嵌加载（确定性，不依赖文件系统顺序）。

use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use serde_json::Value;

const DOMAIN_VECTORS: &[(&str, &str)] = &[
    (
        "domain-tx-001",
        include_str!("../../../tests/vectors/domain/domain-tx-001.json"),
    ),
    (
        "domain-vote-001",
        include_str!("../../../tests/vectors/domain/domain-vote-001.json"),
    ),
    (
        "domain-block-001",
        include_str!("../../../tests/vectors/domain/domain-block-001.json"),
    ),
    (
        "domain-gov-001",
        include_str!("../../../tests/vectors/domain/domain-gov-001.json"),
    ),
    (
        "domain-addr-001",
        include_str!("../../../tests/vectors/domain/domain-addr-001.json"),
    ),
    (
        "domain-cross-chain-001",
        include_str!("../../../tests/vectors/domain/domain-cross-chain-001.json"),
    ),
    (
        "domain-diff-payload-001",
        include_str!("../../../tests/vectors/domain/domain-diff-payload-001.json"),
    ),
    (
        "domain-unknown-domain-001",
        include_str!("../../../tests/vectors/domain/domain-unknown-domain-001.json"),
    ),
    (
        "domain-unknown-algorithm-001",
        include_str!("../../../tests/vectors/domain/domain-unknown-algorithm-001.json"),
    ),
    (
        "domain-inconsistent-signed-001",
        include_str!("../../../tests/vectors/domain/domain-inconsistent-signed-001.json"),
    ),
];

fn nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(format!("invalid hex char: {b:#x}")),
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len() / 2);
    for i in (0..b.len()).step_by(2) {
        out.push((nibble(b[i])? << 4) | nibble(b[i + 1])?);
    }
    Ok(out)
}

#[test]
fn domain_vectors_match_implementation() {
    for &(id, json) in DOMAIN_VECTORS {
        let v: Value = serde_json::from_str(json).unwrap_or_else(|e| panic!("{id}: bad json: {e}"));
        let algorithm_id = v["algorithm_id"].as_u64().unwrap() as u8;
        let domain_id = v["domain_id"].as_u64().unwrap() as u8;
        let chain_id = v["chain_id"].as_u64().unwrap();
        let payload = hex_decode(v["canonical_payload"].as_str().unwrap()).unwrap();
        let expected = v["expected"].as_str().unwrap();

        match (
            AlgorithmId::try_from(algorithm_id),
            DomainId::try_from(domain_id),
        ) {
            (Ok(alg), Ok(dom)) => {
                let signed = build_signed_bytes(alg, dom, chain_id, &payload)
                    .unwrap_or_else(|e| panic!("{id}: build_signed_bytes: {e}"));
                let hash = hash_signing_message(&signed);

                let signed_expected = hex_decode(v["signed_bytes"].as_str().unwrap()).unwrap();
                let hash_expected = hex_decode(v["message_hash"].as_str().unwrap()).unwrap();

                if id == "domain-inconsistent-signed-001" {
                    // 该向量特意携带不一致的 signed_bytes（测试拒绝能力）。
                    // 正式实现按字段重算，必须与向量中的错误值不一致（证明检测有效）。
                    assert_ne!(
                        signed, signed_expected,
                        "{id}: vector signed_bytes is intentionally inconsistent; impl must differ"
                    );
                    continue;
                }

                assert_eq!(
                    signed, signed_expected,
                    "{id}: signed_bytes mismatch (impl != frozen vector)"
                );
                assert_eq!(
                    hash.as_bytes().as_slice(),
                    hash_expected.as_slice(),
                    "{id}: message_hash mismatch (impl != frozen vector)"
                );
                assert_eq!(expected, "VALID", "{id}: expected VALID");
            }
            _ => {
                // unknown domain / algorithm ⇒ 实现必须拒绝（禁 fallback）。
                assert_ne!(
                    expected, "VALID",
                    "{id}: expected rejection but vector says VALID"
                );
            }
        }
    }
}
