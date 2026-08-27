//! Random Witness（STEP 10-4 — ADR-0036 W-1~W-6）。
//!
//! - [`witness_seed`]：`protocol_hash(previous_finality_reference ‖ height)`（W-3，C-4）。
//! - [`deterministic_select`]：`rank = SHA-256(seed ‖ validator_id)` 升序取前 count（W-2）。
//! - [`WitnessProof`]：Witness 对区块 availability 的签名（W-5；`DomainId::Witness`）。
//! - **Witness ≠ finality authority**（W-6）：只提供 availability signal / DAG confidence，
//!   不改变 voting power / 不替代 BFT vote / 不直接 finalize。

use crate::error::ConsensusError;
use crate::validator::{ValidatorId, ValidatorSet};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::hash::protocol_hash;
use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};

/// Witness 随机种子：`SHA-256(previous_finality_reference ‖ height LE)`（W-3；任何节点可复算）。
pub fn witness_seed(previous_finality_reference: &[u8; 32], height: u64) -> [u8; 32] {
    let mut pre = Vec::with_capacity(32 + 8);
    pre.extend_from_slice(previous_finality_reference);
    pre.extend_from_slice(&height.to_le_bytes());
    protocol_hash(&pre)
}

/// 确定性选择 witness 集（W-2）：`rank = SHA-256(seed ‖ validator_id)`，按 rank 升序取前 `count`。
///
/// 同 `ValidatorSet + seed + count` ⇒ 同 `WitnessSet`（无中心随机源、无 VRF）。
pub fn deterministic_select(set: &ValidatorSet, seed: [u8; 32], count: usize) -> Vec<ValidatorId> {
    let mut ranked: Vec<(ValidatorId, [u8; 32])> = set
        .validators()
        .iter()
        .map(|v| {
            let mut pre = Vec::with_capacity(32 + 32);
            pre.extend_from_slice(&seed);
            pre.extend_from_slice(v.validator_id.as_bytes());
            (v.validator_id, protocol_hash(&pre))
        })
        .collect();
    // rank 升序；tie 用 validator_id 字典序（确定性）
    ranked.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    ranked.into_iter().take(count).map(|(id, _)| id).collect()
}

/// Witness availability proof（ADR-0036 W-5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WitnessProof {
    pub block_hash: [u8; 32],
    pub witness_id: ValidatorId,
    pub signature: [u8; 64],
}

/// Canonical witness payload：`block_hash(32B) ‖ witness_id(32B)`。
pub fn canonical_witness_payload(proof: &WitnessProof) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 32);
    out.extend_from_slice(&proof.block_hash);
    out.extend_from_slice(proof.witness_id.as_bytes());
    out
}

/// 验证 witness proof（W-1/W-5）。
///
/// ① witness ∈ ValidatorSet → ② identity（witness_id == SHA-256(pubkey)）→
/// ③ `DomainId::Witness` signed_bytes → ④ hash → ⑤ verify_strict。
pub fn verify_witness_proof(
    proof: &WitnessProof,
    vk: &VerifyingKey,
    chain_id: u64,
    set: &ValidatorSet,
) -> Result<(), ConsensusError> {
    // ① 成员（W-1：Witness 必须受 ValidatorSet 管理）
    if !set.contains(&proof.witness_id) {
        return Err(ConsensusError::UnknownValidator);
    }
    // ② 身份绑定
    if ValidatorId::from_consensus_public_key(&vk.to_bytes()) != proof.witness_id {
        return Err(ConsensusError::ValidatorIdentityMismatch);
    }
    // ③ 域分离签名（W-5：DomainId::Witness，非 ValidatorVote）
    let payload = canonical_witness_payload(proof);
    let signed = build_signed_bytes(AlgorithmId::Ed25519, DomainId::Witness, chain_id, &payload)
        .map_err(|_| ConsensusError::InvalidDomain)?;
    // ④ hash
    let h = hash_signing_message(&signed);
    // ⑤ verify_strict
    let sig =
        Signature::from_bytes(&proof.signature).map_err(|_| ConsensusError::InvalidSignature)?;
    verify_message_hash(vk, &h, &sig).map_err(|_| ConsensusError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};
    use nova_crypto::key::KeyPair;
    use nova_crypto::signature::sign_message_hash;

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn genesis_with(vals: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 0,
            initial_validator_set: vals,
            initial_accounts: Vec::new(),
            protocol_parameters: ProtocolParamsV1 {
                max_tx_bytes: 64 * 1024,
                max_block_bytes: 8 * 1024 * 1024,
                max_gas_per_block: 100_000_000_000,
                max_contract_code_bytes: 0,
                max_contract_storage_bytes: 0,
                epoch_length_blocks: 1_000_000,
                snapshot_interval_blocks: 10_000_000,
            },
            economics_parameters: EconomicsParamsV1 {
                total_supply: 1_000_000_000,
                min_validator_stake: 100,
                unbonding_period_seconds: 1_000,
                fee_burn_bps: 100,
            },
        }
    }

    fn vin(pk: [u8; 32], kh: [u8; 32]) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: 100,
            commission_bps: 100,
        }
    }

    fn sample_set() -> ValidatorSet {
        let vals = (1..=5).map(|i| vin([i; 32], [i + 0x10; 32])).collect();
        ValidatorSet::from_genesis(&genesis_with(vals))
    }

    #[test]
    fn witness_seed_deterministic_and_height_sensitive() {
        let fr = [0xab; 32];
        let s1 = witness_seed(&fr, 10);
        let s2 = witness_seed(&fr, 10);
        assert_eq!(s1, s2, "确定性");
        assert_ne!(witness_seed(&fr, 11), s1, "height 敏感");
        assert_ne!(witness_seed(&[0xcd; 32], 10), s1, "finality ref 敏感");
    }

    #[test]
    fn deterministic_select_consistent_and_members_only() {
        let set = sample_set();
        let seed = witness_seed(&[0xab; 32], 10);
        let w1 = deterministic_select(&set, seed, 3);
        let w2 = deterministic_select(&set, seed, 3);
        assert_eq!(w1, w2, "同输入同输出");
        assert_eq!(w1.len(), 3);
        // 全部是 ValidatorSet 成员
        for id in &w1 {
            assert!(set.contains(id), "witness 必须受 ValidatorSet 管理");
        }
        // count 上限
        assert_eq!(deterministic_select(&set, seed, 999).len(), 5);
        // 不同 seed 通常产生不同集合
        let seed2 = witness_seed(&[0xcd; 32], 10);
        let w3 = deterministic_select(&set, seed2, 3);
        assert_ne!(w1, w3);
    }

    #[test]
    fn witness_proof_sign_verify_ok() {
        let kp = KeyPair::generate().unwrap();
        // 用 kp 作为第一个 validator 的 consensus key 构建 set
        let pk = kp.verifying_key().to_bytes();
        let vals = vec![vin(pk, [0xaa; 32]), vin([0x22; 32], [0xbb; 32])];
        let set = ValidatorSet::from_genesis(&genesis_with(vals));
        let wid = ValidatorId::from_consensus_public_key(&pk);

        let mut proof = WitnessProof {
            block_hash: [0x11; 32],
            witness_id: wid,
            signature: [0u8; 64],
        };
        // 签名
        let payload = canonical_witness_payload(&proof);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Witness, 1001, &payload).unwrap();
        proof.signature =
            sign_message_hash(kp.signing_key(), &hash_signing_message(&signed)).to_bytes();
        assert_eq!(
            verify_witness_proof(&proof, kp.verifying_key(), 1001, &set),
            Ok(())
        );
    }

    #[test]
    fn witness_proof_verify_rejects_tampering() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let vals = vec![vin(pk, [0xaa; 32])];
        let set = ValidatorSet::from_genesis(&genesis_with(vals));
        let wid = ValidatorId::from_consensus_public_key(&pk);

        let mut proof = WitnessProof {
            block_hash: [0x11; 32],
            witness_id: wid,
            signature: [0u8; 64],
        };
        let payload = canonical_witness_payload(&proof);
        let signed =
            build_signed_bytes(AlgorithmId::Ed25519, DomainId::Witness, 1001, &payload).unwrap();
        proof.signature =
            sign_message_hash(kp.signing_key(), &hash_signing_message(&signed)).to_bytes();

        // 篡改 block_hash ⇒ 签名失败
        let mut t = proof.clone();
        t.block_hash[0] ^= 0xff;
        assert_eq!(
            verify_witness_proof(&t, kp.verifying_key(), 1001, &set),
            Err(ConsensusError::InvalidSignature)
        );
        // 未知 witness ⇒ UnknownValidator
        let mut t2 = proof.clone();
        t2.witness_id = ValidatorId::from_consensus_public_key(&[0x99; 32]);
        assert_eq!(
            verify_witness_proof(&t2, kp.verifying_key(), 1001, &set),
            Err(ConsensusError::UnknownValidator)
        );
        // 错误 chain_id ⇒ 签名失败
        assert_eq!(
            verify_witness_proof(&proof, kp.verifying_key(), 9999, &set),
            Err(ConsensusError::InvalidSignature)
        );
    }
}
