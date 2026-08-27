//! Validator Vote（STEP 10-2 — ADR-0034 V-4/V-5）。
//!
//! - `VoteType{Prevote, Precommit}`（C-5 两阶段）。
//! - `ValidatorVote` canonical 顺序与 ADR-0009 完全一致。
//! - `verify_vote`：membership → identity → signed_bytes → hash → verify_strict（五步，V-5）。

use crate::error::ConsensusError;
use crate::validator::{ValidatorId, ValidatorSet};
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::signature::{Signature, VerifyingKey, verify_message_hash};

/// 投票类型（C-5 两阶段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum VoteType {
    /// 预投票。
    Prevote = 0x01,
    /// 预提交。
    Precommit = 0x02,
}

impl VoteType {
    /// 底层字节值。
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

impl TryFrom<u8> for VoteType {
    type Error = ConsensusError;

    fn try_from(v: u8) -> Result<Self, Self::Error> {
        match v {
            0x01 => Ok(Self::Prevote),
            0x02 => Ok(Self::Precommit),
            _ => Err(ConsensusError::InvalidVoteEncoding),
        }
    }
}

/// 验证者投票（ADR-0033 C-9 / ADR-0034 V-4；结构不含 signature——签名外部）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorVote {
    pub round: u64,
    pub height: u64,
    pub target_block_hash: [u8; 32],
    pub vote_type: VoteType,
    pub source_block_hash: [u8; 32],
    pub validator_id: ValidatorId,
    pub timestamp: u64,
}

/// Canonical 投票 payload（ADR-0009 顺序）：
/// `round(8B LE) ‖ height(8B LE) ‖ target(32B) ‖ vote_type(1B) ‖ source(32B) ‖ validator_id(32B) ‖ timestamp(8B LE)`。
pub fn canonical_vote_payload(vote: &ValidatorVote) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + 8 + 32 + 1 + 32 + 32 + 8);
    out.extend_from_slice(&vote.round.to_le_bytes());
    out.extend_from_slice(&vote.height.to_le_bytes());
    out.extend_from_slice(&vote.target_block_hash);
    out.push(vote.vote_type.as_u8());
    out.extend_from_slice(&vote.source_block_hash);
    out.extend_from_slice(vote.validator_id.as_bytes());
    out.extend_from_slice(&vote.timestamp.to_le_bytes());
    out
}

/// 验证投票（五步；ADR-0034 V-5）。
///
/// `signature` 外部（Vote 结构不含签名）；`chain_id` 域绑定。
pub fn verify_vote(
    vote: &ValidatorVote,
    signature: &[u8; 64],
    vk: &VerifyingKey,
    chain_id: u64,
    set: &ValidatorSet,
) -> Result<(), ConsensusError> {
    // ① membership
    if !set.contains(&vote.validator_id) {
        return Err(ConsensusError::UnknownValidator);
    }
    // ② identity：validator_id == SHA-256(canonical pubkey)
    if ValidatorId::from_consensus_public_key(&vk.to_bytes()) != vote.validator_id {
        return Err(ConsensusError::ValidatorIdentityMismatch);
    }
    // ③ signed_bytes（域分离：ValidatorVote）
    let payload = canonical_vote_payload(vote);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        chain_id,
        &payload,
    )
    .map_err(|_| ConsensusError::InvalidDomain)?;
    // ④ hash
    let h = hash_signing_message(&signed);
    // ⑤ verify_strict
    let sig = Signature::from_bytes(signature).map_err(|_| ConsensusError::InvalidSignature)?;
    verify_message_hash(vk, &h, &sig).map_err(|_| ConsensusError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator::ValidatorSet;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::domain::DomainId;
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

    fn genesis_with(v: ValidatorInit) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 0,
            initial_validator_set: vec![v],
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

    fn sign_vote(
        signing: &nova_crypto::signature::SigningKey,
        vote: &ValidatorVote,
        chain_id: u64,
    ) -> [u8; 64] {
        let payload = canonical_vote_payload(vote);
        let signed = build_signed_bytes(
            AlgorithmId::Ed25519,
            DomainId::ValidatorVote,
            chain_id,
            &payload,
        )
        .unwrap();
        sign_message_hash(signing, &hash_signing_message(&signed)).to_bytes()
    }

    #[test]
    fn vote_verify_ok() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let v = ValidatorInit {
            account_address: addr([0xaa; 32]),
            consensus_public_key: pk,
            bonded_stake: 100,
            commission_bps: 100,
        };
        let set = ValidatorSet::from_genesis(&genesis_with(v));
        let vote = ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: 0,
        };
        let sig = sign_vote(kp.signing_key(), &vote, 1001);
        assert_eq!(
            verify_vote(&vote, &sig, kp.verifying_key(), 1001, &set),
            Ok(())
        );
    }

    #[test]
    fn vote_verify_rejects_tampering() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let v = ValidatorInit {
            account_address: addr([0xaa; 32]),
            consensus_public_key: pk,
            bonded_stake: 100,
            commission_bps: 100,
        };
        let set = ValidatorSet::from_genesis(&genesis_with(v));
        let mut vote = ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: 0,
        };
        let sig = sign_vote(kp.signing_key(), &vote, 1001);
        // 篡改 target ⇒ 签名失败
        let mut tampered = vote.clone();
        tampered.target_block_hash[0] ^= 0xff;
        assert_eq!(
            verify_vote(&tampered, &sig, kp.verifying_key(), 1001, &set),
            Err(ConsensusError::InvalidSignature)
        );
        // 错误 chain_id ⇒ 签名失败（域绑定）
        assert_eq!(
            verify_vote(&vote, &sig, kp.verifying_key(), 9999, &set),
            Err(ConsensusError::InvalidSignature)
        );
        // 未知 validator ⇒ UnknownValidator
        vote.validator_id = ValidatorId::from_consensus_public_key(&[0x99; 32]);
        assert_eq!(
            verify_vote(&vote, &sig, kp.verifying_key(), 1001, &set),
            Err(ConsensusError::UnknownValidator)
        );
    }

    #[test]
    fn canonical_vote_payload_order() {
        let pk = [0x44; 32];
        let vote = ValidatorVote {
            round: 7,
            height: 3,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Precommit,
            source_block_hash: [0x22; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: 99,
        };
        let bytes = canonical_vote_payload(&vote);
        // round 8B LE
        assert_eq!(&bytes[0..8], &7u64.to_le_bytes());
        // height 8B LE
        assert_eq!(&bytes[8..16], &3u64.to_le_bytes());
        // target 32B
        assert_eq!(&bytes[16..48], &[0x11; 32]);
        // vote_type 1B
        assert_eq!(bytes[48], 0x02);
        // source 32B
        assert_eq!(&bytes[49..81], &[0x22; 32]);
        // validator_id 32B
        assert_eq!(&bytes[81..113], &protocol_hash(&pk));
        // timestamp 8B LE
        assert_eq!(&bytes[113..121], &99u64.to_le_bytes());
        assert_eq!(bytes.len(), 121);
    }

    fn protocol_hash(b: &[u8]) -> [u8; 32] {
        nova_crypto::hash::protocol_hash(b)
    }
}
