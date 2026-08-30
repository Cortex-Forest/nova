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

/// Consensus 验证门面（GAP-1 解决；STEP 11-6）。V-5 验证入口，供 Node 在构造
/// `ConsensusEvent::Vote` 前调用，强制 MF-2 precondition。
///
/// - **只委托既有 `verify_vote`（V-5），不复制验证逻辑**。
/// - 从 `set` 按 `vote.validator_id` 解析共识公钥（**不信任 envelope sender / NodeId**，B5）；
///   `set.info` 查无 ⇒ `UnknownValidator`；公钥畸形 ⇒ `ValidatorIdentityMismatch`（与 verify_qc 先例一致）。
pub fn verify_vote_input(
    vote: &ValidatorVote,
    signature: &[u8; 64],
    chain_id: u64,
    set: &ValidatorSet,
) -> Result<(), ConsensusError> {
    let info = set
        .info(&vote.validator_id)
        .ok_or(ConsensusError::UnknownValidator)?;
    let vk = VerifyingKey::from_bytes(&info.consensus_public_key)
        .map_err(|_| ConsensusError::ValidatorIdentityMismatch)?;
    verify_vote(vote, signature, &vk, chain_id, set)
}

/// 恢复冻结 roundtrip 契约（crypto-serialization §8）的 decode 侧（P0-B1）。
///
/// 严格逆向冻结 121B canonical layout（ADR-0034 V-4 / ADR-0009 顺序）：
/// `round(8LE) ‖ height(8LE) ‖ target(32) ‖ vote_type(1) ‖ source(32) ‖ validator_id(32) ‖ timestamp(8LE)`。
/// 仅结构解析；**不做 semantic validation**（membership / signature / authority / domain / replay
/// 均不验证——分别归 `verify_vote` / transition）。
pub fn decode_validator_vote(bytes: &[u8]) -> Result<ValidatorVote, ConsensusError> {
    const VOTE_LEN: usize = 121;
    if bytes.len() != VOTE_LEN {
        return Err(ConsensusError::InvalidVoteEncoding);
    }
    let round = u64::from_le_bytes(bytes[0..8].try_into().expect("len checked"));
    let height = u64::from_le_bytes(bytes[8..16].try_into().expect("len checked"));
    let mut target_block_hash = [0u8; 32];
    target_block_hash.copy_from_slice(&bytes[16..48]);
    let vote_type = VoteType::try_from(bytes[48])?;
    let mut source_block_hash = [0u8; 32];
    source_block_hash.copy_from_slice(&bytes[49..81]);
    let mut vid = [0u8; 32];
    vid.copy_from_slice(&bytes[81..113]);
    let validator_id = ValidatorId::from_bytes(vid);
    let timestamp = u64::from_le_bytes(bytes[113..121].try_into().expect("len checked"));
    Ok(ValidatorVote {
        round,
        height,
        target_block_hash,
        vote_type,
        source_block_hash,
        validator_id,
        timestamp,
    })
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

    #[test]
    fn decode_validator_vote_roundtrip() {
        let pk = [0x44; 32];
        for vt in [VoteType::Prevote, VoteType::Precommit] {
            let vote = ValidatorVote {
                round: 7,
                height: 3,
                target_block_hash: [0x11; 32],
                vote_type: vt,
                source_block_hash: [0x22; 32],
                validator_id: ValidatorId::from_consensus_public_key(&pk),
                timestamp: 99,
            };
            let bytes = canonical_vote_payload(&vote);
            assert_eq!(decode_validator_vote(&bytes), Ok(vote), "roundtrip");
        }
    }

    #[test]
    fn decode_validator_vote_rejects_bad_length() {
        let pk = [0x44; 32];
        let vote = ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: 0,
        };
        let bytes = canonical_vote_payload(&vote);
        // 截断
        assert_eq!(
            decode_validator_vote(&bytes[..120]),
            Err(ConsensusError::InvalidVoteEncoding)
        );
        // 超长 / trailing bytes
        let mut long = bytes.clone();
        long.push(0x00);
        assert_eq!(
            decode_validator_vote(&long),
            Err(ConsensusError::InvalidVoteEncoding)
        );
        // 空
        assert_eq!(
            decode_validator_vote(&[]),
            Err(ConsensusError::InvalidVoteEncoding)
        );
    }

    #[test]
    fn decode_validator_vote_rejects_invalid_vote_type() {
        let pk = [0x44; 32];
        let vote = ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: 0,
        };
        let mut bytes = canonical_vote_payload(&vote);
        bytes[48] = 0x03; // 非 0x01/0x02 ⇒ 拒绝
        assert_eq!(
            decode_validator_vote(&bytes),
            Err(ConsensusError::InvalidVoteEncoding)
        );
    }

    #[test]
    fn decode_validator_vote_field_accuracy() {
        let pk = [0x77; 32];
        let vote = ValidatorVote {
            round: 1 << 40,
            height: 999,
            target_block_hash: [0xab; 32],
            vote_type: VoteType::Precommit,
            source_block_hash: [0xcd; 32],
            validator_id: ValidatorId::from_consensus_public_key(&pk),
            timestamp: u64::MAX,
        };
        let d = decode_validator_vote(&canonical_vote_payload(&vote)).unwrap();
        assert_eq!(d.round, vote.round);
        assert_eq!(d.height, vote.height);
        assert_eq!(d.target_block_hash, vote.target_block_hash);
        assert_eq!(d.vote_type, vote.vote_type);
        assert_eq!(d.source_block_hash, vote.source_block_hash);
        assert_eq!(d.validator_id, vote.validator_id);
        assert_eq!(d.timestamp, vote.timestamp);
    }

    #[test]
    fn decode_validator_vote_no_membership_check() {
        // validator_id 只做字节恢复，不做 membership/authority 验证（归 verify_vote ①）。
        let mut bytes = [0u8; 121];
        bytes[48] = 0x01; // 有效 vote_type（Prevote）；其余字段任意
        bytes[81..113].copy_from_slice(&[0xee; 32]); // 任意 32B validator_id
        let d = decode_validator_vote(&bytes).unwrap();
        assert_eq!(d.validator_id, ValidatorId::from_bytes([0xee; 32]));
    }

    #[test]
    fn verify_vote_input_ok() {
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
        assert_eq!(verify_vote_input(&vote, &sig, 1001, &set), Ok(()));
    }

    #[test]
    fn verify_vote_input_rejects_bad_signature() {
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
        // 非 validator key 签名（validator_id 指向 set validator）⇒ 签名验证失败
        let other = KeyPair::generate().unwrap();
        let sig = sign_vote(other.signing_key(), &vote, 1001);
        assert_eq!(
            verify_vote_input(&vote, &sig, 1001, &set),
            Err(ConsensusError::InvalidSignature)
        );
    }

    #[test]
    fn verify_vote_input_rejects_unknown_validator() {
        let kp = KeyPair::generate().unwrap();
        let pk = kp.verifying_key().to_bytes();
        let v = ValidatorInit {
            account_address: addr([0xaa; 32]),
            consensus_public_key: pk,
            bonded_stake: 100,
            commission_bps: 100,
        };
        let set = ValidatorSet::from_genesis(&genesis_with(v));
        // validator_id 指向非 set 成员 ⇒ UnknownValidator（门面在委托前拒）
        let vote = ValidatorVote {
            round: 0,
            height: 1,
            target_block_hash: [0x11; 32],
            vote_type: VoteType::Prevote,
            source_block_hash: [0x00; 32],
            validator_id: ValidatorId::from_consensus_public_key(&[0x99; 32]),
            timestamp: 0,
        };
        assert_eq!(
            verify_vote_input(&vote, &[0u8; 64], 1001, &set),
            Err(ConsensusError::UnknownValidator)
        );
    }

    #[test]
    fn verify_vote_input_rejects_wrong_chain_id() {
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
            verify_vote_input(&vote, &sig, 9999, &set),
            Err(ConsensusError::InvalidSignature)
        );
    }
}
