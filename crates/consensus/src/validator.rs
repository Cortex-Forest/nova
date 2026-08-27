//! Validator Set（STEP 10-2 — ADR-0034 V-1~V-3）。
//!
//! - `ValidatorId = SHA-256(consensus_public_key)`（32B；genesis 冻结）。
//! - `ValidatorSet` 由 genesis `initial_validator_set` 构建；**weight = bonded_stake（V-2 静态）**。
//! - **quorum = `ceil(total_weight * 2 / 3)`**（`3Q >= 2T`；C-5 加权 ≥2/3）。
//! - 属共识安全域；**ValidatorId ≠ NodeId ≠ Account Address**（身份隔离）。

use core::fmt;
use nova_crypto::address::NovaAddress;
use nova_crypto::hash::protocol_hash;
use nova_crypto::identity::GenesisV1;

/// 共识验证者身份（`SHA-256(consensus_public_key)`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ValidatorId([u8; 32]);

impl ValidatorId {
    /// 从共识公钥派生（`SHA-256(canonical pubkey)`）。
    pub fn from_consensus_public_key(consensus_public_key: &[u8; 32]) -> Self {
        Self(protocol_hash(consensus_public_key))
    }

    /// 从 32 字节反序列化恢复。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 读取内部字节。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl fmt::Display for ValidatorId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ValidatorId({})", hex_str(&self.0))
    }
}

/// 验证者信息（ADR-0034 V-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorInfo {
    pub validator_id: ValidatorId,
    /// Ed25519 压缩点。
    pub consensus_public_key: [u8; 32],
    /// 链账户（fee/reward 归属）。
    pub account_address: NovaAddress,
    /// 投票权重（= genesis bonded_stake，V-2 静态）。
    pub voting_weight: u128,
}

/// 验证者集合（共识安全域；纯计算，V-1）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    validators: Vec<ValidatorInfo>,
    total_weight: u128,
}

impl ValidatorSet {
    /// 从 genesis 构建（genesis 已保证按 validator_id 升序；weight = bonded_stake）。
    pub fn from_genesis(genesis: &GenesisV1) -> Self {
        let mut total_weight = 0u128;
        let mut validators = Vec::with_capacity(genesis.initial_validator_set.len());
        for v in &genesis.initial_validator_set {
            total_weight = total_weight.saturating_add(v.bonded_stake);
            validators.push(ValidatorInfo {
                validator_id: ValidatorId::from_consensus_public_key(&v.consensus_public_key),
                consensus_public_key: v.consensus_public_key,
                account_address: v.account_address,
                voting_weight: v.bonded_stake,
            });
        }
        Self {
            validators,
            total_weight,
        }
    }

    /// 是否为成员。
    pub fn contains(&self, validator_id: &ValidatorId) -> bool {
        self.validators
            .iter()
            .any(|v| &v.validator_id == validator_id)
    }

    /// 成员投票权重。
    pub fn weight_of(&self, validator_id: &ValidatorId) -> Option<u128> {
        self.validators
            .iter()
            .find(|v| &v.validator_id == validator_id)
            .map(|v| v.voting_weight)
    }

    /// 成员信息。
    pub fn info(&self, validator_id: &ValidatorId) -> Option<&ValidatorInfo> {
        self.validators
            .iter()
            .find(|v| &v.validator_id == validator_id)
    }

    /// 总投票权重（Σ bonded_stake）。
    pub fn total_weight(&self) -> u128 {
        self.total_weight
    }

    /// 法定人数：`ceil(total_weight * 2 / 3)`（`3Q >= 2T`；C-5）。
    pub fn quorum(&self) -> u128 {
        self.total_weight.saturating_mul(2).div_ceil(3)
    }

    /// 给定累计权重是否达到法定人数（`>= quorum`）。
    pub fn is_quorum(&self, weight: u128) -> bool {
        weight >= self.quorum()
    }

    /// 验证者数量。
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// 全部验证者信息（按 validator_id 升序；deterministic_select 用，W-2）。
    pub fn validators(&self) -> &[ValidatorInfo] {
        &self.validators
    }

    /// 是否为空。
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, ProtocolParamsV1, ValidatorInit};

    fn addr(kh: [u8; 32]) -> NovaAddress {
        NovaAddress::from_payload(NovaAddressPayload {
            address_version: ADDRESS_VERSION,
            address_type: AddressType::UserAccount,
            network_id: NetworkId::Mainnet,
            key_hash: kh,
        })
    }

    fn genesis_with(validators: Vec<ValidatorInit>) -> GenesisV1 {
        GenesisV1 {
            network_id: NetworkId::Mainnet,
            chain_id: 1001,
            genesis_timestamp: 0,
            initial_validator_set: validators,
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

    fn vin(pk: [u8; 32], stake: u128, kh: [u8; 32]) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: stake,
            commission_bps: 100,
        }
    }

    #[test]
    fn validator_id_derives_from_consensus_pubkey() {
        let pk = [0x11u8; 32];
        let id = ValidatorId::from_consensus_public_key(&pk);
        assert_eq!(id.as_bytes(), &protocol_hash(&pk));
        // 确定性
        assert_eq!(
            ValidatorId::from_consensus_public_key(&pk),
            ValidatorId::from_consensus_public_key(&pk)
        );
        // 不同 pk ⇒ 不同 id
        assert_ne!(
            ValidatorId::from_consensus_public_key(&pk),
            ValidatorId::from_consensus_public_key(&[0x22u8; 32])
        );
    }

    #[test]
    fn validator_set_from_genesis_weight_and_quorum() {
        let g = genesis_with(vec![
            vin([0x11; 32], 100, [0xaa; 32]),
            vin([0x22; 32], 200, [0xbb; 32]),
        ]);
        let set = ValidatorSet::from_genesis(&g);
        assert_eq!(set.len(), 2);
        assert_eq!(set.total_weight(), 300);
        let v1 = ValidatorId::from_consensus_public_key(&[0x11; 32]);
        assert_eq!(set.weight_of(&v1), Some(100));
        assert!(set.contains(&v1));
        assert!(!set.contains(&ValidatorId::from_consensus_public_key(&[0x99; 32])));
        // quorum = ceil(300*2/3) = ceil(200) = 200
        assert_eq!(set.quorum(), 200);
        assert!(!set.is_quorum(199));
        assert!(set.is_quorum(200));
    }

    #[test]
    fn quorum_three_q_geq_two_t() {
        // 3Q >= 2T 性质
        let g = genesis_with(vec![
            vin([0x11; 32], 100, [0xaa; 32]),
            vin([0x22; 32], 100, [0xbb; 32]),
            vin([0x33; 32], 100, [0xcc; 32]),
        ]);
        let set = ValidatorSet::from_genesis(&g);
        let t = set.total_weight();
        let q = set.quorum();
        assert!(
            3u128.saturating_mul(q) >= 2u128.saturating_mul(t),
            "3Q >= 2T"
        );
        assert_eq!(q, 200); // ceil(300*2/3)
    }
}
