//! Proposer Selection V1（STEP 10-13D — ADR-0050 FROZEN）。
//!
//! # 冻结规范（ADR-0050）
//! - **Deterministic ValidatorSet-bound Weighted Selection**。
//! - `voting_weight = bonded_stake`；`ValidatorId = SHA-256(consensus_public_key)`；
//!   ordering = **ValidatorId ascending**（canonical，不依赖输入顺序）。
//! - seed 输入（Micro-Fix #2，57B 定宽）：
//!   ```text
//!   ProposerSeedInput =
//!       ProposerDomain(1B, = 0x07) ‖ chain_id(8B LE) ‖ height(8B LE) ‖ round(8B LE)
//!       ‖ validator_set_id(32B)
//!   ```
//! - `x = LE_u128(H(seed)[0..16]) mod total_weight`；选 **first validator where cumulative > x**。
//! - V0.1：`validator_set_reference = validator_set_id = genesis_hash`（ADR-0038 F-11）。
//! - 边界：`total_weight == 0` ⇒ 错误（无 proposer，不 fallback）；duplicate ValidatorId / 权重溢出 ⇒ 错误。
//!
//! # Witness 隔离（ADR-0050 §12）
//! - Proposer seed **不**含 `previous_finality_reference` / WitnessSeed / WitnessSet / ProposalRef /
//!   proposer-self / timestamp / network_id。
//!
//! # 边界（ADR-0050 §31/§32）
//! - 纯函数（consensus-level）；不接网络/广播/block 生产/timer 生命周期/node 协调。
//! - 本模块**不是** Lock/Finality/Quorum authority。

use crate::error::ConsensusError;
use crate::validator::{ValidatorId, ValidatorSet};
use nova_crypto::domain::DomainId;
use nova_crypto::hash::protocol_hash;

/// ProposerSeedInput 定长总长度（ADR-0050 §20）：1 + 8 + 8 + 8 + 32 = 57。
pub const PROPOSER_SEED_INPUT_LEN: usize = 57;

/// 构造 `ProposerSeedInput`（ADR-0050 §20；57B 定宽、字段顺序冻结）。
///
/// `validator_set_id`：V0.1 = `genesis_hash`（[u8;32]，ADR-0038 F-11）。
pub fn proposer_seed_input(
    chain_id: u64,
    height: u64,
    round: u64,
    validator_set_id: &[u8; 32],
) -> [u8; PROPOSER_SEED_INPUT_LEN] {
    let mut out = [0u8; PROPOSER_SEED_INPUT_LEN];
    out[0] = DomainId::Proposer.as_u8();
    out[1..9].copy_from_slice(&chain_id.to_le_bytes());
    out[9..17].copy_from_slice(&height.to_le_bytes());
    out[17..25].copy_from_slice(&round.to_le_bytes());
    out[25..57].copy_from_slice(validator_set_id);
    out
}

/// `ProposerSeed = H(ProposerSeedInput)`（H = protocol_hash / SHA-256）。
pub fn proposer_seed(
    chain_id: u64,
    height: u64,
    round: u64,
    validator_set_id: &[u8; 32],
) -> [u8; 32] {
    protocol_hash(&proposer_seed_input(
        chain_id,
        height,
        round,
        validator_set_id,
    ))
}

/// 确定性 ValidatorSet-bound 加权 proposer 选择（ADR-0050 §6/§10/§17）。
///
/// 返回当前 `(height, round)` 的 proposer `ValidatorId`。
///
/// 错误（ADR-0050 §30）：
/// - [`ConsensusError::EmptyValidatorSet`]：`total_weight == 0` ⇒ 无 proposer（不 fallback、不 panic）。
/// - [`ConsensusError::InvalidValidatorSet`]：duplicate ValidatorId 或权重累计溢出（非法输入防御）。
///
/// 实现细节：内部按 `ValidatorId` ascending 排序（canonical），保证与 ValidatorSet 输入顺序无关。
pub fn select_proposer(
    chain_id: u64,
    height: u64,
    round: u64,
    validator_set_id: &[u8; 32],
    set: &ValidatorSet,
) -> Result<ValidatorId, ConsensusError> {
    let total_weight = set.total_weight();
    if total_weight == 0 {
        return Err(ConsensusError::EmptyValidatorSet);
    }

    let seed = proposer_seed(chain_id, height, round, validator_set_id);
    let mut x_bytes = [0u8; 16];
    x_bytes.copy_from_slice(&seed[0..16]);
    let x = u128::from_le_bytes(x_bytes) % total_weight;

    // canonical ordering：ValidatorId ascending（ADR-0050 §15；不依赖输入/容器顺序）
    let mut vals: Vec<(ValidatorId, u128)> = set
        .validators()
        .iter()
        .map(|v| (v.validator_id, v.voting_weight))
        .collect();
    vals.sort_by_key(|(id, _)| *id);

    // duplicate ValidatorId 防御（非法 ValidatorSet）
    for pair in vals.windows(2) {
        if pair[0].0 == pair[1].0 {
            return Err(ConsensusError::InvalidValidatorSet);
        }
    }

    // weighted selection：first validator whose cumulative_weight > x（严格 `x < cumulative`）
    let mut cumulative: u128 = 0;
    for (id, weight) in &vals {
        cumulative = cumulative
            .checked_add(*weight)
            .ok_or(ConsensusError::InvalidValidatorSet)?;
        if x < cumulative {
            return Ok(*id);
        }
    }

    // 不可达：x ∈ [0, total_weight) 且 Σweight == total_weight ⇒ 必有 cum > x。
    Err(ConsensusError::InvalidValidatorSet)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::address::{
        ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
    };
    use nova_crypto::identity::{EconomicsParamsV1, GenesisV1, ProtocolParamsV1, ValidatorInit};

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

    /// (pk, key_hash, bonded_stake) → ValidatorInit；pubkey 与 key_hash 均须互异以保证身份唯一。
    fn vin(pk: [u8; 32], kh: [u8; 32], weight: u128) -> ValidatorInit {
        ValidatorInit {
            account_address: addr(kh),
            consensus_public_key: pk,
            bonded_stake: weight,
            commission_bps: 100,
        }
    }

    /// 3 个 validator，权重 10/20/30（total=60）。pk 互异。
    fn sample_set() -> ValidatorSet {
        let vals = vec![
            vin([0x11; 32], [0x21; 32], 10),
            vin([0x22; 32], [0x22; 32], 20),
            vin([0x33; 32], [0x23; 32], 30),
        ];
        ValidatorSet::from_genesis(&genesis_with(vals))
    }

    fn set_id() -> [u8; 32] {
        [0xAA; 32]
    }

    // ---- Test 2: seed length ----
    #[test]
    fn proposer_seed_input_len_is_57() {
        let input = proposer_seed_input(1, 2, 3, &[0x22; 32]);
        assert_eq!(input.len(), 57);
        assert_eq!(PROPOSER_SEED_INPUT_LEN, 57);
    }

    // ---- Test 1 (domain byte) + layout ----
    #[test]
    fn proposer_seed_input_layout_and_domain() {
        let chain_id = 1u64;
        let height = 2u64;
        let round = 3u64;
        let vsid = [0x22; 32];
        let input = proposer_seed_input(chain_id, height, round, &vsid);
        assert_eq!(
            input[0],
            DomainId::Proposer.as_u8(),
            "byte 0 = ProposerDomain(0x07)"
        );
        assert_eq!(&input[1..9], &chain_id.to_le_bytes(), "chain_id 8B LE");
        assert_eq!(&input[9..17], &height.to_le_bytes(), "height 8B LE");
        assert_eq!(&input[17..25], &round.to_le_bytes(), "round 8B LE");
        assert_eq!(&input[25..57], &vsid[..], "validator_set_id 32B");
    }

    // ---- Test 3-7: seed determinism / separation ----
    #[test]
    fn proposer_seed_deterministic() {
        let a = proposer_seed(1, 2, 3, &set_id());
        let b = proposer_seed(1, 2, 3, &set_id());
        assert_eq!(a, b);
    }

    #[test]
    fn proposer_seed_height_round_chain_set_separation() {
        let base = proposer_seed(1, 2, 3, &set_id());
        assert_ne!(proposer_seed(1, 3, 3, &set_id()), base, "height separation");
        assert_ne!(proposer_seed(1, 2, 4, &set_id()), base, "round separation");
        assert_ne!(proposer_seed(2, 2, 3, &set_id()), base, "chain separation");
        assert_ne!(
            proposer_seed(1, 2, 3, &[0xBB; 32]),
            base,
            "validator_set separation"
        );
    }

    // ---- Test 10: single validator always selected ----
    #[test]
    fn single_validator_always_selected() {
        let set = ValidatorSet::from_genesis(&genesis_with(vec![vin([0x01; 32], [0x11; 32], 100)]));
        for height in 0..8u64 {
            for round in 0..8u64 {
                let p = select_proposer(1, height, round, &set_id(), &set).unwrap();
                assert_eq!(p, set.validators()[0].validator_id);
            }
        }
    }

    // ---- Test 11: zero total weight → error, no panic ----
    #[test]
    fn zero_total_weight_errors() {
        // ValidatorSet::from_genesis 不做 validate；构造全零权重集合模拟 total_weight==0。
        let set = ValidatorSet::from_genesis(&genesis_with(vec![
            vin([0x01; 32], [0x11; 32], 0),
            vin([0x02; 32], [0x12; 32], 0),
        ]));
        assert_eq!(set.total_weight(), 0);
        let r = select_proposer(1, 0, 0, &set_id(), &set);
        assert_eq!(r, Err(ConsensusError::EmptyValidatorSet));
    }

    // ---- Test 12: duplicate ValidatorId → invalid set error ----
    #[test]
    fn duplicate_validator_id_errors() {
        // 同一 consensus_public_key ⇒ 同一 ValidatorId（无效 ValidatorSet）
        let set = ValidatorSet::from_genesis(&genesis_with(vec![
            vin([0x07; 32], [0x17; 32], 10),
            vin([0x07; 32], [0x18; 32], 20),
        ]));
        let r = select_proposer(1, 0, 0, &set_id(), &set);
        assert_eq!(r, Err(ConsensusError::InvalidValidatorSet));
    }

    // ---- Test 8: input ordering independence ----
    #[test]
    fn selection_independent_of_validator_order() {
        // 相同逻辑集合、不同 genesis 排列 → 相同 proposer
        let a = ValidatorSet::from_genesis(&genesis_with(vec![
            vin([0x11; 32], [0x21; 32], 10),
            vin([0x22; 32], [0x22; 32], 20),
            vin([0x33; 32], [0x23; 32], 30),
        ]));
        let b = ValidatorSet::from_genesis(&genesis_with(vec![
            vin([0x33; 32], [0x23; 32], 30),
            vin([0x11; 32], [0x21; 32], 10),
            vin([0x22; 32], [0x22; 32], 20),
        ]));
        for h in 0..4u64 {
            for r in 0..4u64 {
                let pa = select_proposer(1, h, r, &set_id(), &a).unwrap();
                let pb = select_proposer(1, h, r, &set_id(), &b).unwrap();
                assert_eq!(pa, pb, "proposer must not depend on validator input order");
            }
        }
    }

    // ---- Test 9: weighted selection follows first-cumulative > x ----
    #[test]
    fn weighted_selection_matches_cumulative_rule() {
        let set = sample_set(); // weights 10/20/30, total 60
        let chain = 1u64;
        let vsid = set_id();
        for height in 0..6u64 {
            for round in 0..6u64 {
                let seed = proposer_seed(chain, height, round, &vsid);
                let mut xb = [0u8; 16];
                xb.copy_from_slice(&seed[0..16]);
                let x = u128::from_le_bytes(xb) % set.total_weight();
                // canonical 排序
                let mut sorted: Vec<(ValidatorId, u128)> = set
                    .validators()
                    .iter()
                    .map(|v| (v.validator_id, v.voting_weight))
                    .collect();
                sorted.sort_by_key(|(id, _)| *id);
                let mut cum = 0u128;
                let expected = sorted
                    .iter()
                    .find_map(|(id, w)| {
                        cum += w;
                        (x < cum).then_some(*id)
                    })
                    .expect("some validator selected");
                let got = select_proposer(chain, height, round, &vsid, &set).unwrap();
                assert_eq!(got, expected);
                // 验证落在对应 validator 的权重区间内
                assert!(set.weight_of(&got).unwrap() > 0);
            }
        }
    }

    // ---- Test 4/5/6/7: selection separation sanity (not guaranteed different proposer, but input changes) ----
    #[test]
    fn proposer_selection_inputs_change_deterministically() {
        let set = sample_set();
        let p0 = select_proposer(1, 0, 0, &set_id(), &set).unwrap();
        assert!(set.contains(&p0), "proposer ∈ ValidatorSet");
        // round+1 / height+1 重新计算（值可能巧合相同；仅验证可独立复算）
        let p1 = select_proposer(1, 0, 1, &set_id(), &set).unwrap();
        assert!(set.contains(&p1));
        let p2 = select_proposer(1, 1, 0, &set_id(), &set).unwrap();
        assert!(set.contains(&p2));
    }

    // ---- Test 13: witness isolation ----
    // Proposer API 无 previous_finality_reference / WitnessSeed / WitnessSet 输入（结构隔离）。
    // 此处验证：同 (chain,height,round,set_id,set) 重复调用（代表任何 finality/witness 状态下）恒同。
    #[test]
    fn proposer_isolated_from_finality_and_witness() {
        let set = sample_set();
        // 两次调用之间不存在任何 finality/witness 输入可改变结果 → 证明隔离（结构保证）
        let a = select_proposer(1, 5, 2, &set_id(), &set).unwrap();
        let b = select_proposer(1, 5, 2, &set_id(), &set).unwrap();
        assert_eq!(a, b);
        // proposer_seed 与 witness_seed（W-3：H(prev_finality_ref‖height)）不同源：seed 输入第一个字节为
        // ProposerDomain(0x07)，非 Witness 域。
        assert_eq!(proposer_seed_input(1, 5, 2, &set_id())[0], 0x07);
    }

    // ---- 确定性测试向量（ADR-0050 §33；常量由独立 SHA-256 计算固化）----
    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn parse32(s: &str) -> [u8; 32] {
        let b = s.as_bytes();
        let nib = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => panic!("bad hex"),
        };
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        }
        out
    }

    #[test]
    fn golden_vector_seed_and_selection() {
        // 输入：chain_id=1 · height=2 · round=3 · validator_set_id=[0xAA;32]
        // ValidatorSet = sample_set()（pk 0x11/0x22/0x33；weight 10/20/30，total=60）
        let chain = 1u64;
        let height = 2u64;
        let round = 3u64;
        let vsid = [0xAA; 32];

        // ProposerSeedInput（57B）golden
        let input = proposer_seed_input(chain, height, round, &vsid);
        assert_eq!(
            hex(&input),
            "07010000000000000002000000000000000300000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        );

        // ProposerSeed golden（H = SHA-256）
        let seed = proposer_seed(chain, height, round, &vsid);
        assert_eq!(
            hex(&seed),
            "ca343ad379060d182f97b7f2618a7b56fcfbe20ee44616ccd3842410aa5f5fcc"
        );

        // selection：ValidatorId ascending，cumulative 10/30/60；x=14 ⇒ 第二位（cum 30 > 14）
        let set = sample_set();
        let got = select_proposer(chain, height, round, &vsid, &set).unwrap();
        assert_eq!(
            got,
            ValidatorId::from_bytes(parse32(
                "9f72ea0cf49536e3c66c787f705186df9a4378083753ae9536d65b3ad7fcddc4"
            ))
        );
        // 与 golden x 一致（x = LE_u128(seed[0..16]) % total_weight）
        let mut xb = [0u8; 16];
        xb.copy_from_slice(&seed[0..16]);
        assert_eq!(u128::from_le_bytes(xb) % set.total_weight(), 14);
    }
}
