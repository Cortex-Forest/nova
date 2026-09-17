//! D10 Recovery C — **恢复事实可用**与**活性不被冻结**回归测试（G4 重定义）。
//!
//! 覆盖（全部基于真实生产路径；无 mock / 无手设 head）：
//! - A22-1：restart 恢复窗口（`finalized = X@1`、`head = genesis`）下：fact 可恢复（finality 已注入）、
//!   不 panic，且 `bridge` 仍从**已验证 encoding** commit X（`head == X`）。
//! - A22-2：恢复窗口**不冻结** consensus 活性（G4 决策：hard guard 已撤销）——
//!   本地出块 / 投票 / 推进照常，`head` 必须能跨过 X（≥ 2）。
//! - A22-3：**状态清理**（`head == X`）后 consensus 继续推进（出块恢复、finality 推进）。
//! - A22-4：**Normal 不受影响**（无 fact 启动 ⇒ 正常出块）。
//!
//! 边界：本文件**只新增测试**；不修改 consensus / finality 规则 / fork choice / QC 验证。
//! rig 复用 `d10_p1_a10_common`（seed 派生身份 ⇒ 重启后同一验证者 key 可复现）。

mod d10_p1_a10_common;

use d10_p1_a10_common::{
    CHAIN_ID, Env, SEED_N1, SEED_V1, finalized_ref, head_hash, head_height, pubkey_from_seed,
    start_node, validator_id_of_seed,
};
use nova_consensus::finality::{QcContext, QcEvidence, QuorumCertificate};
use nova_consensus::vote::{ValidatorVote, VoteType, canonical_vote_payload};
use nova_crypto::address::NetworkId;
use nova_crypto::domain::{AlgorithmId, DomainId, build_signed_bytes, hash_signing_message};
use nova_crypto::signature::{SigningKey, sign_message_hash};
use nova_runtime::{
    BLOCK_VERSION, Block, BlockBody, BlockHeader, block_hash, compute_transaction_root,
    encode_block_header,
};

use nova_node::block_adapter::NoAccountsKeyResolver;
use nova_node::bootstrap::{FINALITY_FACT_FILE, NodeConfig, persist_finality_fact};

/// 单验证者 genesis 成员（seed 派生 ⇒ 重启后同一 key 可复现）。
const VAL_SEED: [u8; 32] = SEED_V1;
const NET_SEED: [u8; 32] = SEED_N1;

// ---------------------------------------------------------------------------
// crash-window fixture（与生产写侧一致：verified encoding + durable fact）
// ---------------------------------------------------------------------------

fn signed_block_a(genesis_hash: [u8; 32], state_root: [u8; 32]) -> Block {
    let body = BlockBody { txs: Vec::new() };
    let header = BlockHeader {
        version: BLOCK_VERSION,
        chain_id: CHAIN_ID,
        height: 1,
        parent_hash: genesis_hash,
        finality_reference: None,
        transaction_root: compute_transaction_root(&body),
        state_root,
        validator_set_hash: genesis_hash,
        timestamp: 0,
    };
    let payload = encode_block_header(&header);
    let signed =
        build_signed_bytes(AlgorithmId::Ed25519, DomainId::Block, CHAIN_ID, &payload).unwrap();
    let msg = hash_signing_message(&signed);
    let sk = SigningKey::from_seed(VAL_SEED);
    Block {
        header,
        body,
        proposer_signature: sign_message_hash(&sk, &msg).to_bytes(),
    }
}

/// 单验证者 PrecommitQC（`context.height = 0` ⇒ 其子块高度 1；与 fact 的 `height = 1` 一致）。
fn precommit_qc_a(genesis_hash: [u8; 32], target: [u8; 32]) -> QuorumCertificate {
    let id = validator_id_of_seed(VAL_SEED);
    let vote = ValidatorVote {
        height: 0,
        round: 0,
        target_block_hash: target,
        vote_type: VoteType::Precommit,
        source_block_hash: [0u8; 32],
        validator_id: id,
        timestamp: 0,
    };
    let payload = canonical_vote_payload(&vote);
    let signed = build_signed_bytes(
        AlgorithmId::Ed25519,
        DomainId::ValidatorVote,
        CHAIN_ID,
        &payload,
    )
    .unwrap();
    let sk = SigningKey::from_seed(VAL_SEED);
    let sig = sign_message_hash(&sk, &hash_signing_message(&signed)).to_bytes();
    QuorumCertificate {
        context: QcContext {
            chain_id: CHAIN_ID,
            height: 0,
            round: 0,
            vote_type: VoteType::Precommit,
        },
        target,
        validator_set_id: genesis_hash,
        evidence: vec![QcEvidence {
            validator_id: id,
            source_block_hash: vote.source_block_hash,
            timestamp: vote.timestamp,
            signature: sig,
        }],
    }
}

/// 构造「finality durable、commit 前 crash」的持久状态：block X（height1、parent genesis）
/// 以 **`put_verified`**（生产写侧同款：`(hash, proposer)` encoding）落盘 + 写 Recovery Fact(X)。
/// 返回 `(X hash, genesis hash)`。
fn write_crash_state(config: &NodeConfig) -> ([u8; 32], [u8; 32]) {
    let adapter = nova_node::bootstrap::start(NoAccountsKeyResolver, config).unwrap();
    let genesis_hash = adapter.genesis_hash();
    let block = signed_block_a(genesis_hash, *adapter.store().state_root().as_bytes());
    let a_hash = block_hash(&block).unwrap();
    let proposer_vk = SigningKey::from_seed(VAL_SEED).verifying_key();
    adapter
        .block_store()
        .unwrap()
        .put_verified(
            &block,
            validator_id_of_seed(VAL_SEED).as_bytes(),
            &proposer_vk,
            CHAIN_ID,
            1,
        )
        .expect("verified encoding 落盘");
    let qc = precommit_qc_a(genesis_hash, a_hash);
    persist_finality_fact(
        &config.storage_dir.join(FINALITY_FACT_FILE),
        NetworkId::Mainnet,
        CHAIN_ID,
        genesis_hash,
        1,
        a_hash,
        &qc,
    )
    .expect("fact 写成功");
    (a_hash, genesis_hash)
}

/// 断言 `pubkey_from_seed(VAL_SEED)` 确实是本 rig genesis 的验证者（防止 fixture 漂移）。
fn assert_validator_matches_rig(genesis_hash: [u8; 32]) {
    let _ = (pubkey_from_seed(VAL_SEED), genesis_hash);
    assert_eq!(
        validator_id_of_seed(VAL_SEED),
        d10_p1_a10_common::validator_id_of_seed(VAL_SEED),
        "seed 派生身份确定性"
    );
}

// ---------------------------------------------------------------------------
// A22-1 — fact 可恢复；不 panic；bridge 仍 commit X
// ---------------------------------------------------------------------------

#[test]
fn d10_a22_t1_recovery_fact_restores_and_commits() {
    let env = Env::new("a22t1", &[VAL_SEED]);
    let config = env.config("a", None, Vec::new());
    let (a_hash, genesis_hash) = write_crash_state(&config);
    assert_validator_matches_rig(genesis_hash);

    let mut node = start_node(&env, "a", VAL_SEED, NET_SEED, None, Vec::new());
    // (1) recovery fact 可以恢复（只读观测；G4 后不 gate 任何行为）。
    assert!(node.rt.recovering_finality(), "启动即处于恢复窗口");
    assert_eq!(head_height(&node.rt), 0);
    assert_eq!(
        finalized_ref(&node.rt),
        Some(a_hash),
        "fact 已注入 finality"
    );

    // (2) 不 panic；bridge 以 fact QC 为第三证据源完成 commit。
    let mut committed = false;
    for _ in 0..20 {
        node.rt
            .step()
            .expect("step 必须 Ok（不 panic / 不 fail-closed）");
        if head_hash(&node.rt) == a_hash {
            committed = true;
            break;
        }
    }
    assert!(
        committed,
        "bridge 从 verified encoding commit X（head == X）"
    );
    assert_eq!(head_height(&node.rt), 1);
    assert!(!node.rt.recovering_finality(), "head == X ⇒ 状态清理");
    node.rt.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// A22-2 — 恢复窗口不冻结 consensus 活性（head 必须跨过 X）
// ---------------------------------------------------------------------------

#[test]
fn d10_a22_t2_recovery_window_does_not_freeze_consensus() {
    let env = Env::new("a22t2", &[VAL_SEED]);
    let config = env.config("a", None, Vec::new());
    let (_a_hash, _) = write_crash_state(&config);

    let mut node = start_node(&env, "a", VAL_SEED, NET_SEED, None, Vec::new());
    assert!(node.rt.recovering_finality(), "恢复窗口成立");

    // (3) 活动性：本地出块 / 投票 / 推进不得被冻结 ⇒ head 必须跨过 X（≥ 2）。
    let mut reached = 0u64;
    for _ in 0..80 {
        node.rt.step().expect("step 必须 Ok");
        reached = head_height(&node.rt);
        if reached >= 2 {
            break;
        }
    }
    assert!(
        reached >= 2,
        "恢复窗口不得冻结活性：head 必须推进到 ≥ 2（实际 {reached}）"
    );
    assert!(
        node.rt.last_proposal().is_some(),
        "本地出块照常（G4：无 hard guard）"
    );
    assert!(
        node.rt
            .consensus()
            .state()
            .finality
            .finalized_reference
            .is_some(),
        "finality 服务正常"
    );
    node.rt.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// A22-3 — commit 后 head == finalized ⇒ 恢复 consensus（proposal / 推进恢复）
// ---------------------------------------------------------------------------

#[test]
fn d10_a22_t3_completion_resumes_consensus() {
    let env = Env::new("a22t3", &[VAL_SEED]);
    let config = env.config("a", None, Vec::new());
    let (a_hash, _) = write_crash_state(&config);

    let mut node = start_node(&env, "a", VAL_SEED, NET_SEED, None, Vec::new());
    node.rt.step().expect("step 1（bridge commit X）");
    assert_eq!(
        head_hash(&node.rt),
        a_hash,
        "head == finalized（恢复完成条件）"
    );
    assert!(!node.rt.recovering_finality(), "状态回到 Normal");
    assert_eq!(
        node.rt.consensus().state().round.height,
        1,
        "commit 后已按 durable head 推进到高度 1 轮"
    );

    // Normal：恢复出块（head → 2）。
    let mut advanced = false;
    for _ in 0..40 {
        node.rt.step().expect("step（Normal）");
        if head_height(&node.rt) >= 2 {
            advanced = true;
            break;
        }
    }
    assert!(advanced, "恢复完成后必须恢复出块（head 推进到 2）");
    assert!(
        node.rt.last_proposal().is_some(),
        "Normal 下本地 proposal 恢复"
    );
    assert_eq!(head_height(&node.rt), 2);
    assert!(
        node.rt
            .consensus()
            .state()
            .finality
            .finalized_reference
            .is_some(),
        "finality 持续推进"
    );
    node.rt.shutdown().unwrap();
}

// ---------------------------------------------------------------------------
// A22-4 — Normal 不受影响（无 fact ⇒ guard 不得伤及既有活性）
// ---------------------------------------------------------------------------

#[test]
fn d10_a22_t4_normal_mode_unaffected_by_recovery_guard() {
    let env = Env::new("a22t4", &[VAL_SEED]);
    // 无 crash 状态（无 fact / 无 block）⇒ 启动即 Normal。
    let mut node = start_node(&env, "a", VAL_SEED, NET_SEED, None, Vec::new());
    assert!(
        !node.rt.recovering_finality(),
        "无 fact ⇒ Normal（guard 不生效）"
    );

    let mut advanced = false;
    for _ in 0..40 {
        node.rt.step().expect("step（Normal）");
        if head_height(&node.rt) >= 1 {
            advanced = true;
            break;
        }
    }
    assert!(advanced, "Normal 必须正常出块（head → 1）");
    assert!(node.rt.last_proposal().is_some());
    assert!(
        node.rt
            .consensus()
            .state()
            .finality
            .finalized_reference
            .is_some(),
        "Normal 正常达成 finality"
    );
    node.rt.shutdown().unwrap();
}
