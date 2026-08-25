//! `nova-core` 冒烟测试（PHASE 1）。
//!
//! 本阶段无业务逻辑，仅验证测试基础设施可用。

use nova_core::PROTOCOL_VERSION;
use nova_core::error::ErrorKind;

/// 冒烟测试：协议版本常量已定义且非空。
#[test]
fn protocol_version_is_defined() {
    assert!(!PROTOCOL_VERSION.is_empty());
}

/// 冒烟测试：错误分类骨架可用，且 8 个分类互不相同。
#[test]
fn error_kind_classification_exists() {
    let kinds = [
        ErrorKind::Core,
        ErrorKind::Crypto,
        ErrorKind::Network,
        ErrorKind::Storage,
        ErrorKind::Consensus,
        ErrorKind::Execution,
        ErrorKind::Rpc,
        ErrorKind::Wallet,
    ];
    let mut seen = std::collections::HashSet::new();
    for kind in kinds {
        assert!(seen.insert(kind), "duplicate error kind: {kind:?}");
    }
    assert_eq!(seen.len(), 8);
}
