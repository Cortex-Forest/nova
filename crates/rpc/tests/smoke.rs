//! `nova-rpc` 冒烟测试（PHASE 1）。

use nova_rpc::API_VERSION;

/// 冒烟测试：API 版本常量已定义。
#[test]
fn api_version_is_defined() {
    assert_eq!(API_VERSION, "v1");
}
