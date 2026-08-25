//! `nova-storage` 冒烟测试（PHASE 1）。

use nova_storage::DATABASE_VERSION;

/// 冒烟测试：数据库版本常量已定义。
#[test]
fn database_version_is_defined() {
    assert_eq!(DATABASE_VERSION, 1);
}
