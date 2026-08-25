//! `nova-node` 冒烟测试（PHASE 1）。

use nova_node::config::Config;

/// 冒烟测试：配置骨架可构造（unit struct 字面量）。
#[test]
fn config_constructible() {
    let _ = Config;
}
