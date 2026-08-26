//! 生成器（一次性开发工具）：生成**真实 Bech32m 地址向量**（STEP 5）。
//!
//! - 合法地址：用 `nova_crypto::address`（生产 codec）从 payload 编码。
//! - 破坏/越权情形：用 bech32 直接构造（未知 HRP / 跨网 HRP / 坏版本 / 未知类型 /
//!   错误长度 / 大小写 / 截断 / 追加 / 篡改字符）。
//! - 运行：`cargo run -p nova-test-vectors --bin gen_address_vectors`。
//! - 运行时测试用 `include_str!`（编译期内嵌，确定性）。
//! - 本工具**不含任何生产密码学实现**；仅复用 codec 按冻结规范（ADR-0004）生成期望值。

use bech32::{Bech32m, Hrp};
use nova_crypto::address::{
    ADDRESS_VERSION, AddressType, NetworkId, NovaAddress, NovaAddressPayload,
};
use nova_test_vectors::hex;
use serde_json::{Value, json};

const KH_A: [u8; 32] = [0xab; 32];
const KH_B: [u8; 32] = [0x5c; 32];
const KH_C: [u8; 32] = [0x1f; 32];

/// payload → 35 字节（version ‖ type ‖ network ‖ key_hash；与 codec 一致）。
fn payload_bytes(version: u8, at: u8, net: u8, kh: &[u8; 32]) -> Vec<u8> {
    let mut b = Vec::with_capacity(35);
    b.push(version);
    b.push(at);
    b.push(net);
    b.extend_from_slice(kh);
    b
}

/// 用任意 HRP 编码任意数据（bech32m checksum）。
fn bech32m_encode(hrp: &str, data: &[u8]) -> String {
    let hrp = Hrp::parse(hrp).expect("valid hrp");
    bech32::encode::<Bech32m>(hrp, data).expect("bech32m encode")
}

/// 用生产 codec 编码（合法地址）。
fn encode_prod(net: NetworkId, at: AddressType, kh: [u8; 32]) -> String {
    NovaAddress::from_payload(NovaAddressPayload {
        address_version: ADDRESS_VERSION,
        address_type: at,
        network_id: net,
        key_hash: kh,
    })
    .encode()
    .expect("prod encode")
}

/// 写向量 JSON。
fn write_vector(base: &std::path::Path, v: Value) {
    let id = v["id"].as_str().expect("id").to_string();
    let path = base.join(format!("{id}.json"));
    let out = serde_json::to_string_pretty(&v).expect("json");
    std::fs::write(&path, format!("{out}\n")).expect("write");
    println!("wrote: {}", path.display());
}

/// 向量元数据（payload 期望字段；破坏情形为"元数据"而非合法 payload）。
struct Meta {
    net: u8,
    at: u8,
    version: u8,
    kh: [u8; 32],
}

fn meta(net: u8, at: u8, version: u8, kh: [u8; 32]) -> Meta {
    Meta {
        net,
        at,
        version,
        kh,
    }
}

fn valid_vector(id: &str, addr: String, m: &Meta, note: &str) -> Value {
    json!({
        "id": id,
        "category": "address",
        "address": addr,
        "network_id": m.net,
        "address_type": m.at,
        "address_version": m.version,
        "key_hash": hex::encode_lower_hex(&m.kh),
        "expected": "VALID",
        "expected_error": null,
        "note": note,
    })
}

fn invalid_vector(id: &str, addr: String, m: &Meta, expected_error: &str, note: &str) -> Value {
    json!({
        "id": id,
        "category": "address",
        "address": addr,
        "network_id": m.net,
        "address_type": m.at,
        "address_version": m.version,
        "key_hash": hex::encode_lower_hex(&m.kh),
        "expected": "INVALID",
        "expected_error": expected_error,
        "note": note,
    })
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let base = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("address");
    let m_main = meta(0x01, 0x01, 0x01, KH_A);
    let m_test = meta(0x02, 0x01, 0x01, KH_B);
    let m_dev = meta(0x03, 0x01, 0x01, KH_C);

    // ---- VALID：三网络 ----
    write_vector(
        &base,
        valid_vector(
            "address-mainnet-valid-001",
            encode_prod(NetworkId::Mainnet, AddressType::UserAccount, KH_A),
            &m_main,
            "mainnet user account (canonical nova1...)",
        ),
    );
    write_vector(
        &base,
        valid_vector(
            "address-testnet-valid-001",
            encode_prod(NetworkId::Testnet, AddressType::UserAccount, KH_B),
            &m_test,
            "testnet user account (canonical novat1...)",
        ),
    );
    write_vector(
        &base,
        valid_vector(
            "address-devnet-valid-001",
            encode_prod(NetworkId::Devnet, AddressType::UserAccount, KH_C),
            &m_dev,
            "devnet user account (canonical novad1...)",
        ),
    );

    let base_addr = encode_prod(NetworkId::Mainnet, AddressType::UserAccount, KH_A);

    // ---- INVALID：未知 HRP（bitcoin1 + 合法 checksum）----
    write_vector(
        &base,
        invalid_vector(
            "address-wrong-hrp-001",
            bech32m_encode("bitcoin", &payload_bytes(0x01, 0x01, 0x01, &KH_A)),
            &m_main,
            "InvalidHrp",
            "HRP 'bitcoin' 未注册（非 nova/novat/novad）",
        ),
    );

    // ---- INVALID：跨网（mainnet payload 但 novat HRP，checksum 合法）----
    write_vector(
        &base,
        invalid_vector(
            "address-wrong-network-001",
            bech32m_encode("novat", &payload_bytes(0x01, 0x01, 0x01, &KH_A)),
            &m_main,
            "NetworkMismatch",
            "HRP 网络 novat 与 payload network_id=mainnet 不一致",
        ),
    );

    // ---- INVALID：坏 checksum（篡改校验区一字符）----
    let mut c: Vec<char> = base_addr.chars().collect();
    let n = c.len();
    c[n - 1] = if c[n - 1] == 'q' { 'p' } else { 'q' };
    let bad_ck: String = c.into_iter().collect();
    write_vector(
        &base,
        invalid_vector(
            "address-wrong-checksum-001",
            bad_ck,
            &m_main,
            "InvalidChecksum",
            "checksum 区被篡改",
        ),
    );

    // ---- INVALID：未知版本（payload version=0x02）----
    write_vector(
        &base,
        invalid_vector(
            "address-unknown-version-001",
            bech32m_encode("nova", &payload_bytes(0x02, 0x01, 0x01, &KH_A)),
            &meta(0x01, 0x01, 0x02, KH_A),
            "UnsupportedVersion",
            "address_version=0x02 未注册（当前 0x01）",
        ),
    );

    // ---- INVALID：未知类型（payload type=0x99）----
    write_vector(
        &base,
        invalid_vector(
            "address-unknown-type-001",
            bech32m_encode("nova", &payload_bytes(0x01, 0x99, 0x01, &KH_A)),
            &meta(0x01, 0x99, 0x01, KH_A),
            "UnknownAddressType",
            "address_type=0x99 未注册（仅 0x01 User Account）",
        ),
    );

    // ---- INVALID：错误 payload 长度（36 字节）----
    let mut long = payload_bytes(0x01, 0x01, 0x01, &KH_A);
    long.push(0x00); // 36 字节
    write_vector(
        &base,
        invalid_vector(
            "address-wrong-payload-length-001",
            bech32m_encode("nova", &long),
            &m_main,
            "InvalidLength",
            "payload 36 字节 ≠ 35",
        ),
    );

    // ---- INVALID：大写（全大写）----
    write_vector(
        &base,
        invalid_vector(
            "address-uppercase-001",
            base_addr.to_uppercase(),
            &m_main,
            "NonCanonicalCase",
            "全大写地址拒绝（canonical 为小写）",
        ),
    );

    // ---- INVALID：混合大小写----
    {
        let mut mb: Vec<u8> = base_addr.bytes().collect();
        let sep = base_addr.find('1').unwrap();
        mb[sep + 1] = mb[sep + 1].to_ascii_uppercase();
        let mixed = String::from_utf8(mb).unwrap();
        write_vector(
            &base,
            invalid_vector(
                "address-mixed-case-001",
                mixed,
                &m_main,
                "NonCanonicalCase",
                "混合大小写拒绝",
            ),
        );
    }

    // ---- INVALID：截断（去尾部 4 字符）----
    write_vector(
        &base,
        invalid_vector(
            "address-truncated-001",
            base_addr[..base_addr.len() - 4].to_string(),
            &m_main,
            "InvalidChecksum",
            "截断导致 checksum 失效",
        ),
    );

    // ---- INVALID：追加一字符----
    write_vector(
        &base,
        invalid_vector(
            "address-extra-char-001",
            format!("{base_addr}q"),
            &m_main,
            "InvalidChecksum",
            "追加字符导致 checksum 失效",
        ),
    );

    // ---- INVALID：数据区篡改一字符----
    {
        let mut mc: Vec<char> = base_addr.chars().collect();
        let sep = base_addr.find('1').unwrap();
        mc[sep + 2] = if mc[sep + 2] == 'q' { 'p' } else { 'q' };
        let mut_char: String = mc.into_iter().collect();
        write_vector(
            &base,
            invalid_vector(
                "address-mutated-char-001",
                mut_char,
                &m_main,
                "InvalidChecksum",
                "data 区篡改一字符（key_hash 变化但 checksum 失效）",
            ),
        );
    }

    Ok(())
}
