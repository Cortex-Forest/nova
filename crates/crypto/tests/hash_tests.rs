//! `nova_crypto::hash` 集成测试（STEP 2 交付要求 3-6）。
//!
//! 覆盖：known vectors / empty input / large input / deterministic。
//! 与单元测试（src/hash.rs）互补，从 crate 外部 API 角度验证。

use nova_crypto::hash::{content_hash, protocol_hash};

fn hex32(s: &str) -> [u8; 32] {
    assert_eq!(s.len(), 64);
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in out.iter_mut().enumerate() {
        let hi = match bytes[i * 2] {
            b'0'..=b'9' => bytes[i * 2] - b'0',
            b'a'..=b'f' => bytes[i * 2] - b'a' + 10,
            _ => panic!("bad hex"),
        };
        let lo = match bytes[i * 2 + 1] {
            b'0'..=b'9' => bytes[i * 2 + 1] - b'0',
            b'a'..=b'f' => bytes[i * 2 + 1] - b'a' + 10,
            _ => panic!("bad hex"),
        };
        *b = (hi << 4) | lo;
    }
    out
}

#[test]
fn protocol_hash_known_vectors() {
    assert_eq!(
        protocol_hash(b"abc"),
        hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

#[test]
fn content_hash_known_vectors() {
    assert_eq!(
        content_hash(b"abc"),
        hex32("6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
    );
}

#[test]
fn empty_input_vectors() {
    assert_eq!(
        protocol_hash(b""),
        hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
    assert_eq!(
        content_hash(b""),
        hex32("af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
    );
}

#[test]
fn large_input_deterministic() {
    // 4 MiB 固定模式数据：确定性与一致长度。
    let data: Vec<u8> = (0..(4 * 1024 * 1024)).map(|i| (i % 253) as u8).collect();
    let a = protocol_hash(&data);
    let b = protocol_hash(&data);
    assert_eq!(a, b);
    assert_eq!(a.len(), 32);

    let ca = content_hash(&data);
    let cb = content_hash(&data);
    assert_eq!(ca, cb);
    assert_eq!(ca.len(), 32);
}

#[test]
fn protocol_and_content_differ() {
    // 同一输入，两种哈希输出不同（独立用途，ADR-0006）。
    let data = b"nova";
    assert_ne!(protocol_hash(data), content_hash(data));
}
