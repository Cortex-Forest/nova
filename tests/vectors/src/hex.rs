//! 严格小写 hex 解码（crypto-test-vectors-v1.md §4）。
//!
//! 拒绝：odd-length、非法字符、大写（规范要求小写）、空白、`0x` 前缀。

use std::fmt;

/// Hex 解码错误。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HexError {
    /// 奇数长度。
    OddLength,
    /// 非法字符。
    InvalidCharacter(u8),
    /// 大写字符（规范要求小写，必须拒绝）。
    Uppercase(u8),
    /// 含空白。
    Whitespace,
    /// `0x` / `0X` 前缀（规范不允许时必须拒绝）。
    ZeroXPrefix,
}

impl fmt::Display for HexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OddLength => write!(f, "odd-length hex string"),
            Self::InvalidCharacter(c) => write!(f, "invalid hex character: {c:#x}"),
            Self::Uppercase(c) => write!(f, "uppercase hex character not allowed: {c:#x}"),
            Self::Whitespace => write!(f, "whitespace not allowed in hex"),
            Self::ZeroXPrefix => write!(f, "0x prefix not allowed"),
        }
    }
}

impl std::error::Error for HexError {}

const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// 严格小写 hex 解码。
pub fn decode_strict_lower_hex(input: &str) -> Result<Vec<u8>, HexError> {
    if input.starts_with("0x") || input.starts_with("0X") {
        return Err(HexError::ZeroXPrefix);
    }
    if input.bytes().any(|b| b.is_ascii_whitespace()) {
        return Err(HexError::Whitespace);
    }
    if !input.len().is_multiple_of(2) {
        return Err(HexError::OddLength);
    }
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        let hi = decode_nibble(chunk[0])?;
        let lo = decode_nibble(chunk[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn decode_nibble(b: u8) -> Result<u8, HexError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Err(HexError::Uppercase(b)),
        other => Err(HexError::InvalidCharacter(other)),
    }
}

/// 将字节编码为小写 hex。
pub fn encode_lower_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX_LOWER[(b >> 4) as usize] as char);
        s.push(HEX_LOWER[(b & 0x0f) as usize] as char);
    }
    s
}
