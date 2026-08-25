//! JSON 解析辅助（serde_json）+ 重复键检测（STEP 1 §21）。
//!
//! serde_json 对重复键默认"后者覆盖"而不报错；协议测试向量要求显式检测重复键
//! （防 fixture 歧义 / tampering / parser ambiguity）。

use serde_json::Value;

/// JSON 错误。
#[derive(Debug)]
pub enum JsonError {
    /// 解析失败。
    Parse(serde_json::Error),
    /// 存在重复键（重复键路径列表，如 `["a.b", "x"]`）。
    DuplicateKeys(Vec<String>),
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "json parse error: {e}"),
            Self::DuplicateKeys(keys) => {
                write!(f, "duplicate json keys: {}", keys.join(", "))
            }
        }
    }
}

impl std::error::Error for JsonError {}

use std::fmt;

/// 解析 JSON 并检测重复键。
pub fn parse(input: &str) -> Result<Value, JsonError> {
    if let Some(dups) = detect_duplicate_keys(input) {
        return Err(JsonError::DuplicateKeys(dups));
    }
    serde_json::from_str(input).map_err(JsonError::Parse)
}

/// 检测 JSON 字符串中的重复对象键；返回重复键路径列表（有则 `Some`）。
fn detect_duplicate_keys(input: &str) -> Option<Vec<String>> {
    let bytes = input.as_bytes();
    let mut pos = 0usize;
    let mut dups = Vec::new();
    let mut path: Vec<String> = Vec::new();
    parse_value(bytes, &mut pos, &mut path, &mut dups);
    if dups.is_empty() { None } else { Some(dups) }
}

fn skip_ws(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && b[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn parse_value(b: &[u8], pos: &mut usize, path: &mut Vec<String>, dups: &mut Vec<String>) {
    skip_ws(b, pos);
    if *pos >= b.len() {
        return;
    }
    match b[*pos] {
        b'{' => parse_object(b, pos, path, dups),
        b'[' => parse_array(b, pos, path, dups),
        b'"' => {
            let _ = parse_string(b, pos);
        }
        _ => skip_value(b, pos),
    }
}

fn parse_object(b: &[u8], pos: &mut usize, path: &mut Vec<String>, dups: &mut Vec<String>) {
    *pos += 1; // consume '{'
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b'}' {
        *pos += 1;
        return;
    }
    let mut seen: Vec<String> = Vec::new();
    loop {
        skip_ws(b, pos);
        if *pos >= b.len() || b[*pos] != b'"' {
            return; // malformed; serde will report
        }
        let key = match parse_string(b, pos) {
            Some(k) => k,
            None => return,
        };
        if seen.contains(&key) {
            let mut p = path.join(".");
            if !p.is_empty() {
                p.push('.');
            }
            p.push_str(&key);
            dups.push(p);
        } else {
            seen.push(key.clone());
        }
        skip_ws(b, pos);
        if *pos < b.len() && b[*pos] == b':' {
            *pos += 1;
        } else {
            return;
        }
        path.push(key);
        parse_value(b, pos, path, dups);
        path.pop();
        skip_ws(b, pos);
        if *pos >= b.len() {
            return;
        }
        match b[*pos] {
            b',' => *pos += 1,
            b'}' => {
                *pos += 1;
                return;
            }
            _ => return,
        }
    }
}

fn parse_array(b: &[u8], pos: &mut usize, path: &mut Vec<String>, dups: &mut Vec<String>) {
    *pos += 1; // '['
    skip_ws(b, pos);
    if *pos < b.len() && b[*pos] == b']' {
        *pos += 1;
        return;
    }
    loop {
        parse_value(b, pos, path, dups);
        skip_ws(b, pos);
        if *pos >= b.len() {
            return;
        }
        match b[*pos] {
            b',' => *pos += 1,
            b']' => {
                *pos += 1;
                return;
            }
            _ => return,
        }
    }
}

/// 解析 JSON 字符串（处理转义），返回内容（不含引号）。
fn parse_string(b: &[u8], pos: &mut usize) -> Option<String> {
    if *pos >= b.len() || b[*pos] != b'"' {
        return None;
    }
    *pos += 1;
    let mut buf: Vec<u8> = Vec::new();
    while *pos < b.len() {
        let c = b[*pos];
        *pos += 1;
        match c {
            b'"' => return String::from_utf8(buf).ok(),
            b'\\' => {
                if *pos >= b.len() {
                    return None;
                }
                let e = b[*pos];
                *pos += 1;
                match e {
                    b'"' => buf.push(b'"'),
                    b'\\' => buf.push(b'\\'),
                    b'/' => buf.push(b'/'),
                    b'b' => buf.push(8),
                    b'f' => buf.push(12),
                    b'n' => buf.push(b'\n'),
                    b'r' => buf.push(b'\r'),
                    b't' => buf.push(b'\t'),
                    b'u' => {
                        if *pos + 4 > b.len() {
                            return None;
                        }
                        let hex_str = std::str::from_utf8(&b[*pos..*pos + 4]).ok()?;
                        let code = u32::from_str_radix(hex_str, 16).ok()?;
                        *pos += 4;
                        let ch = char::from_u32(code)?;
                        let mut tmp = [0u8; 4];
                        buf.extend_from_slice(ch.encode_utf8(&mut tmp).as_bytes());
                    }
                    _ => return None,
                }
            }
            _ => buf.push(c),
        }
    }
    None
}

/// 跳过非结构化的标量值（数字 / true / false / null）。
fn skip_value(b: &[u8], pos: &mut usize) {
    while *pos < b.len() && !matches!(b[*pos], b',' | b']' | b'}') && !b[*pos].is_ascii_whitespace()
    {
        *pos += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn duplicate_keys_detected() {
        let s = r#"{"id": "a", "id": "b", "nested": {"x": 1, "x": 2}}"#;
        let dups = detect_duplicate_keys(s).unwrap_or_default();
        assert_eq!(dups, vec!["id".to_string(), "nested.x".to_string()]);
    }

    #[test]
    fn unique_keys_ok() {
        let s = r#"{"id": "a", "nested": {"x": 1}}"#;
        assert!(detect_duplicate_keys(s).is_none());
        assert!(parse(s).is_ok());
    }
}
