//! P2P 节点身份（STEP 9-2 — ADR-0032 N-2）。
//!
//! - `NodeId([u8; 32])` = **Ed25519 公钥 canonical bytes**（非 `Hash(pubkey)`——
//!   可直接验证签名、免 key lookup、与 validator identity 体系一致）。
//! - **NodeId（P2P 身份）≠ NovaAddress（链账户）≠ ValidatorId（共识身份）**，三者禁混用（N-2）。

use core::fmt;
use nova_crypto::signature::VerifyingKey;

/// P2P 节点身份（Ed25519 公钥 canonical bytes）。
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// 从节点公钥派生（`canonical pubkey bytes`；N-2）。
    pub fn from_verifying_key(vk: &VerifyingKey) -> Self {
        Self(vk.to_bytes())
    }

    /// 从 32 字节反序列化恢复。
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// 读取内部字节。
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

fn hex_str(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({})", hex_str(&self.0))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex_str(&self.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nova_crypto::key::KeyPair;

    #[test]
    fn node_id_derives_from_public_key_bytes() {
        let kp = KeyPair::generate().unwrap();
        let id = NodeId::from_verifying_key(kp.verifying_key());
        assert_eq!(id.as_bytes(), &kp.verifying_key().to_bytes());
        // 同一 key ⇒ 同一 NodeId（确定性）
        let id2 = NodeId::from_verifying_key(kp.verifying_key());
        assert_eq!(id, id2);
        // 不同 key ⇒ 不同 NodeId
        let kp2 = KeyPair::generate().unwrap();
        assert_ne!(id, NodeId::from_verifying_key(kp2.verifying_key()));
    }

    #[test]
    fn node_id_roundtrip() {
        let kp = KeyPair::generate().unwrap();
        let id = NodeId::from_verifying_key(kp.verifying_key());
        let restored = NodeId::from_bytes(*id.as_bytes());
        assert_eq!(id, restored);
    }
}
