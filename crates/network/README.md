# nova-network

Nova Chain P2P 网络层（**PHASE 1 占位**）。

## 状态

- `NOT IMPLEMENTED`（无任何 P2P 逻辑）。
- 技术选型：rust-libp2p（Gossipsub / Kademlia / Noise / QUIC），待 PHASE 8 + ADR。

## 纪律

- 网络协议必须先定义边界（Message ID / Version / Encoding / Max Size / Timeout，Master Prompt §21）。
- 必须防御 Eclipse / Sybil / DDoS / Spam / Gossip Amplification（Master Prompt §20）。

## 测试

```bash
cargo test -p nova-network
```
