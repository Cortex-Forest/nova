# nova-network

YAZIMAO P2P 网络层（STEP 9 起；运行时基础设施**已实现**，libp2p **未采用**）。

## 状态

- **已实现**：`node_id`、`message`（MessageEnvelope / MessageType / canonical codec / 签名与验证）、
  `transport`（含生产 `std::net` TcpTransport）、`gossip`、`sync`、`session`、`security`、
  `network_service`、`event_loop`；消息族含 `round_change_limit` / `abandon_attestation`
  （ADR-0032 / ADR-0055 / ADR-0056 / ADR-0059 / ADR-0073 / ADR-0075）。
- `NOT IMPLEMENTED`（本项目**未采用** libp2p）：libp2p adapter / QUIC / Noise / Gossipsub 调度；
  完整状态同步亦未实现。当前网络实现为自研 TCP transport（ADR-0032 P2P 架构）。
- 边界（ADR-0032 N-1）：`network → core`、`network → crypto`；**禁止** `network → execution` /
  `network → storage`（消息层不执行状态转换）。

## 纪律

- 网络协议必须先定义边界（Message ID / Version / Encoding / Max Size / Timeout，Master Prompt §21）。
- 必须防御 Eclipse / Sybil / DDoS / Spam / Gossip Amplification（Master Prompt §20）。

## 测试

```bash
cargo test -p nova-network
```
