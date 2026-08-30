# TUN 模式设计（hub 协调 + 可选直连）

范围：每台机器一个 TUN 接口；一台跑 `tun serve` 做 **协调 hub**（成员表 +
兜底转发），其余用 `tun connect` 加入。**同一虚拟网段内任意 VIP 可达**；能打通
NAT 时 spoke↔spoke 走直连 QUIC，打不穿时退回 hub 按目的 VIP 转发。与现有
`serve`/`connect`（stream 转发）**并存**，互不取代。

本文件只做裁决，不罗列选项。每条给出明确选择和理由。

---

## 决策 0：拓扑 —— hub 协调 + 直连优先（Tailscale 模型）

**选择**：

1. `tun serve` 并发接受多个会话；本地 TUN 按目的 VIP 解复用。
2. Hub 在 VIP 握手后，经 **可靠控制流** 广播 VIP↔EndpointId 成员表（快照 /
   加入 / 离开）。ALPN：`link-p2p/tun/2`（`/1` 仅 VIP 交换、无成员表）。
3. Spoke 收到成员表后，对每个新 peer 尝试 `endpoint.connect(..., TUN_ALPN)`
   直连（iroh 发现/打洞）；转发前查本地路由：有直连用直连，否则发给 hub。
4. Hub 仍保留 spoke→spoke 转发作 **fallback**（对称 NAT 等打不穿的 pair）。
5. Hub 发送侧用 **per-peer mpsc**，避免单个 `send_datagram_wait` 阻塞拖死整条
   读循环（队头阻塞）。

```
spoke A ──QUIC──┐                    ┌── spoke B
                ├── hub (roster +      │
spoke C ──QUIC──┘    fallback)        │
         A↔B 优先直连；不通才经 hub
```

- Spoke 侧安装 `172.24.0.0/16` 进 TUN。
- Hub 侧仍为每个在线 peer 装 `/32`。
- 源地址校验：丢弃源 VIP ≠ 该连接握手 VIP 的包（防冒充）。
- 同一 VIP 第二次加入：拒绝（地址簿冲突）。
- 直连 dial 用 EndpointId 字典序打破双边同时拨号。

理由：iroh 已负责发现与打洞；缺的是应用层成员表。Hub 只做协调 + 兜底，数据面
能直连就直连，避免默认二跳。

## 决策 1：地址分配 —— 默认从 EndpointId 确定性派生，实际地址握手时交换

**选择**：默认虚拟 IP = `f(EndpointId)`；**实际绑定地址在握手时经一次性 bidi stream 交换**。**仅 IPv4**（`172.24.0.0/16`）。

```
vip(ep) = 172.24.0.0/16 段内，取 BLAKE3(EndpointId) 的低 16 bit 作为主机位
        = 0xAC18_0000 | (blake3(ep) 低 2 字节)
```

- 多节点碰撞由本地 `ensure_vip_free` + hub 拒绝重复 VIP 兜底。
- **不用 100.64.0.0/10**：Tailscale netfilter 会 DROP 非 tailscale0 入口的 100.64/10 源地址。
- Spoke 装整段 `/16`；hub 按 peer 装 `/32`。
- `--tun-ip` 覆盖本端地址。

## 决策 2：MTU —— 运行时钳制到 `max_datagram_size()`，默认 1280

最终 MTU = `min(--mtu, max_datagram_size())`，默认上限 1280；超限注入 ICMP Frag Needed；升/降 MTU 带滞回。详见实现与 `docs/tun-acceptance.md`。

## 决策 3：与 stream 模式并存；允许名单

```
link-p2p tun serve  [--tun-ip <addr>] [--mtu <mtu>] [--allow <id>]…
link-p2p tun connect --to <EndpointId> [--allow <id>]…
```

`--allow` / `LINK_P2P_ALLOW`：白名单 EndpointId。Hub 拒绝非名单入站；spoke 拒绝
非名单的直连入站/出站拨号（连 hub 本身不受此限）。拒绝走退出码 `DENIED`。

全局 `--cc bbr3` 对 lossy 链路更友好（默认 cubic）；建议先对比测再改架构预期。

## 决策 4：仍出界（roadmap）

惰性建连（仅有流量才拨）、精细 ACL（按端口/CIDR）、独立路由协议、公开 DHT
（iroh 已覆盖发现层）。

---

## 传输层

内层 IP 用 QUIC **datagram**（不可靠）；成员表用可靠 control stream（`LPR2`
帧）。**不用** stream 模式的 `STREAM_HELLO`（`LPF1`）——那属于
`link-p2p/tcp-forward/1` 的 fixed-forward 流，与 TUN ALPN 无关。

## 数据流

```
A 应用 → tun → spoke A
  → 直连到 B（若有）或 → hub → B（fallback）
B: 收 datagram → 写 tun → B 应用
```

阶段 0 诊断：`link-p2p ping` 会打出 **initial** 与 **settled** 两套 RTT/path
（握手常先走 relay，再升级直连；只看 settled）。长会话在仍走 relay 时会周期性
`network_change` 重试打洞，并对「中继限速形态」的低吞吐打黄字警告。需要仅
relay 对照时双方加 `--relay-only`；自建可重复传 `--relay`。裸 IP 上
`mtr`/`iperf3` 与 `--cc bbr3`（仅在已直连时）对比可区分链路/CC vs 选路/公共
relay 限速。优先确认服务器是否有全局 IPv6。
