# TUN 模式设计（hub-and-spoke 组网）

范围：每台机器一个 TUN 接口；一台跑 `tun serve` 做 **hub**，其余用 `tun connect`
加入。**同一虚拟网段内任意 VIP 可达**（含 spoke↔spoke，由 hub 按目的 VIP 转发）。
与现有 `serve`/`connect`（stream 转发）**并存**，互不取代。

不做：无 hub 的全互联 mesh、节点自动发现、ACL（见 roadmap）。

本文件只做裁决，不罗列选项。每条给出明确选择和理由。

---

## 决策 0：拓扑 —— hub-and-spoke（不是点对点独占）

**选择**：`tun serve` 并发接受多个会话；本地 TUN 按目的 VIP 解复用到对应连接；
spoke 发来的包若目的是另一 spoke 的 VIP，则 **在 hub 上转发**，不经本机协议栈。

```
spoke A ──QUIC──┐
                ├── hub (tun serve) ── 本机 TUN / 应用
spoke B ──QUIC──┘
         A↔B 经 hub 按内层目的 VIP 转发
```

- Spoke 侧安装 `172.24.0.0/16` 进 TUN（不只是 hub 的 /32），这样发往任意 mesh VIP
  的包都会进隧道，由 hub 投递。
- Hub 侧仍为每个在线 peer 装 `/32`，便于本机访问该 VIP，并在断开时清理。
- 源地址校验：丢弃源 VIP ≠ 该连接握手 VIP 的包（防冒充）。
- 同一 VIP 第二次加入：拒绝（地址簿冲突）。

理由：虚拟 IP 的意义就是「组网后彼此可达」；点对点单会话会让第二台客户端
拨号超时，且无法解释 /16 派生地址空间。全互联（每人对每人建连）留作后续，
需要地址簿广播；hub 转发已满足「互相 ping VIP」的产品预期。

---

## 决策 1：地址分配 —— 默认从 EndpointId 确定性派生，实际地址握手时交换

**选择**：默认虚拟 IP = `f(EndpointId)`；**实际绑定地址在握手时经一次性 bidi stream 交换**。**仅 IPv4**（`172.24.0.0/16`）。

```
vip(ep) = 172.24.0.0/16 段内，取 BLAKE3(EndpointId) 的低 16 bit 作为主机位
        = 0xAC18_0000 | (blake3(ep) 低 2 字节)
```

- 多节点碰撞由本地 `ensure_vip_free` + hub 拒绝重复 VIP 兜底。
- **不用 100.64.0.0/10**：Tailscale netfilter 会 DROP 非 tailscale0 入口的 100.64/10 源地址。
- Spoke 装整段 `/16`；hub 按 peer 装 `/32`。协议 ALPN：`link-p2p/tun/1`。
- `--tun-ip` 覆盖本端地址。

## 决策 2：MTU —— 运行时钳制到 `max_datagram_size()`，默认 1280

与先前一致：最终 MTU = `min(--mtu, max_datagram_size())`，默认上限 1280；超限注入 ICMP Frag Needed；升/降 MTU 带滞回。详见实现与 `docs/tun-acceptance.md`。

## 决策 3：与 stream 模式并存

```
link-p2p tun serve  [--tun-ip <addr>] [--mtu <mtu>]   # hub
link-p2p tun connect --to <EndpointId> [...]          # spoke
```

## 决策 4：仍出界（roadmap）

无 hub 全互联、自动发现、ACL、独立路由协议。

---

## 传输层

内层 IP 用 QUIC **datagram**（不可靠），避免 stream 队头阻塞。

## 数据流

```
A 应用 → tun → spoke A → hub 连接
hub: 目的=本机 VIP → 写 hub TUN
     目的=其他 spoke → 转发
B: 收 datagram → 写 tun → B 应用
```

## 权限与平台

特权模式（root / CAP_NET_ADMIN / Administrator + wintun.dll）。Linux / macOS / Windows。
