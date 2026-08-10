# TUN 模式设计（v1：点对点）

范围：一台机器一个 TUN 接口，与另一台机器建立一条隧道，让**整台机器**能通过虚拟 IP 访问对端。
与现有 `serve`/`connect`（stream 转发）**并存**，互不取代。**不做 mesh**（多对点/白名单/自动发现列为下一步）。

本文件只做裁决，不罗列选项。每条给出明确选择和理由。

---

## 决策 1：地址分配 —— 从 EndpointId 确定性派生，无协调服务器

**选择**：虚拟 IP = `f(EndpointId)`，确定性函数，双方各自可算。

```
vip(ep) = 100.64.0.0/10 段内，取 BLAKE3(EndpointId) 的低 22 bit 作为主机位
        = 0x6440_0000 | (blake3(ep)[0..3] 与 0x003F_FFFF)
```

- 22 bit 主机位 → 4M 地址空间；点对点两节点碰撞概率 ~1/4M，可忽略。
- **确定性是关键**：A 知道 B 的 EndpointId 就能算出 B 的虚拟 IP，无需任何额外协议交换地址；B 同理。拨号建立连接时双方天然已持有对方 EndpointId。
- 不需要协调服务器。这决定了后续复杂度基线：**TUN v1 无任何服务端组件**。
- 已知冲突场景：本机同时跑 Tailscale 时 100.64.0.0/10 可能已被占用（本沙箱机器就有 tailscale0）。运行时必须**检查本地接口**，冲突则报错并提示 `--tun-ip` 覆盖。`--tun-ip <addr>` 显式指定本端地址，作为逃生门。

路由推论：A 只需一条路由 `ip route add <vip(B)>/32 dev tun0`。点对点不需要路由表/地址簿。

## 决策 2：MTU —— 运行时钳制到 `max_datagram_size()`，默认 1280

**选择**：TUN MTU = `min(1280, max_datagram_size())`，`max_datagram_size()` 为 `None` 时直接报错退出（datagram 未协商启用）。

开销账（外层路径 MTU = 1500 时）：

| 层 | 字节 |
|---|---|
| 外层 IPv4 头 | 20 |
| 外层 UDP 头 | 8 |
| QUIC short header（flags + pn，无 CID） | ~3 |
| DATAGRAM frame（type + varint 长度） | ~3 |
| **外层总开销** | **~34** |
| 留给内层 IP 包 | 1500 - 34 ≈ 1466 |

- 选 **1280** 的理由：内层 IPv6 最小 MTU 就是 1280，设 1280 保证任何内层协议都能承载；外层 1280+34 ≈ 1314，在 1492（PPPoE）、IPv6 外层（40B 头 → 1368）、以及走 relay 的路径上都放得下，**任何常见路径都不会触发外层分片**。
- 不要设 1500：内层 1500 的包在外层会超 1500 → 要么外层 IP 分片（QUIC 禁 IP 分片），要么丢包——这就是"能连但巨卡"的来源。
- 运行时必须 `max_datagram_size()` 钳制：noq 保证"至少 1KB 出头"，若协商值 < 1280（理论上极少见）以协商值为准。
- 内层超过 MTU 的包由内核在 TUN 接口做标准 IP 分片，隧道层不处理分片。

## 决策 3：与现有 stream 模式的关系 —— 独立子命令，共存

**选择**：新增 `link-p2p tun` 子命令，`serve`/`connect` 完全不动。

- 两个模式解决不同场景：TUN = 整机/整网段可达；stream = 转发单个端口。没有取代关系。
- CLI 形态（沿用现有 serve/connect 的角色模型）：

```
link-p2p tun serve  [--tun-ip <addr>] [--mtu <mtu>]   # 被访问侧：接受连接，创建 tun0
link-p2p tun connect --to <EndpointId> [--tun-ip <addr>] [--mtu <mtu>]  # 访问侧：拨号，创建 tun0
```

serve 侧不需要监听地址参数（虚拟 IP 由派生或 `--tun-ip` 决定，本模式没有
TCP 监听端口）。`--tun-ip` 覆盖本端虚拟 IP 派生；`--mtu`（默认 1280，> 1280
拒绝）作为 MTU 上限，最终 MTU = `min(--mtu, max_datagram_size())`。

两侧各自 `--identity`/`--relay` 语义与现有模式一致。`--tun-ip`/`--mtu` 为本模式独有。
- 不共享模式切换逻辑；两个模式的代码路径在 `tun` 模块内部完全独立，唯一共用的是 `i18n`/`style`/endpoint 构建这些基础设施。

## 决策 4：daemon 化范围 —— 仅点对点，mesh 明确出界

**选择**：v1 只做"两台机器一条隧道"。`link-p2p tun` 本身是前台常驻进程（与 `serve` 生命周期相同），systemd unit 属部署说明，不算代码范围。

**出界清单**（明确"下一步，不在本次范围"）：
- 多对点（一个 daemon 同时维护多个对端 + 虚拟 IP 到 EndpointId 的地址簿）
- 节点自动发现 / 广播
- 白名单 / ACL / 认证增强（v1 复用 QUIC/TLS 的 EndpointId 身份，无额外鉴权）
- 路由协议（v1 只有一条 /32 路由）

理由：MTU 计算、TUN API 平台差异、路由下发这些坑都只在真机上能暴露；v1 范围小，出问题时改的是几十行，而不是为一整套 mesh 簿记逻辑返工。

---

## 传输层：为什么必须用 datagram 而不是 stream

TUN 承载的是内层 IP 包。内层可能是 TCP（自带重传）或 UDP（本来不保证可靠）。
如果套进 QUIC **stream**（可靠、有序），会在 QUIC 层重复保证可靠，且产生**队头阻塞**：
一个内层 TCP 包丢失 → stream 重传 → 后面所有包的流都被卡住。这对"整机流量"是灾难性的。

用 **datagram**（QUIC 不可靠扩展，iroh 已支持：`send_datagram`/`read_datagram`）：
- 不重传、不保序、不保队头 → 可靠性完全交给内层协议自己。
- 代价：丢包 = 内层协议自己恢复（TCP 重传 / UDP 应用处理），与"走物理网卡"的语义一致。
- 需要在连接建立后检查 `max_datagram_size()`；datagram 是连接级协商的，对端不支持则 TUN 模式无法工作（报错而非静默降级）。

## 数据流（点对点，无解复用）

```
A 应用进程 → 内核 → tun0 → link-p2p tun (A)
    read IP packet → conn.send_datagram(packet)          # 全部发往唯一对端，无需解析内层 IP
B: conn.read_datagram() → 写入 tun0 → 内核 → B 应用进程
```

反向同理。因为只有一个对端，**发送侧不需要解析内层目的 IP**——这是点对点简化带来的直接好处（mesh 才需要内层 IP → 对端映射）。

## 权限与路由

- 创建 TUN 设备 + 配置地址/路由需要 `CAP_NET_ADMIN`（`ip tuntap add`/`ip addr add`/`ip route add`）。
- 这直接与 README "不需要 root" 的卖点冲突——文档必须明确：**TUN 模式是特权模式**，stream 模式保持无特权。
- 实现方式：v1 直接调用 `ip` 命令（最易测试、出错信息明确）；后续可换 `rtnetlink` crate（无外部依赖）。`setcap cap_net_admin+ep` 作为"免 root"部署选项写进文档。
- TUN 设备用 `tun` crate（Linux: /dev/net/tun + TUNSETIFF，异步 `tun::AsyncDevice`）。

## 平台范围

**Linux only（v1）**。macOS/Windows 的 TUN API 和路由差异大，v1 不承诺；文档明确 Linux-first。

## 真机验证清单（v1 验收标准）

1. 两台机器（或本机 + 一台真机）跑 `tun serve`/`tun connect`，`ping <对端虚拟IP>` 通。
2. `ping` 的 RTT 与直接 ICMP 对比，确认 MTU 没有引发外层分片（`tcpdump` 外层 UDP 包大小 ≤ 路径 MTU）。
3. 大包测试：`ping -s 1200 <对端vip>`（内层 1228 字节）应无分片；`-s 1500`（内层 1528）应被 TUN MTU 截断为 1280 分片——验证 MTU 生效。
4. 经隧道跑一次 `iperf3`（对照 README 基准表的 stream 模式数字）。
5. 同时跑 Tailscale 的机器上验证虚拟 IP 无冲突（决策 1 的运行时检查生效）。
6. `--tun-ip` 覆盖路径 + 冲突报错路径。

## 下一步（不在本文件范围）

- mesh：地址簿 + 多对端连接池 + 内层 IP 解复用
- datagram 在 relay 路径上的吞吐/丢包实测（本沙箱无法测真机网络）
- 自动发现 / ACL / systemd 单元
