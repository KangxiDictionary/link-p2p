# TUN 模式设计（v1：点对点）

范围：一台机器一个 TUN 接口，与另一台机器建立一条隧道，让**整台机器**能通过虚拟 IP 访问对端。
与现有 `serve`/`connect`（stream 转发）**并存**，互不取代。**不做 mesh**（多对点/白名单/自动发现列为下一步）。

本文件只做裁决，不罗列选项。每条给出明确选择和理由。

---

## 决策 1：地址分配 —— 默认从 EndpointId 确定性派生，实际地址握手时交换，无协调服务器

**选择**：默认虚拟 IP = `f(EndpointId)`（确定性、双方各自可算）；但**实际绑定到 TUN 的地址在握手时通过一条一次性 bidi stream 交换**，路由装到对端真实地址。

```
vip(ep) = 172.24.0.0/16 段内，取 BLAKE3(EndpointId) 的低 16 bit 作为主机位
        = 0xAC18_0000 | (blake3(ep) 低 2 字节)
```

- 16 bit 主机位 → 64K 地址空间；点对点两节点碰撞概率 ~1/64K，可忽略。
- **确定性是关键（默认值）**：没有 `--tun-ip` 时，A、B 各自能算出自己的默认地址，无需协调服务器；这决定了复杂度基线：**TUN v1 无任何服务端组件**。
- **为什么不用 100.64.0.0/10（RFC 6598）**：真机实测（2026-08）发现 Tailscale 的 netfilter 规则会**直接 DROP** 源地址落在 100.64/10、但并非从 tailscale0 进入的包（`-A ts-input -s 100.64.0.0/10 ! -i tailscale0 -j DROP`）。隧道内层包从 link-p2p0/1 进 INPUT 时源地址恰为对端 VIP（100.64/10），命中该规则 → 双向 100% 丢包。172.24.0.0/16 取自 RFC 1918 的 172.16/12，避开 Docker 默认桥（172.17/16）与常见家用路由器网段。
- **网段选择只是绕开已知冲突，不是通用解**：任何私有段都可能被某个第三方工具针对性过滤。**启动碰撞检查（`ensure_vip_free`）是唯一通用兜底**——但它只覆盖"地址已被本地接口占用"这一类冲突；"地址落在被过滤网段"这类冲突仍须逐个排查（换段、或关掉对方过滤规则）。
- **路由不再本地推导**：早期实现里 A 用 `derive_vip(B)` 硬算对端路由，一旦任一侧用 `--tun-ip` 覆盖本端地址，对端路由就指向错误地址，逃生门形同虚设。现在握手后双方交换**实际绑定**的 VIP（派生默认值或 `--tun-ip` 覆盖值），路由天然一致；交换超时（10s）按会话错误处理。协议变了，ALPN 升到 `link-p2p/tun/1`。
- `--tun-ip <addr>` 显式指定本端地址，作为逃生门（现在真正可用）。

路由推论：A 只需一条路由 `ip route add <对端实际 VIP>/32 dev tun0`（来自握手交换，不再本地推导）。点对点不需要路由表/地址簿。**会话结束（对端退出/错误/Ctrl+C）时 serve 会 `ip route del` 删除该路由**，避免重连的新对端（VIP 不同）残留旧路由；两侧退出路径都会先 `endpoint.close()` 发 QUIC 关闭帧，让对端立即感知会话结束，而不是等 idle 超时（实测约 40s）。对端猝死（崩溃/断网）时清理延迟仍受 idle 超时限制，这是 QUIC 的固有特性，无法完全消除。

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
- **已知限制：`max_datagram_size()` 是本端值，不是双向对称的**。noq 的 `max_size()` = `min(本端 current_mtu() 预算, 对端公告的 max_datagram_frame_size)`，前者由本端自己发 PMTUD 探测、受本端出网接口 MTU 约束（PPPoE/VPN/Tailscale exit node 等都会让两端不一致），后者默认 65535 档、对称。
- **判读校准（重要）：两端数字不相等本身无害**。每端 tun MTU = `min(1280, 自己的 max_datagram_size)`，只要两边都 ≥ 1280，最终都会被同一个 1280 封顶，差值被抹平。**真正的危险信号是任一端 < 1280**：该端的 tun MTU 被迫小于对端，对端仍按 1280 发包，超出部分在该端 tun 写入时被内核静默丢弃（该端自己的发送没问题，被自己的较小上限钳制）。真机判据：看两台机器 `RUST_LOG=link_p2p=info` 里 `TUN datagram negotiation` 行的 `max_datagram_size` 相对 1280 的位置，而非两数是否相等；`ping -s 1200/1500` 只作交叉确认。若任一端 < 1280 且大包丢包，再补 mini handshake（各开一条 uni stream 交换 MTU，取 min）。注意：该值在会话期间可能随路径 MTU 变化漂移——`run_datagram_loop` 每 2s 重查 `max_datagram_size()`，PMTUD 收敛后接口 MTU 会向上调（日志：`TUN interface MTU raised {0} → {1}`），`TUN datagram negotiation` 那一行只反映建连时刻。
- **升/降不对称 + 滞回**：升 MTU 由 2s 定时器驱动（`refresh_tun_mtu`）；降 MTU 只在发送路径撞到超限包时事件驱动（`shrink_tun_mtu`）。缩 MTU 后 **15s 内禁止再升**（`MTU_RAISE_HOLDOFF`），避免 Tailscale 直连 ↔ relay 等路径抖动时出现 raise→丢包→shrink 振荡。运维止血仍可用 `--mtu` 钉在抖动下限（如 1162）。
- **ICMP PMTUD 反馈（根治“卡一下”）**：超限丢包时不只内部计数，还会向 TUN **反向注入** ICMP Type 3 Code 4（Fragmentation Needed，Next-Hop MTU = 当前 ceiling），源地址为本端 VIP。本机 TCP 立刻收到下一跳 MTU 变小的信号并降 MSS，不必等黑洞探测的重传超时。对 ICMP 自身 / 组播广播源地址不回复；注入限速 20/s。IPv6 Packet Too Big 留给日后（v1 VIP 仅 IPv4）。
- 内层超过 *接口* MTU 的包由内核在 TUN 接口做标准 IP 分片；超过 *路径 datagram ceiling* 但接口尚未跟上的包由本层丢弃并走上面的 ICMP 路径。

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
5. 同时跑 Tailscale 的机器上验证虚拟 IP 无冲突（决策 1 的运行时检查生效）。实测教训（2026-08）：Tailscale 的 netfilter 会 DROP 100.64/10 非 tailscale0 入站包，网段已因此改为 172.24/16——换段只是绕开已知冲突，碰撞检查才是通用兜底。
6. `--tun-ip` 覆盖路径 + 冲突报错路径（对端路由来自握手交换，`--tun-ip` 现在真正可用）。
7. 对端退出后 serve 侧路由被清理，换身份重连无僵尸路由（`scripts/tun-loopback-test.sh` 第 7.5 节已覆盖此回归）。

> 注：`tun serve` 与 `tun connect` 必须用同一 ALPN 版本（当前 `link-p2p/tun/1`）；混用新旧二进制会在握手期直接失败，属预期行为。

## 下一步（不在本文件范围）

- mesh：地址簿 + 多对端连接池 + 内层 IP 解复用
- datagram 在 relay 路径上的吞吐/丢包实测（本沙箱无法测真机网络）
- 自动发现 / ACL / systemd 单元
