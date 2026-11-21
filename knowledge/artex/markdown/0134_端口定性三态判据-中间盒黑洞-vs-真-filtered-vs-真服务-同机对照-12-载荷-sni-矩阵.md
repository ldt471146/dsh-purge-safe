# 端口定性三态判据：中间盒黑洞 vs 真 filtered vs 真服务（同机对照 + 12 载荷 + SNI 矩阵）

- **code**: 端口定性三态判据-中间盒黑洞-vs-真-filtered-vs-真服务-同机对照-12-载荷-sni-矩阵
- **kind**: script
- **category**: info-leak
- **component**: 端口定性
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 codex-miaomiaocode-com 靶标的 203.0.113.51 / 203.0.113.110 / 203.0.113.20 三台一致复现：8443 空闲连接可维持 5s+、发任意字节即被关闭且 0 字节响应、TLS ClientHello（5 种 SNI）一律 ECONNRESET、12 种协议载荷全无 banner；同机 443 返回真实 400/OpenResty、4321 返回真实 200 OK、8444/18443/9999/20000 全部 SYN 超时；FOFA 对两台主机的 8443 均无资产（同 IP 的 80/443 有）。据此判 8443 为中间盒黑洞、7070 为 filtered 且无 banner，均为无 Nday 可查的死面。
- **path**: pocs/端口定性三态判据-中间盒黑洞-vs-真-filtered-vs-真服务-同机对照-12-载荷-sni-矩阵/port_triage_blackhole_vs_filtered.md
- **tags**: 端口定性,黑洞,filtered,对照实验,ECONNRESET,TLS,SNI,nmap,FOFA,8443
- **created_at**: 2026-09-30T01:54:34.370Z
- **found_by**: exploit

## 描述

端口定性方法论：把"中间盒黑洞 / 真 filtered / 真服务"三态区分开（空闲连接行为 + 发数据后的响应/ECONNRESET/SYN 超时 + 同机对照端口基线 + 第三方测绘旁证），附 12 载荷清单与 SNI 矩阵，以及 Squid 类代理不放行非 80/443 的注意事项。

## 用法

```
1) 先 `nmap -sT -Pn -sV --version-all -p <port>`（只能给出 `xxx?` 猜测的端口要继续人工判）；2) 裸 socket：先测"空闲连接能维持多久"，再逐个发 12 种首包，逐条记录【响应字节数 / 超时 / ECONNRESET】；3) 同机取 4 个对照端口：一个已知真服务（443/80）、一个已知 filtered（随便一个高位关端口）；若目标端口行为与真服务不同、又与 filtered（SYN 超时）不同 ⇒ 中间盒黑洞；4) TLS 侧用 SNI 矩阵（空 + 所有已知 vhost）各握手一次；5) 用 FOFA/Shodan 查该 IP:端口有没有资产做旁证；6) 判死就别再投时间。
```

## 正文

```
## 问题
一个端口"TCP 能连但没 banner、TLS 握手被 reset"，是**真服务**、**被防火墙 filtered**、还是**中间盒黑洞**？三者处置完全不同：只有"真服务"才值得查版本/Nday。

## 判据（三态区分，必须做同机对照）
| 现象 | 空闲连接 | 发任意数据 | 结论 |
| --- | --- | --- | --- |
| 真服务 | 保持（或服务端先发 banner） | **有响应**（banner / HTTP 状态行 / TLS ServerHello 或 alert） | 可指纹，查 Nday |
| **真 filtered** | —— | **SYN 就超时**（连接建不起来） | 无攻击面，跳过 |
| **中间盒黑洞** | **能建成且能维持秒级** | **任何字节都被立即关闭、0 字节响应**；TLS ClientHello 直接 ECONNRESET | 无 banner/版本/协议，**查不了 Nday** |

**关键：必须用同机对照端口做基线**，否则会把"黑洞"误判成"filtered"或"服务不响应"。

## 载荷清单（一次性打完，别一条条试）
裸 socket 发以下首包，记录响应字节数与错误类型（ECONNRESET 要单独记，它≠超时≠FIN）：
`HTTP/1.0`、`HTTP/1.1+Host`、`GET /version HTTP/1.1`、`HEAD/OPTIONS/POST`、`CONNECT host:port`、
`\x05\x01\x00`(SOCKS5)、`\x04\x01\x00\x50...`(SOCKS4)、`SSH-2.0-...`、`\xffSMB`、`OPTIONS rtsp://...`、
`*1\r\n$4\r\nPING\r\n`(RESP)、`JRMI\x00\x02\x4b`、`stats\r\n`(memcached)、`PING\r\n`(redis)、
`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`+SETTINGS(h2c)、裸 TLS ClientHello（**并用 SNI 矩阵**：空 + 每个已知 vhost）、`\x00`*16、单字节。

## 案例（实测，2026-09-30 codex-miaomiaocode-com）
`nmap -sT -Pn -sV --version-all`：8443 判 open 但只猜得出 `https-alt?`（无版本）；7070 全 filtered。
- 8443：TCP 可连、**空闲连接维持 5285ms+**；`GET / HTTP/1.0` → 约 500ms 后被关闭、**0 字节**；`HTTP/1.1+Host+UA` → **ECONNRESET**；**裸 TLS ClientHello（5 种 SNI 全试）→ ECONNRESET**；12 种协议载荷**全部 0 字节 banner**。
- 同机对照：443 → 497ms 返回真实 `HTTP/1.1 400 Bad Request / Server: openresty`；4321 → 真实 `200 OK`；**8444/18443/9999/20000 → 每种载荷都 SYN 超时（那才是真 filtered）**。
- **独立旁证**：FOFA 对 203.0.113.51 与 203.0.113.110 的 8443 **无任何资产**（同 IP 的 80/443 有）⇒ 第三方爬虫同样取不到 banner。
⇒ 结论：8443 = **中间盒/防护型黑洞**，无协议无版本，**不建议再投**。7070 = 可连但任何载荷都不回一个字节（连 TLS alert 都没有）⇒ 到不了 TLS 层，同样判死。

## 附：不要指望用代理绕
若怀疑是本机出口被针对性处理，想借开放代理从别的路径复核：Squid 类代理通常只放行 80/443 —— 实测 `CONNECT 203.0.113.51:8443` → `403 ERR_ACCESS_DENIED`（`X-Squid-Error: ERR_ACCESS_DENIED`）。**要复核就得用别的出口（另一条链路/另一台机器），别把时间花在代理上。**

## 脚本
裸 socket 多载荷探针 + SNI 矩阵：`raw_proto_probe.py` / `port8443_probe.py` / `_ctrl8443.py`（同机对照）
```
