# MSSQL TDS PRELOGIN 探针（47 字节，struct 构造 + assert）—— 长度写错会被误判为"伪造开放"

- **code**: mssql-tds-prelogin-probe-47
- **kind**: script
- **category**: info-leak
- **component**: Microsoft SQL Server (TDS)
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 203.0.113.122:1433 实测：47 字节包 → 直连与经 VPS 转发均收到 43 字节响应 `04 01 00 2b 00 00 01 00 | 00 00 1a 00 06 01 00 20 ... 0a 32 06 40 00 00 00 00 00 00`，版本字段 10.50.1600 与 nmap ms-sql-info 完全一致；而此前用 38/40 字节的包全部 0 字节响应，导致错误结论。
- **path**: pocs/mssql-tds-prelogin-probe-47/poc.py
- **tags**: mssql,tds,prelogin,探针,踩坑,长度校验
- **created_at**: 2026-09-28T07:10:21.651Z
- **found_by**: exploit

## 描述

合法的 47 字节 TDS PRELOGIN 探针（struct 保证长度自洽 + assert 校验）。手写 hex 长度写错会让 SQL Server 直接断连，极易被误判为"云防火墙伪造开放/应用层零交互"。

## 用法

```
替换 TARGET 后运行；收到 43 字节 `04 01 ...` 即证明 TDS 服务真实存在并可交互。再用 impacket MSSQL(host,1433).connect()+login(db,user,pwd) 判断认证阶段是否可达。
```

## 正文

```
# coding: utf-8
"""合法构造的 TDS PRELOGIN 探针 —— 长度必须严格 = 8(头) + 39(体) = 47

坑点（我为此误判了整整一轮"该主机是云防火墙伪造开放、应用层零交互"）：
  手写 hex 时把 payload 拼成 38 或 40 字节，而 header 里的 length 字段写 0x2f(47)，
  SQL Server 收到长度不符的包会**直接断开连接（recv 返回 0 字节）**，
  看起来就像"端口是假的、应用层无响应"。
  → 凡是"TCP 通但应用层零响应"的 MSSQL，第一件事就是核对 prelogin 包长度。

正确构造（用 struct 保证长度自洽）：
"""
import socket, struct

PAYLOAD = (b"\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01\x03\x00\x22\x00\x04"
           b"\x04\x00\x26\x00\x01\xff\x09" + b"\x00" * 12)      # 39 字节
assert len(PAYLOAD) == 39, len(PAYLOAD)

HEADER = struct.pack(">BBHHBB", 0x12, 0x01, 8 + len(PAYLOAD), 0, 0, 0)   # type=0x12 PRELOGIN
PKT = HEADER + PAYLOAD                                                    # 47 字节

s = socket.create_connection(("TARGET", 1433), 10)
s.settimeout(12)
s.sendall(PKT)
d = s.recv(1024)
if d:
    t, st, ln = d[0], d[1], struct.unpack(">H", d[2:4])[0]
    print("TDS response: type=0x%02x status=0x%02x len=%d" % (t, st, ln))   # 期望 type=0x04 (TABULAR_RESULT)
    ver = d[8 + 6:8 + 12].hex() if len(d) >= 20 else "?"
    print("payload head: %s" % d[8:8 + 20].hex())
else:
    print("recv 0 bytes —— 包长度或协议被拒/被前置信设备丢弃")

# 版本字段解出示例（实测 203.0.113.122）：
#   payload = 00001a00060100200001020021000103002200000400220001ff0a3206400000000000
#   其中 0a 32 06 40 = major 10 / minor 50 / build 1600 → SQL Server 2008 R2 RTM 10.50.1600
#
# 重要区分（避免把"认证被拦"误判成"服务不存在"）：
#   · 口令错误 → SQL Server 会返回 Error 18456（有明确报错）
#   · 收不到 LOGIN7 的任何响应（timeout）→ 认证包被前置代理/IPS 丢弃，或服务端只放行特定来源
#   实测 203.0.113.122 属后者：prelogin 有 43 字节真实响应，但 impacket login 10 组全部 timeout。

```
