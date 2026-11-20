# MSSQL 1433 防火墙握手代理式伪装的判定法与 TDS PRELOGIN 探针

- **code**: mssql-1433-防火墙握手代理式伪装的判定法与-tds-prelogin-探针
- **kind**: script
- **category**: waf
- **component**: MSSQL / SQL Server 1433 可达性判定
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.71:1433 实测：TCP 可握手（经 VPS socks5 0.38s）但 TDS PRELOGIN 15s 无响应；ssh -L 转发同样超时；pymssql DB-Lib error 20003 —— 据此判定该端口为防火墙握手代理式伪装，避免了"看着通就连"的误判。
- **path**: pocs/mssql-1433-防火墙握手代理式伪装的判定法与-tds-prelogin-探针/tds_probe.py
- **tags**: mssql,1433,TDS,可达性判定,防火墙伪装,误判避免
- **created_at**: 2026-09-28T23:36:29.399Z
- **found_by**: exploit

## 描述

MSSQL 1433 可达性判定教训 + TDS PRELOGIN 探针：TCP 可握手 ≠ 服务可达（实测 203.0.113.71:1433 为防火墙握手代理式伪装：socks5 出口三次握手 0.38s 成功但 TDS 包 15s 无响应，ssh -L 转发同样超时，pymssql 报 DB-Lib 20003）。判 MSSQL 可达性绝不能只看 TCP 通不通，必须发 TDS 包验证。

## 用法

```
python tds_probe.py 203.0.113.71 1433
# 走代理：ssh -D 1080 user@vps 后可用 ssh -L 11433:<target>:1433 转发，再对 127.0.0.1:11433 探测
# 返回「真 MSSQL」才值得继续上凭据；返回「握手代理式伪装」就直接换目标，别浪费爆破/登录时间
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tds_probe.py - 判定 MSSQL 1433 是"真服务"还是"防火墙握手代理式伪装"。

背景（实测教训，203.0.113.71:1433）：
  · Test-NetConnection / nc 报 "TCP 通"（socks5 出口 0.38s 完成三次握手）——
    **这不等于 MSSQL 可达**；
  · 真正发一个 TDS PRELOGIN 包后 15s 无任何响应；
  · ssh -L 端口转发（11433->1433）同样超时；pymssql 报 DB-Lib error 20003
    "TDS server connection timed out"。
  ⇒ 典型的防火墙/中间设备"握手代理"：只代答 SYN，不转发应用层流量。
**结论纪律：判断 MSSQL 可达性时，绝不能只看 TCP 通不通，必须做 TDS 层探测。**

用法：
  python tds_probe.py 203.0.113.71 1433
  # 需要走代理时：先用 ssh -D 建 socks5，或 ssh -L 转发后探测 127.0.0.1:<port>
"""
import socket, sys

PRELOGIN = (b'\x12\x01\x00\x2f\x00\x00\x00\x00'
            b'\x00\x00\x1a\x00\x06\x01\x00\x20\x00\x01\x02\x00\x21\x00\x01'
            b'\x03\x00\x22\x00\x04\x04\x00\x26\x00\x01\xff')


def probe(host, port, timeout=15):
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
    except Exception as e:
        return f'TCP 不可达: {type(e).__name__}: {e}'
    s.settimeout(timeout)
    s.sendall(PRELOGIN)
    try:
        d = s.recv(4096)
    except socket.timeout:
        return ('TCP 可握手但 TDS PRELOGIN 无响应 ⇒ **防火墙/中间设备握手代理式伪装，MSSQL 实际不可达**')
    except Exception as e:
        return f'读失败: {type(e).__name__}: {e}'
    finally:
        try:
            s.close()
        except Exception:
            pass
    if d[:1] == b'\x04':
        return f'*** TDS PRELOGIN 响应正常（{len(d)}B）⇒ 真 MSSQL 服务，可继续用凭据登录 ***'
    return f'非 TDS 响应（{len(d)}B）: {d[:40].hex()} ⇒ 可能是别的服务或拦截页'


if __name__ == '__main__':
    h = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    p = sys.argv[2] if len(sys.argv) > 2 else '1433'
    print(f'{h}:{p} -> {probe(h, p)}')

```
