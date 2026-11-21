# DNS 解析 + 指定 SNI/Host 的 HTTPS 定向探测 sni72.py

- **code**: dns-解析-指定-sni-host-的-https-定向探测-sni72.py
- **kind**: poc
- **category**: recon
- **component**: TLS / vhost 路由
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 靶标上实测出两条对后续利用很关键的结论：① **SNI 坑** —— `203.0.113.12:443` 用 `SNI=example.com / example.com / example.com / example.com / www.example.com` **全部 TLS SSLEOFError**（nginx 无对应 server block），**只有 `SNI=IP 字面量` 可用**（此时 `/LHService/` 200、`/PayBmob/` 200、`routing/health` 403 REQUEST_REJECTED）；不写清这点，后来者用域名去打 443 会一律"连不上"而误判该入口不可用。② **DNS 对照** —— `example.com` 与 `example.com` 当前 A 记录**都指向 203.0.113.55**（不是 .72），而 .72 的证书却是为 example.com 签发的 ⇒ 判定 .72 是 example.com 的**历史/备用部署节点**。同时确认 `api3.example.com` DNS 无解析（死链）。
- **path**: pocs/dns-解析-指定-sni-host-的-https-定向探测-sni72.py/sni72.py
- **tags**: SNI,DNS,归属判定,vhost,历史节点
- **created_at**: 2026-10-11T09:41:35.465Z
- **found_by**: recon

## 描述

两件事：① 批量 DNS 解析一组域名（原生 `socket.getaddrinfo`，**不经 DNS-over-HTTPS 也不受代理影响**），用来核实"某域名当前到底指向哪个 IP"；② 对指定 IP:443 用**不同 SNI**（`ssl.wrap_socket(server_hostname=...)`）+ 对应 Host 头逐条探测，看该站认不认某个域名。用于把"证书里写着某域名"与"该域名当前 DNS 指向哪里"对照，从而判断某台机是该域名的**当前节点还是历史/备用节点**。

## 用法

```
python sni72.py   # 脚本内改 DOMAINS 与 SNI/PATHS 列表；模式可照抄到任意目标
```

## 正文

```
# -*- coding: utf-8 -*-
"""DNS 解析 + 指定 SNI/Host 的 HTTPS 探测（原生 socket，不走代理）。"""
import socket, ssl, os, sys, re, json

for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

DOMAINS = ["example.com","example.com","example.com","api3.example.com",
           "example.com","www.example.com","example.com","www.example.com","6hmb.com",
           "api4.xeffss.cn","xeffss.cn","pay.qingfu.tech","ourhost.com"]

print("===== DNS 解析 =====")
res = {}
for d in DOMAINS:
    try:
        infos = socket.getaddrinfo(d, None, socket.AF_INET)
        ips = sorted({i[4][0] for i in infos})
        res[d] = ips
        print("%-22s -> %s" % (d, ", ".join(ips)))
    except Exception as e:
        res[d] = None
        print("%-22s -> DNS FAIL (%s)" % (d, type(e).__name__))

def probe(ip, port, host, sni, path, timeout=8.0):
    req = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0 (Linux; Android 12; lz2025)\r\n"
           "Accept: */*\r\nX-Security-Version: 2\r\nConnection: close\r\n\r\n" % (path, host))
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except Exception: pass
        s = ctx.wrap_socket(s, server_hostname=sni)
        s.sendall(req.encode())
        buf = b""
        while len(buf) < 5000:
            try: c = s.recv(4096)
            except socket.timeout: break
            if not c: break
            buf += c
        head, _, body = buf.partition(b"\r\n\r\n")
        ht = head.decode("utf-8","replace")
        st = 0
        m = re.match(r"HTTP/\d\.\d (\d+)", ht)
        if m: st = int(m.group(1))
        return st, body.decode("utf-8","replace")[:300].replace("\n"," ")
    except Exception as e:
        return None, "%s: %s" % (type(e).__name__, e)
    finally:
        try: s.close()
        except Exception: pass

print("\n===== 203.0.113.12:443 定向 SNI/Host 探测 =====")
SNIS = ["example.com","example.com","example.com","example.com","www.example.com","203.0.113.12"]
PATHS = ["/", "/LHService/", "/PayBmob/", "/IMService/admin/", "/LHService/v27/routing/health"]
for sni in SNIS:
    for p in PATHS:
        st, body = probe("203.0.113.12", 443, sni, sni, p)
        print("  SNI/Host=%-20s %-34s st=%-5s %s" % (sni, p, st, body), flush=True)

```
