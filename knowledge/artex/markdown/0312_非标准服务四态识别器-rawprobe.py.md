# 非标准服务四态识别器 rawprobe.py

- **code**: 非标准服务四态识别器-rawprobe.py
- **kind**: poc
- **category**: recon
- **component**: 红队侦察基础设施
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 靶标上实测：① 判定 `203.0.113.9` 的 443/8443/8888 与 `.234:8080`、`.30:8080` 为**应用层黑洞**（四态全零响应，TLS 报 SSLEOFError）—— 据此在资产备注里写明"不要因为 6 个端口全开就当高价值目标"。② 正确识别出 `203.0.113.7:80` = Microsoft-HTTPAPI/2.0（HTTP.sys，合法 HTTP→404、乱包→400）与 `.181:80` = IIS 6.0 + ASP.NET（GB2312，401，乱包→400 `<h1>Bad Request (Invalid Verb)</h1>`），二者技术栈与靶标的 nginx+Tomcat/Spring Boot 不符，据此判非靶标。
- **path**: pocs/非标准服务四态识别器-rawprobe.py/rawprobe.py
- **tags**: 服务识别,黑洞端口,协议判定,recon
- **created_at**: 2026-10-11T09:41:10.729Z
- **found_by**: recon

## 描述

对可疑端口做**四种形态对照探测**：① 空读（服务端先发协议：SSH/MySQL/SMTP/Redis 会主动吐 banner）② 标准 HTTP 请求 ③ TLS 握手（并提 DER 域名）④ 发乱包（看是否回显错误）。用来判定"TCP 通但不知道是什么"的端口：真服务会在某一态响应，**四态全零响应 = 应用层黑洞**（过滤设备/空绑定端口），这类端口不要当高价值目标。

## 用法

```
python rawprobe.py "ip:port,ip:port,..."
例：python rawprobe.py "203.0.113.9:8888,203.0.113.10:8080"
```

## 正文

```
# -*- coding: utf-8 -*-
"""非标准服务识别：空读 → HTTP → TLS → 乱包，四态对照（原生 socket，不走代理）。"""
import socket, ssl, os, sys, re
for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

def rd(s, n=400, t=4.0):
    s.settimeout(t)
    try:
        return s.recv(n)
    except Exception:
        return b""

def show(ip, port):
    print("\n########## %s:%d ##########" % (ip, port))
    # 1) 空读（服务端先发协议：SSH/MySQL/SMTP/Redis...）
    try:
        s = socket.create_connection((ip, port), timeout=6)
        b = rd(s, 400, 4.0)
        print("  [空读] %r" % (b[:200],))
        s.close()
    except Exception as e:
        print("  [空读] 连接失败 %s: %s" % (type(e).__name__, e))
    # 2) HTTP
    try:
        s = socket.create_connection((ip, port), timeout=6)
        s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n" % ip).encode())
        b = rd(s, 1200, 6.0)
        print("  [HTTP] %r" % (b[:400],))
        s.close()
    except Exception as e:
        print("  [HTTP] %s: %s" % (type(e).__name__, e))
    # 3) TLS
    try:
        s = socket.create_connection((ip, port), timeout=6)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        try: ctx.set_ciphers("DEFAULT@SECLEVEL=1")
        except Exception: pass
        ss = ctx.wrap_socket(s, server_hostname=ip)
        der = ss.getpeercert(binary_form=True)
        names = re.findall(rb"[!-~]{5,80}", der or b"")
        cand = [n.decode("latin-1") for n in names if b"." in n and b" " not in n and not n.startswith(b"http")]
        print("  [TLS ] OK version=%s der=%dB names=%s" % (ss.version(), len(der or b""), cand[:12]))
        ss.close()
    except Exception as e:
        print("  [TLS ] %s: %s" % (type(e).__name__, e))
    # 4) 乱包（看是否回显错误）
    try:
        s = socket.create_connection((ip, port), timeout=6)
        s.sendall(b"\x00\x00\x00\x00\xff\xff\xff\xffGET / HTTP/1.0\r\n\r\n")
        b = rd(s, 500, 5.0)
        print("  [乱包] %r" % (b[:300],))
        s.close()
    except Exception as e:
        print("  [乱包] %s: %s" % (type(e).__name__, e))

TARGETS = [(t.split(":")[0], int(t.split(":")[1])) for t in sys.argv[1].split(",") if t.strip()]
for ip, port in TARGETS:
    show(ip, port)

```
