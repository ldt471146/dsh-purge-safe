# 本机 fake-ip DNS + 规则型本地代理下，用 CONNECT+自定义 SNI 直达 nginx vhost（绕过假性「目标封 IP」）

- **code**: 本机-fake-ip-dns-规则型本地代理下-用-connect-自定义-sni-直达-nginx-vhost-绕过假性-目标封-ip
- **kind**: script
- **category**: tunnel
- **component**: 本地 HTTP 代理（Clash/v2ray 类）+ 目标 nginx vhost
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-12 在 example-com 靶标实测：example.com → 200 len=3920（Pear Admin 登录页）；example.com → 200 len=56032（代理后台）；example.com → 302 /login（GoFly）；example.com/example.com → 200。同一批 URL 用普通 requests/curl（走域名解析）全部 SSLEOFError 失败。前提：需要一条能出境的 HTTP 代理（本例 127.0.0.1:7892，出口 203.0.113.115）。
- **path**: pocs/本机-fake-ip-dns-规则型本地代理下-用-connect-自定义-sni-直达-nginx-vhost-绕过假性-目标封-ip/connect_sni_vhost.py
- **tags**: fake-ip,DNS劫持,SNI,CONNECT,代理,vhost,出口
- **created_at**: 2026-10-12T10:06:11.442Z
- **found_by**: exploit

## 描述

本机 DNS 为 fake-ip 且本地代理按域名规则解析时，用「CONNECT 真实 IP + 自定义 TLS SNI」访问任意 nginx vhost，绕过 client 侧劫持造成的假性「目标封 IP」。

## 用法

```
python3 connect_sni_vhost.py  # 按需替换 connect_ip / proxy / sni_host / host_header
```

## 正文

```
# 场景：本机 DNS 返回 fake-ip（203.0.113.79/15），且本地代理按域名规则做远端解析。
# 结果：某些域名（不在代理规则内）请求必然 TLS 复位；而用「CONNECT 到源站真实 IP + 手工指定 TLS SNI」可完全绕过。
#
# ① 先定位：哪些域名被 fake-ip 劫持
python3 - <<'PY'
import socket
for h in ["example.com","example.com","example.com","example.com","example.com"]:
    try: print(h, socket.gethostbyname(h))
    except Exception as e: print(h, e)
PY
# 若解析到 198.18.x.x / 198.19.x.x（RFC2544 保留段）即为 fake-ip 劫持
#
# ② 核心：底层 socket 自己拼 CONNECT 隧道（Python 版，见 ex_raw.py）
import socket, ssl
def raw_req(sni_host, path, method="GET", body=None, headers=None, connect_ip="203.0.113.95",
            port=443, host_header=None, proxy=("127.0.0.1", 7892), timeout=30):
    h = {"User-Agent": "Mozilla/5.0", "Accept": "*/*", "Connection": "close"}
    h.update(headers or {}); h["Host"] = host_header or sni_host
    if body is not None:
        body = body.encode() if isinstance(body, str) else body
        h["Content-Length"] = str(len(body))
    s = socket.create_connection(proxy, timeout=timeout)
    s.sendall(f"CONNECT {connect_ip}:{port} HTTP/1.1\r\nHost: {connect_ip}:{port}\r\n\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        c = s.recv(4096)
        if not c: break
        head += c
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])
    ss = ctx.wrap_socket(s, server_hostname=sni_host)          # <<< 关键：SNI 用目标域名
    req = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k,v in h.items()) + "\r\n"
    ss.sendall(req.encode() + (body or b""))
    data = b""
    while True:
        try: c = ss.recv(65536)
        except socket.timeout: break
        if not c: break
        data += c
    ss.close(); return data

# ③ 变体：CONNECT 到「能正常解析的兄弟域名」+ Host 改成被劫持的域名（nginx 会按 Host 重选 vhost）
#    raw_req("example.com", "/", connect_ip="example.com", host_header="example.com")
#
# ④ curl 等价（对不被 SNI 劫持的链路）
#    curl -k --resolve example.com:443:203.0.113.95 https://example.com/
```
