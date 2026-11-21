# 原生 socket / 手工 TLS 探测骨架（绕本机 HTTP 代理污染 + binary_form 证书取证 + 定制404/Spring404/406 三态判存）

- **code**: 原生-socket-手工-tls-探测骨架-绕本机-http-代理污染-binary_form-证书取证-定制404-spring404-406-三态判存
- **kind**: poc
- **category**: env
- **component**: 自研「Json接口」Spring Boot 框架 / nginx 前置
- **severity**: info
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在本靶标 7 台（203.0.113.96/63/70/101/102/103/104，:443 与 .70:80）上实测生效：由它完成基线（base）、41 种路由形状反推（prefix，由此发现 /service）、7 台差异表（diff，区分出无安全头/带安全头的两个应用版本）、单段路由枚举（enum，>2000 请求）、/service 语义穷尽（svc/deep/keys/hdrtry）、multipart 500（mp）、证书与 whois 归属取证（cert2/whois，定出 O=每日互动股份有限公司 CN=*.getui.com）。未取得任何权限，纯探测骨架。
- **path**: pocs/原生-socket-手工-tls-探测骨架-绕本机-http-代理污染-binary_form-证书取证-定制404-spring404-406-三态判存/poc.py
- **tags**: 原生socket,手写HTTP,绕本机代理,SNI=IP,证书取证,指纹判存,chunked
- **created_at**: 2026-10-11T12:02:26.890Z
- **found_by**: exploit

## 描述

红队通用探测骨架：清代理环境变量 + 原生 socket/手工 TLS 拼包（SNI=IP）+ chunked 解码 + binary_form 证书取证 + APNIC whois。适用于任何「本机代理会污染 Go/curl 结果」的目标环境，以及需要区分"自研框架定制 404 vs Spring 默认 404 vs 后缀协商 406"的应用面判存。

## 用法

```
python probe.py   # 直接 import req(ip,port,path,method,body,hdrs) / cert_org(ip) / whois_apnic(ip)
关键点：
1) 入口先 pop 掉 http_proxy/https_proxy/all_proxy/HTTP_PROXY/HTTPS_PROXY/ALL_PROXY —— 本机这 6 个变量指向 127.0.0.1:17992，不去掉会让 curl 与所有 Go 工具假超时。
2) HTTPS：ssl.SSLContext(PROTOCOL_TLS_CLIENT) + check_hostname=False + verify_mode=CERT_NONE + wrap_socket(server_hostname=IP)。SNI 与 Host 都用 IP 字面量。
3) 不要发 Accept: application/json（produces=text/html 的 dispatcher 会回 406）；用 Accept: */* 或不发 Accept。
4) 判存三态：自研框架定制 404 文案 = 路由未命中；Spring 默认 `{"timestamp","status","error","message","path"}` 404 = 进了 DispatcherServlet 但无 handler；406 = 后缀内容协商冲突（说明该路径被当成带扩展名的请求）。
5) 取证书必须 binary_form=True。
```

## 正文

```
# -*- coding: utf-8 -*-
"""原生 socket + 手工拼 HTTP/HTTPS 报文探测骨架（绕本机代理；SNI=IP；含 chunked 解码）。"""
import socket, ssl, os, sys, re

# ① 必须先清代理：本机 http_proxy/https_proxy/all_proxy/HTTP_PROXY 全指向 127.0.0.1:17992，
#    curl 与所有 Go 工具（nuclei / fscan / gogo / suo5）都会因此产生"超时/不可达"假象。
for k in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
    os.environ.pop(k, None)

UA = ("Mozilla/5.0 (Linux; Android 13; 23013RK75C) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/203.0.113.52 Mobile Safari/537.36")


def dechunk(b):
    res = b""
    while True:
        i = b.find(b"\r\n")
        if i < 0:
            break
        try:
            n = int(b[:i].split(b";")[0], 16)
        except Exception:
            break
        if n == 0:
            break
        res += b[i + 2:i + 2 + n]
        b = b[i + 2 + n + 2:]
    return res


def req(ip, port, path, method="GET", body=None, hdrs=None, timeout=8.0):
    """手工拼 HTTP 报文。HTTPS 用 ssl 手工握手，SNI 与 Host 都用 IP 字面量（用域名可能 SSLEOFError）。
    注意：不要发 Accept: application/json —— 很多自研 dispatcher 的 produces 是 text/html，
    带了会直接 406 Not Acceptable。"""
    h = {"Host": ip, "User-Agent": UA, "Accept": "*/*",
         "Accept-Encoding": "identity", "Connection": "close"}
    if hdrs:
        h.update(hdrs)
    data = body or b""
    if isinstance(data, str):
        data = data.encode("utf-8")
    if method == "POST" and "Content-Length" not in h:
        h["Content-Length"] = str(len(data))
    raw = ("%s: %s".replace(": ", ": ") % ("", "")).encode()  # noop 占位
    raw = ("%s %s HTTP/1.1\r\n" % (method, path)
           + "".join("%s: %s\r\n" % (k, v) for k, v in h.items())
           + "\r\n").encode("latin-1") + data
    out = {"status": None, "headers": "", "body": b"", "err": None}
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if port == 443:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            try:
                ctx.set_ciphers("DEFAULT@SECLEVEL=1")
            except Exception:
                pass
            s = ctx.wrap_socket(s, server_hostname=ip)
        s.settimeout(timeout)
        s.sendall(raw)
        buf = b""
        while True:
            try:
                c = s.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            buf += c
            if len(buf) > 4 * 1024 * 1024:
                break
        s.close()
        out["raw_len"] = len(buf)
        if b"\r\n\r\n" in buf:
            hd, bd = buf.split(b"\r\n\r\n", 1)
            out["headers"] = hd.decode("latin-1", "replace")
            m = re.match(r"HTTP/1\.[01]\s+(\d+)", out["headers"])
            if m:
                out["status"] = int(m.group(1))
            if "transfer-encoding: chunked" in out["headers"].lower():
                bd = dechunk(bd)
            out["body"] = bd
        else:
            out["body"] = buf
    except Exception as e:
        out["err"] = "%s: %s" % (type(e).__name__, e)
    return out


def cert_org(ip, port=443):
    """★ 证书取证：VERIFY_NONE 下 getpeercert() 返回空 dict，
    必须 getpeercert(binary_form=True) 取 DER 再解码，否则会误判成"无证书"。"""
    import tempfile
    s = socket.create_connection((ip, port), timeout=8)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=ip)
    der = ss.getpeercert(binary_form=True)
    ss.close()
    pem = ssl.DER_cert_to_PEM_cert(der)
    fn = os.path.join(tempfile.gettempdir(), "c.pem")
    open(fn, "w").write(pem)
    d = ssl._ssl._test_decode_cert(fn)
    m = dict([kv for t in d.get("subject", ()) for kv in t])
    return m.get("organizationName"), m.get("commonName"), d.get("subjectAltName"), d.get("issuer")


def whois_apnic(ip):
    """归属查询：whois.apnic.net:43 原始 TCP。"""
    s = socket.create_connection(("whois.apnic.net", 43), timeout=15)
    s.sendall(("%s\r\n" % ip).encode())
    buf = b""
    while True:
        c = s.recv(8192)
        if not c:
            break
        buf += c
    s.close()
    return buf.decode("utf-8", "replace")

```
