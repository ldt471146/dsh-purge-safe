# TLS 证书 SAN 反查域名 + 同 IP vhost 路由发现（纯 IP 段挖真实域名，避免错过 target）

- **code**: tls-证书-san-反查域名-同-ip-vhost-路由发现-纯-ip-段挖真实域名-避免错过-target
- **kind**: script
- **category**: info-leak
- **component**: TLS 证书 / nginx vhost / 泛域名
- **severity**: low
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.84/24、203.0.113.88/24、203.0.113.38/24、203.0.113.80/24 实战验证（2026-10-15）。核心验证：203.0.113.40:443 按 Host 头路由到三个不同服务 —— 裸 IP 返回 MinIO AccessDenied XML；Host: example.com 返回迷茫网 Vue3 SPA；Host: example.com 返回芋道管理系统 5.7.0（落库 vuln_id=30 critical）；Host: oss.example.com 返回 MinIO S3 API。一次证书采集从 SAN 挖出 20+ 真实域名（example.com / example.com / oss.example.com / hk.092000.xyz / aimanplay.cn / 251w.com / 2vshop.com / 56meme.com / amazoney.com / files.cjngames.cn / 755500.xyz / cha.6-7.cc / wenjie.us / pay.yertw.cn / pay.winxizhifu.top / kk1.xqcc88.top / cc.ygdnvjvjc.top / harness.nanlat.com 等）。同时验证了"页面源码绝对 URL 挖自动生成 vhost"（从 PHPWind 后台页挖出 example.com → 203.0.113.86，148 词字典爆破不可能命中）。
- **path**: pocs/tls-证书-san-反查域名-同-ip-vhost-路由发现-纯-ip-段挖真实域名-避免错过-target/tls_san_vhost_discovery.py
- **tags**: 信息泄露,TLS证书,SAN,vhost发现,域名挖掘,纯IP段,内网服务发现,可复用
- **created_at**: 2026-10-15T20:49:13.884Z
- **found_by**: vuln-scan

## 描述

纯 IP 段挖真实域名：抓 TLS 证书 SAN 累积域名池，再用域名当 Host 反打同 IP，通过响应差异发现隐藏 vhost（管理后台/对象存储/内部 API）。含"页面源码绝对 URL 挖自动生成 vhost"补充手法。

## 用法

```
拿到一个纯 IP 段（无域名线索）时用它挖真实域名与隐藏服务：
1) 对段内每个开放 443 的 IP 抓证书 SAN → 累积域名池（一次采集可能拿到 20+ 域名）
2) 用域名逐个当 Host 反打同 IP，比对响应差异（状态码/字节数偏离基线 = 命中不同服务）
3) 补充：crt.sh 查历史子域；扫已收页面的绝对 URL 找自动生成 vhost

实战价值：本靶标 203.0.113.40 裸 IP 只返回 MinIO 报错，给 Host: example.com 才命中芋道管理后台（critical 暴露）、oss.example.com 才命中 MinIO。同 IP 三服务，不给 Host 全错过。
随后用域名池去试 frps（Fast Reverse Proxy）vhost 入口，命中即可直达内网服务。
```

## 正文

```
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TLS 证书 SAN 反查域名 + 同 IP vhost 路由发现（纯 IP 段挖真实域名）

## 为什么有效（实战验证）

同 IP 多 vhost 场景下，**裸 IP 访问会返回默认 server 块**（通常是无害的 404/403 或某个次要服务的报错 XML）。而**真正的高价值目标（管理后台、对象存储、内部 API）只在正确 Host 头下才暴露**。

实测案例（203.0.113.40:443）：
- 裸 IP → 只返回 MinIO 的 AccessDenied XML
- Host: example.com        → 迷茫网前端（Vue3 SPA）
- Host: example.com  → ★ 芋道管理系统（RuoYi-Vue-Pro 5.7.0）
- Host: oss.example.com    → ★ MinIO S3 API
→ **不给 Host 头会完全错过这两个高价值目标**

## 域名从哪来：TLS 证书 SAN

运维常把同批域名签进**同一张证书**的 SAN 字段（省钱），因此一次证书采集就能拿到整批域名：
```
openssl s_client -connect <IP>:443 -servername <IP> </dev/null 2>/dev/null \
  | openssl x509 -noout -text | grep -A2 "Subject Alternative Name"
```
用 Python ssl 抓 `getpeercert(binary_form=True)` 再用 openssl 解析，可绕开本机证书链校验问题。

## 完整流程（三步）

### 1. 抓 SAN，累积域名池
```python
import socket, ssl, subprocess, tempfile, os, re
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
s = ctx.wrap_socket(socket.create_connection((IP,443),timeout=12), server_hostname=IP)
der = s.getpeercert(binary_form=True)
with tempfile.NamedTemporaryFile(suffix=".der", delete=False) as f: f.write(der); fn=f.name
txt = subprocess.run(["openssl","x509","-inform","DER","-in",fn,"-noout","-text"],
                     capture_output=True,text=True).stdout
os.unlink(fn)
sans = re.findall(r"DNS:([A-Za-z0-9\.\-\*_]+)", txt)   # 含通配 *.example.com
domains = {x.lstrip("*.") for x in sans if not x.startswith("*")}
```

### 2. 用域名逐个当 Host 反打同 IP，比对响应差异
```python
def probe(IP, port, host):
    s = socket.create_connection((IP,port),timeout=12)
    s = ssl_ctx.wrap_socket(s, server_hostname=host)          # ★ SNI 用域名
    s.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % host).encode())
    ...return (status, len(body), title)
base = probe(IP, port, IP)                                     # 裸 IP 基线
for h in domains:
    r = probe(IP, port, h)
    if (r[0], r[1]) != (base[0], base[1]):  print("差异 Host:", h, r)
```
**判据：状态码或字节数偏离基线 = 该 Host 路由到不同服务。**

### 3. 顺带挖：页面源码里的绝对 URL
后台/前端页面常硬编码绝对 URL，可挖出**自动生成的 vhost**（字典爆破不可能命中）：
```html
<img src="http://example.com:1031/...">
```
正则扫已收页面：`https?://([a-z0-9\-\.]+\.(?:com|top|net|cn|xyz|shop|cc|cfd|buzz))`

## 适用与限制
- **必须 HTTPS 开放**；纯 HTTP 无证书则改用 Host 字典爆破 + 响应差异比对
- SAN 里可能是**通配域名**（`*.example.com`）→ 只能给后缀，需配合子域爆破
- 证书可能是**自签/默认证书**（不含业务域名）→ 则本条无效，转用「页面源码绝对 URL」或「被动 DNS / crt.sh」
- **crt.sh 补充**：`https://crt.sh/?q=%25.<domain>&output=json` 可拿到历史所有子域（含已下线）

## 配套铁律
- CONNECT 用 IP、**TLS SNI 用域名**才稳（代理场景）
- 本机 curl 走 schannel 可能因吊销检查失败（`CRYPT_E_REVOCATION_OFFLINE`）→ 用 Python ssl 关 verify

```
