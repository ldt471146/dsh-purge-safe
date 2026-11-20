# Shopify UCP/MCP 能力面收口封条（retro32 实测，可作通用基线）

端点：POST https://<shop>/api/ucp/mcp（后端 {shop}.myshopify.com/api/ucp/mcp）
前置：无需 Cookie/JWT；tools/call 需 arguments.meta.ucp-agent.profile=<店铺自身 /.well-known/ucp>；单线程 ≥3s（约 30 发/2400s 窗口）。

## 工具全集（固定 14，无 nextCursor）
get_checkout create_checkout update_checkout complete_checkout cancel_checkout
get_cart create_cart update_cart cancel_cart
get_order
ask_business search_catalog lookup_catalog get_product

## 逐类封条
| 能力类 | 结论 | 证据 |
|---|---|---|
| customer | 无任何 customer 工具 | tools/list 14 项不含 |
| order 读 | get_order 需 agent Global API JWT | 无 JWT→-32000 AuthenticationRequired；alg=none→AuthenticationFailed |
| discount | 仅 cart/checkout.discounts.codes 子字段 | 无效码→discount_code_invalid（kb#696 已记）；非独立工具 |
| payment | 仅 checkout.payment.instruments 子字段；可写元数据但不可支付 | create_checkout 200 success 回显 id/handler_id/type/billing_address，credential token 值丢弃；complete_checkout 仍 JWT 门禁 |
| shipping | 仅 checkout.fulfillment.destinations 写面 | 属 finding#166 未认证写类 |
| inventory | 无库存数量 | product.variants 仅 availability:true/false；ask_business 明确不提供数量 |
| resources/prompts | 不存在 | 两方法带/不带 profile 均 422 invalid_profile_url |
| 隐藏/草稿商品 | 未发现 | lookup_catalog 跨店 variant/伪造 id 全 not_found；available=false 仅售罄公开商品 |

## 判定要点
- 判工具真实性看 body status:success + 真实 gid://shopify/...；不要只看 HTTP 200（MCP 错误可能 200+error 体）。
- 阴性对照：同一请求去掉 profile 应 422 invalid_profile_url，证明门禁存在。
- 限流：MCP 后端与店面 HTML 限流相互独立——MCP 13 发无 429 时，无 Cookie 的 /products/ 页面 GET 已可能 429。
