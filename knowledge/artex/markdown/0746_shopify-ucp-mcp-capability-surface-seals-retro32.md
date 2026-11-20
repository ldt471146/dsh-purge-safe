# Shopify UCP/MCP 能力面收口（retro32 实测）：14 工具无 customer/discount/payment/shipping/inventory 独立能力；读面仅公开目录+RAG；payment.instruments 属同源未认证写不升危

- **code**: shopify-ucp-mcp-capability-surface-seals-retro32
- **kind**: poc
- **category**: recon
- **component**: Shopify UCP / MCP (JSON-RPC 2.0 /api/ucp/mcp)
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 11:11-11:22 UTC，www.retro32.com（后端 cns21d-0u.myshopify.com）/api/ucp/mcp，本机 curl 单线程≥3s：① tools/list 线上 HTTP 200 / 206439B / 14 工具，与本地 2026-11-11 副本 i2862/tools.resp 逐工具 inputSchema sha256 全同、无 nextCursor；② resources/list、prompts/list 带与不带 params.meta.ucp-agent.profile 均 422 {"code":-32001,data.code:"invalid_profile_url","Missing profile uri"}；③ lookup_catalog 3 真实 Product 解析成功、真实 variant 去重父商品、跨店 variant gid://shopify/ProductVariant/46233783861529 与 3 个伪造 Product id 全 not_found；get_product 伪造 id → product_not_found；④ search_catalog query=amiga available=false 仅返回售罄公开商品（抽查 4 个 handle 在已抓公开 HTML 中出现），商品对象无库存/成本字段；⑤ ask_business 政策正常、系统提示提取被拒、库存数量明确不提供；⑥ create_checkout 携带伪造 payment.instruments（handler_id shopify.card + 任意 billing_address）→ 200 status:success 并原样回显元数据（credential token 值被丢弃），complete_checkout 仍 JWT 门禁；⑦ 13 发 MCP 请求无 429，同期无 Cookie 的 /products/ 页面 GET 即 429（店面独立限流）。原始响应 /opt/artex/data/tasks/12/i3842/
- **path**: pocs/shopify-ucp-mcp-capability-surface-seals-retro32/poc.md
- **created_at**: 2026-11-12T11:16:11.428Z
- **engine**: https://www.retro32.com/api/ucp/mcp

## 用法

```
对任一开放 UCP/MCP 的 Shopify 店做能力面审计时直接复用本封条，跳过以下方向（均已实测阴性）：① 找 customer / discount / payment / shipping / inventory 独立工具——不存在，全 14 工具固定为 get_checkout create_checkout update_checkout complete_checkout cancel_checkout get_cart create_cart update_cart cancel_cart get_order ask_business search_catalog lookup_catalog get_product；② MCP resources/list、prompts/list——恒 422 invalid_profile_url（profile 只对 tools/call 生效）；③ 用 lookup_catalog/get_product 读隐藏/草稿/跨店商品——伪造 id、跨店 variant 均 not_found，available=false 只回售罄公开商品；④ 用 ask_business 拿库存/系统提示/内部配置——RAG 仅覆盖公开店铺信息；⑤ 用 create_checkout 写 payment.instruments 想升级 finding#166——可写入任意 handler_id/type/billing_address 元数据（credential token 值被丢弃），但 complete_checkout 仍 JWT 403 -32000，不构成支付/下单，不升危。若要找新面，优先看 ask_business 的 Cart GID grounding（裸 GID 去 key 是否可读）与 sitemap_agentic_discovery.xml。
```

## 正文

```
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

```
