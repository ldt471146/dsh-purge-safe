# Shopify 店面购物车读路径忽略 cart 的 ?key 访问分量——仅凭 25 位 handle 跨会话读他人车

- **code**: shopify-店面购物车读路径忽略-cart-的-key-访问分量-仅凭-25-位-handle-跨会话读他人车
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront (cart.js / /api/graphql)
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 www.thegamecollection.net 实测：造车后全新无 Cookie 会话仅凭 handle 读 /cart.js 得 item_count=2 total_price=2590；换任意错 key 仍命中同一车；随机 handle 回落空车；Storefront cart(id:)/node(id:) 同样忽略 key；写路径 cartLinesAdd 与结算页 /cart/c/<handle> 严格校验 key。已在 collect.thegamecollection.net 同型复现（finding#87）。
- **tags**: shopify,cart,idor,broken-access-control,unauthorized-read,storefront-api
- **created_at**: 2026-11-11T16:00:30.559Z
- **engine**: https://www.thegamecollection.net

## 描述

Shopify 店面的购物车读路径（Ajax /cart.js 与 Storefront API cart(id:)/node(id:)）不校验购物车 token 里的 ?key 秘密分量：只要知道 25 位 handle，任意匿名全新会话即可读到该车结构（行项目/SKU/数量/金额/币种/国别/createdAt）。写路径（cartLinesAdd、cartBuyerIdentityUpdate）与结算 HTML 页 (/cart/c/<handle>) 严格校验 key；buyerIdentity.email 被 key 门禁（无/错 key 返回 null）。属读/写访问控制不一致。影响受限于需先获得随机 handle。含可直接运行的 bash PoC（--demo 全自动造车+跨会话读）。

## 用法

```
handle 形如 25 位 base62（例 hWNJ1rLmO7dBnGzcvU38KG9Q），来自 cart cookie 的 <handle>?key=<32hex> 前半段。读：curl -s https://<shop>/cart.js -H "Cookie: cart=<handle>"（无 key）；或 POST /api/graphql {"query":"{ cart(id:\"gid://shopify/Cart/<handle>\"){ id totalQuantity lines(first:10){nodes{quantity merchandise{... on ProductVariant{sku title}}}} } }"}。判据：带 handle 返回该车内容、错 key 亦然、随机 handle 返回空车/ null 即为命中。handle 不可枚举（前缀定长但后 19 位随机），须先经分享车/结算链接、Referer、日志、analytics 获取。
```
