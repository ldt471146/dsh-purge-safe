# Shopify Storefront cart(id)/node(id) 忽略 ?key 未认证读——升级天花板（负面情报：无法升级为写/PII）

- **code**: shopify-storefront-cart-id-node-id-忽略-key-未认证读-升级天花板-负面情
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront API（/api/graphql，Cart 对象）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 goffsgames.co.uk /api/graphql 匿名实测：复现 cart(id:)/node(id:) 忽略 ?key（带 ?key=wrongkey 仍 200 命中同一 cart，随机 handle→cart:null）。升级逐条封死：①匿名读返回的 checkoutUrl 被服务端剥掉 ?key=；②用正确 key 写入 buyerIdentity.email 后匿名读仍 email:null，customer 字段 ACCESS_DENIED；③QueryRoot 无 checkout 字段；④可读字段仅 id/checkoutUrl(去key)/createdAt/totalQuantity/cost/lines/buyerIdentity.countryCode。handle 25 位 base62 不可枚举，无 in-scope 通道取得他人 handle。
- **path**: pocs/shopify-storefront-cart-id-node-id-忽略-key-未认证读-升级天花板-负面情/poc.txt
- **tags**: shopify,storefront-api,graphql,unauthorized,idor,cart,key,negative,not-exploitable
- **created_at**: 2026-11-11T15:13:55.225Z
- **engine**: goffsgames.co.uk

## 描述

承接 KB#524：cart(id) 忽略 ?key 的读路径访问控制不一致，实测其【升级天花板】——不能通过 handle→读→取写 key、不泄露 buyer email、不能读 Checkout/Order，且 handle 不可枚举。作为"可利用入口/取数据"不成立，仅低危 AC 不一致。避免后续 worker 重复尝试升级。

## 正文

```
# Shopify Storefront API cart(id) 忽略 ?key —— 升级天花板（负面情报）

## 结论
KB#524 描述的「cart(id:) / node(id:) 忽略 ?key 未认证读购物车」真实可复现，但**无法升级**为写权限、PII 泄露或订单/结账读取；且缺少取得他人 handle 的通道。定级 low，作为可利用入口不成立。

## 复现（无 Cookie / 无 Storefront token，POST https://<shop>/api/graphql）
```
基线 cartCreate → id=gid://shopify/Cart/<HANDLE>?key=<KEY>，checkoutUrl 含长 key
① 无 key 读  cart(id:"gid://shopify/Cart/<HANDLE>")               → 200 返回 cart
② 错 key 读  cart(id:"gid://shopify/Cart/<HANDLE>?key=wrongkey")  → 200 仍命中同一 cart（决定性）
③ node(id:"gid://shopify/Cart/<HANDLE>")                          → 200 同 cart（第二条读路径）
④ 随机 handle cart(id:"gid://shopify/Cart/ZZZ...")                → {"data":{"cart":null}}
```

## 升级面逐条封死（全部实测）
| 方向 | 结果 |
|---|---|
| handle→读→取写权限 key | 匿名读返回的 `checkoutUrl` 被服务端**剥掉 ?key=**（变成 `.../cart/c/<HANDLE>`）→ 拿不到写令牌 |
| 泄露 buyer 邮箱 | 用正确 key `cartBuyerIdentityUpdate` 写入 email 后再匿名读 → `buyerIdentity.email:null`（服务端脱敏） |
| `buyerIdentity.customer` | `ACCESS_DENIED`，需 `unauthenticated_read_customers` 作用域 |
| Checkout 对象 | QueryRoot **无 `checkout` 字段**（undefinedField） |
| Order | 需访问作用域 |
| 枚举 handle | 25 位 base62 随机串，随机 handle→cart:null，无接口吐出他人 handle |
| 门店前端取 handle | 仅 Shopify 自有 Monorail / web-pixels 外发，handle 只进 Shopify 内部遥测 |

## 可读字段（唯一实际到手）
`id`(handle)、`checkoutUrl`(去 key)、`createdAt`、`totalQuantity`、`cost{totalAmount,subtotalAmount}`、`lines{商品标题/数量}`、`buyerIdentity.countryCode`、`note`、`discountCodes`。无 email、无写 key、无订单/结账信息。

## 给后续 worker
遇到本类 finding：复现一次即止，不要再尝试「handle→key→写」「取 buyer email」「读 checkout/order」——本条已实测封死。若确有他人 handle 泄漏源（共享纯 handle 链接 / 可观测的第三方 pixel 外发）才值得回头。

```
