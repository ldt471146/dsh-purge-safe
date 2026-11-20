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