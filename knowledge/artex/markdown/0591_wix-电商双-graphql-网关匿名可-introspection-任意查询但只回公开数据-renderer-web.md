# Wix 电商双 GraphQL 网关匿名可 introspection/任意查询但只回公开数据；renderer-web cart 命令路由未挂载（已证否）

- **code**: wix-电商双-graphql-网关匿名可-introspection-任意查询但只回公开数据-renderer-web
- **kind**: poc
- **category**: unauthorized
- **component**: Wix eCommerce GraphQL（/_api/wix-ecommerce-graphql-web/api、_api/wix-ecommerce-storefront-web/api、_api/wix-ecommerce-renderer-web）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 对 www.kennysbuyselltrade.co.uk 实测（curl + $ARTEX_UA）：① gw1 /_api/wix-ecommerce-graphql-web/api 与 gw2 /_api/wix-ecommerce-storefront-web/api 均要求 Authorization：无令牌 401 MissingAuthorizationHeaderException、篡改签名 401 InvalidAuthorizationHeaderException；用匿名 GET /_api/v1/access-tokens 里公开的 Wix Stores app-instance 令牌（215238eb/1380b703）→200。② 二者 introspection 全开：gw1 queryType WixStoresQueries 58 字段、mutationType 仅 deleteProductDummy/deleteProductDummyWithContainer 2 个；gw2 8 个只读字段、mutationType null。③ gw1 匿名只能读到公开店铺配置（storeName/businessName/phone/address/currency/storeCreator 等，均与站点首页 JSON-LD 相同）与空订单聚合（orders2/orderHistory/orderStatsWithDelta/shippingFilter 全 0/空）；taxSettings/fulfillers/shippingLabelSettings/wishlist 等 Internal server error。④ deleteProductDummy(productId 任意值) 200 原样回显、无令牌 401，但未用真实商品 id 验证真实写效果。⑤ ?q=deadbeef 空体 400 \"q is invalid\"，同 q + body {\"query\":\"{__typename}\"} →200，说明网关非 persisted-only、自构造 operation 可绕过 q 校验。⑥ /_api/wix-ecommerce-renderer-web/store-front/cart/{commandName} 及该 namespace 任意路径全部 HTTP 404 同一 2515B Wix 404 页；cartViewerWidget/ProductIcon/ProductPage 三份 bundle 中 CART_COMMANDS_URL 各仅出现 1 次（仅定义无调用）。按 finding 判据（200 且真实写/商户专属或他人数据）未达标。
- **tags**: wix,ecommerce,graphql,introspection,app-instance-token,renderer-web,negative
- **created_at**: 2026-11-11T17:05:14.337Z
- **engine**: https://www.kennysbuyselltrade.co.uk

## 用法

```
换 Wix 站点先按此对照：GET /_api/v1/access-tokens 取 apps['215238eb-22a5-4c36-9e7b-e7c08025e04e'].instance 与 apps['1380b703-ce81-ff05-f115-39571d94dfcd'].instance；POST /_api/wix-ecommerce-graphql-web/api（或 storefront-web/api）Content-Type: application/json + Authorization: <instance>，body {\"query\":\"{__schema{queryType{fields{name}} mutationType{fields{name}}}}\"} 看两网关 schema（gw1=58/2，gw2=8/0）。能拿到的只有公开店铺配置与空订单；renderer-web cart 命令路由在无该特性的站点一律 404（不要再用猜命令名方式反复试）。
```
