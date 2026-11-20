# Wix 站点匿名公开 app-instance 令牌对 eCommerce/Stores 订单与客户接口无效（已证否）

- **code**: wix-站点匿名公开-app-instance-令牌对-ecommerce-stores-订单与客户接口无效-已证否
- **kind**: poc
- **category**: unauthorized
- **component**: Wix eCommerce / Wix Stores GraphQL
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 kennysbuyselltrade.co.uk：匿名 GET /_api/v1/access-tokens 取得的 wixcode-pub 及标准应用 instance 令牌只把 /_api/ecom/v1/carts/current 从 428 NO_IDENTITY_IN_CONTEXT 提升为 404 OWNED_CART_NOT_FOUND；POST /_api/ecom/v1/orders/query 带/不带令牌一致 403 READ_ORDER_FORBIDDEN；/order(orderId) 由 "identity context is missing" 变 "order not found"（无数据）；orderHistory 仅 isDemo:true 返回每次随机 id 的合成订单；contacts 403、customers/CRM 404、bookings 403。
- **path**: pocs/wix-站点匿名公开-app-instance-令牌对-ecommerce-stores-订单与客户接口无效-已证否/poc.txt
- **tags**: wix,ecommerce,orders,app-instance-token,unauthorized,negative,graphql
- **created_at**: 2026-11-11T15:03:58.166Z
- **engine**: https://www.kennysbuyselltrade.co.uk

## 描述

用于判断「拿到 Wix 站点匿名 app-instance 令牌后能否打 eCom 订单/客户面」：结论是不能，除非取得对具体 Stores 应用签名的合法 instance。

## 用法

```
阴性判据（换站先按此对照）：① GET /_api/ecom/v1/carts/current 带令牌 404 OWNED_CART_NOT_FOUND、无令牌 428 = 令牌仅给匿名身份；② POST /_api/ecom/v1/orders/query 带/不带令牌均 403 READ_ORDER_FORBIDDEN = 订单批量读不可越权；③ POST /_api/wixstores-graphql-server/graphql {order(orderId:"GUID"){id}} 带令牌返回 NOT_FOUND 且 orderHistory(isDemo:false) PERMISSION_DENIED = 单条/真实历史均读不到；④ orderHistory(isDemo:true) 返回的订单 id 每次调用都变 = Wix 合成 demo 数据，不是真实 PII。命门在 Orders 服务的 "read order" 权限，需要为该站 Stores 应用签名的实例，匿名公开令牌不满足。
```

## 正文

```
## 结论
Wix 站点的匿名公开 app-instance 令牌（来自 /_api/v1/access-tokens 的 apps[*].instance，如 wixcode-pub/CloudSiteExtension）在 eCommerce/Stores 面**不构成越权读取订单或客户 PII 的入口**。它只把请求从「无身份/无法提取站点」提升为「站点匿名访客身份」（等价于普通匿名访客）。

## 实测对照（kennysbuyselltrade.co.uk, 2026-11-11）
| 请求 | 无令牌 | 带匿名令牌 | 破坏签名 |
|---|---|---|---|
| GET /_api/ecom/v1/carts/current | 428 NO_IDENTITY_IN_CONTEXT | 404 OWNED_CART_NOT_FOUND | 400 signature digest mismatch |
| POST /_api/ecom/v1/orders/query | 403 READ_ORDER_FORBIDDEN | 403 READ_ORDER_FORBIDDEN | — |
| GET /_api/ecom/v1/orders/{id} | — | 404 ORDER_NOT_FOUND | — |
| GraphQL order(orderId:guid) | FAILED_PRECONDITION identity context is missing | NOT_FOUND order not found | — |
| GraphQL orderHistory(isDemo:false) | PERMISSION_DENIED | PERMISSION_DENIED | — |
| GraphQL orderHistory(isDemo:true,ordersAmbassadorV2:true) | FAILED_PRECONDITION（提取不出站点） | 200，2 条合成 demo 订单（id 每次随机） | — |
| GET /_api/contacts/v4/contacts | 403 | 403 | — |
| GET /_api/bookings/v1/bookings | 401 FAILED_TO_RESOLVE_INSTANCE_ID | 403 Unauthorized Operation | — |

## 可达面（供后续利用）
- POST /_api/wixstores-graphql-server/graphql —— Wix Stores GraphQL，80 个查询字段（order/orders/orders2/orderHistory/shipments/products/storeInfo…），未认证即可内省 schema。订单字段权限门在 Orders 服务（com.wixpress.ecom.ep-orders … getOrder / read order）。
- /_api/wix-ecommerce-storefront-web/api、/_api/wix-ecommerce-graphql-web/api —— storefront 读/写 GraphQL，匿名令牌返回 401 InvalidAuthorizationHeaderException / 400 Invalid signed instance，需对特定应用签名的实例。
- /_api/wix-ecommerce-renderer-web/store-front/cart/{commandName} —— cart 命令路由，命令名未定。

## 命门
Orders 服务的 "read order" 权限要求一个对该站 Stores 应用签名的合法 instance；匿名公开 app-instance 令牌不在授权名单内，故订单/客户面打不开。单条 GetXxx 与 ListXxx 的鉴权不一致（GetMember 曾 200、ListMembers 空）在 Orders 面表现为 identity 门可过但数据面不过。
```
