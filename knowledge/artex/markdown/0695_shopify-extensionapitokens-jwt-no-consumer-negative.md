# Shopify extensionApiTokens 铸出的 extension Storefront JWT 在 UCP/customer/persisted/Storefront API 四域均无消费方（阴性封堵）

- **code**: shopify-extensionapitokens-jwt-no-consumer-negative
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify Checkout Web GraphQL extensionApiTokens / JWT 凭据混淆
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 21:18–21:26 UTC，本机 /opt/artex/data/tasks/9/i2940（python3+requests，经平台记录代理，54 请求无 429）：4 次零凭据铸造均 200 且 claims 恒为 sub=cid=580111/sid=103967621452/exp-iat=3600（jti/iat 每次不同），同一 token 跨 40+ 请求 4 分钟内无作废；四类 API 全阴性矩阵见 usage/原始 resp_*.json；appId 999999999/3373963/152456331265/1 全 null。结论已由 record_fact #2995 落库。
- **tags**: shopify, extensionApiTokens, jwt, credential-confusion, ucp, mcp, customer-api, checkout-persisted, negative
- **created_at**: 2026-11-11T21:24:11.096Z
- **engine**: https://retro-refresh.com

## 描述

对 /checkouts/unstable/graphql 字段级未鉴权铸出的 extension Storefront JWT（claims iss=shopify, sub=cid=580111, sid=<shopId>, exp=iat+3600）做跨 API 消费面验证：在 UCP/MCP、account 客户 API、checkouts internal persisted、Storefront API 全版本与 /web/api/graphql 上全部不被接受。580111 是 Shopify 平台级 Storefront API client id（结账页 meta serialized-apiClientId=580111、店面 Trekkie apiClientId=580111，跨店恒定），不是本店安装的第三方 app。

## 用法

```
复测口径（单线程≥3s）：① 铸造后取 token；② UCP get_order/complete_checkout（带 profile 自绕）：无 token 403 AuthenticationRequired，Authorization: Bearer <jwt> → 401 "Invalid global access token."，X-Shopify-Access-Token / X-Shopify-Storefront-Access-Token / x-checkout-one-session-token 被忽略→403 同基线；③ account.<shop>/customer/api/{unstable,2024-07}/graphql：Authorization raw/Bearer → 401 "Invalid token, missing prefix shcat_."，shcat_+JWT → 401 "Invalid token. Decode Error."，其余头视为未携带；④ /checkouts/internal/graphql/persisted?operationName=Proposal 与 /checkouts/unstable/graphql {session{__typename}}：任意形态投递该 JWT → 与无 token 基线逐字节相同的 INVALID_SESSION_TOKEN；⑤ /api/graphql 与 2023-01/2024-01/2024-10/2025-04/unstable、?build_id= 变体：Storefront 头/Bearer → 401 UNAUTHORIZED，X-Shopify-Access-Token/x-checkout-one-session-token → 与匿名 200 基线逐字相同（头被忽略）。同时 appId 枚举：580111 返回 token，任意其它 appId（999999999/3373963/152456331265/1）返回 null；因 580111 为平台常量，"已安装第三方 app"oracle 只对第三方 appId 成立。结论：该 JWT 的数据面消费方不在上述端点，别再重复这条矩阵。
```
