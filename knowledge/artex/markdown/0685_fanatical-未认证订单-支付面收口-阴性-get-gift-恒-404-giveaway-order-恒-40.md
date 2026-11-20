# Fanatical 未认证订单/支付面收口（阴性）：get-gift 恒 404、giveaway-order 恒 401、stripe webhook 强制签名

- **code**: fanatical-未认证订单-支付面收口-阴性-get-gift-恒-404-giveaway-order-恒-40
- **kind**: poc
- **category**: unauthorized
- **component**: Fanatical Express/Heroku API
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 fanatical.com：www 边缘 + ws15 直连（--noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 + Host: ws15 + 任意 X-Forwarded-Host + 唯一伪造 XFF + 合法 anonid）各 50 例 get-gift（8 个 Wayback 真 orderId、3 个 product ObjectId、随机/全零/短串 × en/UUID/同值/空/换位/查询参）全部 HTTP 404 len=27 {"message":"Order Expired"} 且 etag 全等 W/"1b-0j0p1I7JQvmcmqaPiCqcCCDIME0"；POST /api/user/payment/giveaway-order（无 Authorization / 伪造 Bearer / 空体 / 数组 / GET）恒 401 len=28 Missing|Invalid authorization header；POST /api/stripe/webhook 空体/合法 JSON 事件无签名恒 400 "No stripe-signature header value was provided."，伪造 Stripe-Signature 恒 400/448 "No signatures found matching the expected signature for payload"；apistaging/apiprelive 直连交叉一致；9 个 webhook 备选路径全 404。
- **tags**: fanatical,order,gift,webhook,stripe,negative
- **created_at**: 2026-11-11T21:00:54.713Z
- **engine**: https://www.fanatical.com

## 描述

三条未认证订单/支付能力令牌与事件面的证否结论，避免后续 worker 重复：① GET /api/orders/get-gift/{code}/{lang} 对任何 orderId/token 形态恒 404，与随机 id 同构，无 oracle、无穿越（%2e%2e%2f 被当 code 段）、POST 404；真实 gift code 只能靠已付费会话 convert-to-gift 获取（atok 面已封死），Wayback 当前 Temporarily Offline。② POST /api/user/payment/giveaway-order 鉴权中间件先于 body 解析，恒 401。③ POST /api/stripe/webhook 未认证可达但 Stripe SDK HMAC 校验真实生效（错误串即证据），唯有 webhook secret 泄露才可伪造事件。

## 用法

```
复测最小命令（两通道各一例）：
curl -s -A "$ARTEX_UA" -H "anonid: <UUIDv4>" -H "X-Forwarded-For: 198.51.100.9" -w ' [%{http_code}]\n' https://www.fanatical.com/api/orders/get-gift/5bfdb77ccf1bb3009af23d73/en
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' -H 'X-Forwarded-For: 198.51.100.9' -H "anonid: <UUIDv4>" -A "$ARTEX_UA" -w ' [%{http_code}]\n' https://ws15.fanatical.com/api/orders/get-gift/5bfdb77ccf1bb3009af23d73/en
两者均应 404 len=27 Order Expired；若出现 200 + products/recipientHasRedeemed → 结论反转，立即追批量读。
```
