# Shopify app proxy 已注册/未注册的响应差异判定法（含 302 暴露 HMAC signature 与上游 404 指纹）

- **code**: shopify-app-proxy-registration-fingerprint-302-signature-vs
- **kind**: methodology
- **category**: recon
- **component**: Shopify App Proxy
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测 thegamecollection.net 两店（www asset#815 / collect asset#3925）：/apps/revize 与 /apps/revize/api 均 302 到 https://<shop>.myshopify.com/admin/apps/36895f0e7a8b165121bc0d677d0d9a5c/proxy?...&path_prefix=%2Fapps%2Frevize&signature=<64hex>&timestamp=<unix>；/apps/download-pdf(+/api) 返回 404 6571B 且响应头含 x-runtime/x-request-id/vary:Origin/x-permitted-cross-domain-policies/x-download-options、缺 powered-by:Shopify（判定为 Order Printer Pro Rails 上游）；/apps/joy-loyalty 返回 404 len=9 'Not Found'（app 后端文本）；未注册 handle（revize-app/order-printer-pro/opp/checkoutblocks/joy-loyalty-avada/mm-google-shopping/随机）一律 404 len=0 Shopify 默认空响应。
- **tags**: shopify,app-proxy,recon,fingerprint,hmac,signature
- **created_at**: 2026-11-11T20:33:01.719Z
- **engine**: https://www.thegamecollection.net

## 描述

无需知道 app 名即可判定某个 /apps/<handle> 是否在目标 Shopify 店注册，并区分“Shopify 默认 404”“app 后端 404”“app 后端 302”。同时说明匿名请求已注册 app proxy 时 Shopify 会在 Location 中返回合法 HMAC-SHA256 signature 与 timestamp（构成对任意匿名者的签名 oracle），可据此评估 app 后端是否信任签名。

## 用法

```
1) 以 ≥3s 间隔单线程 GET https://<shop>/apps/<handle>、/apps/<handle>/api，看三类响应：\n   · 404 且 len=0、content-type text/html; charset=utf-8 —— 未注册（Shopify 默认）；\n   · 404 有自定义长度/文本（如 len=9 'Not Found'、6571B HTML）或响应头含 x-runtime/x-request-id/vary:Origin/x-permitted-cross-domain-policies/x-download-options —— 已注册，404 来自上游 app 后端（第二例是 Rails）；\n   · 302 且 Location 指向 https://<shop>.myshopify.com/admin/apps/<32hex>/proxy?...&signature=<64hex>&timestamp=<unix> —— 已注册，Location 中的 32hex 是 app API key，signature 是 Shopify 用 app shared secret 对 path_prefix/shop/timestamp/logged_in_customer_id/extra 计算的 HMAC-SHA256。\n2) 302 的 signature 每请求变化但绑定 path_prefix（子路径不进待签串），任意匿名者可获得合法签名；若 app 后端仅校验签名而不校验子路径/时效，存在重放面（需在授权边界内验证，未授权第三方后端不投递）。\n3) 枚举候选 handle 时优先用 namespace/品牌名/常见词根（revize、download-pdf、joy-loyalty、secomapp_*），并配一个随机 handle 做阴性对照。
```
