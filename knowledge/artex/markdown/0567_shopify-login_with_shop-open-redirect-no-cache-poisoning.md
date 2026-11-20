# Shopify Login with Shop 开放重定向的缓存投毒升级路径已封闭（no-store + cf-cache-status DYNAMIC）

- **code**: shopify-login_with_shop-open-redirect-no-cache-poisoning
- **kind**: poc
- **category**: methodology
- **component**: Shopify 商店 (Login with Shop /services/login_with_shop/buyer/*)
- **severity**: info
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:50 UTC 本机 curl 8.5.0 实测 www.retro32.com（task#12）：对 /services/login_with_shop/buyer/complete?return_to=https://evil.example/cachetest 同一 URL 连续请求两次，响应头均为 Cache-Control: no-store 且 Cf-Cache-Status: DYNAMIC（非 HIT），确认 302 不入 CF 缓存，缓存投毒升级（把跳转固化为影响全体访客）不成立。流量快照 1794412255-3379/3378。
- **tags**: open-redirect,shopify,cache-poisoning,negative
- **created_at**: 2026-11-11T15:53:15.834Z
- **engine**: www.retro32.com

## 描述

对 Shopify Login with Shop 开放重定向（return_to 未校验）评估 Web 缓存投毒升级路径的判据：若该 302 响应被前置 CDN 缓存，攻击者可把任意跳转固化为影响全体访客的缓存投毒。实测该端点返回 Cache-Control: no-store 且 Cf-Cache-Status: DYNAMIC，不缓存，故此升级路径封闭。

## 用法

```
评估任意 open-redirect 是否可升级为缓存投毒时，先看响应头：curl -skD- "https://HOST/path?param=https://evil.example/x" | grep -iE "cache-control|cf-cache-status|age|x-cache"；同 URL 连发两次比对 cf-cache-status（HIT=可能可投毒）。若为 no-store / DYNAMIC（Cloudflare）或 no-cache，则缓存投毒不成立，open-redirect 危害上限退回钓鱼/社工。
```
