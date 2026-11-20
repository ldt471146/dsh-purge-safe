# Shopify 托管店+Cloudflare 边缘缓存投毒/缓存欺骗面判据（实测阴性收口：动态一律 DYNAMIC+private，unkeyed 头零反射，Host 伪 403）

- **code**: shopify-托管店-cloudflare-边缘缓存投毒-缓存欺骗面判据-实测阴性收口-动态一律-dynamic-pr
- **kind**: poc
- **category**: methodology
- **component**: Shopify Storefront + Cloudflare 边缘
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 UTC 本机 curl 8.5.0（走平台记录代理，UA=$ARTEX_UA，单线程间隔≥2.5s）对 retro-refresh.com 实测：① 动态/个性化路径 /、/collections/all、/search?q=ipod、/cart.js、/account、/sitemap.xml 响应头恒为 cf-cache-status: DYNAMIC + cache-control: private, max-age=0, must-revalidate（/account 与 404 为 private,no-store），同 URL 二次请求无 MISS→HIT 转变；② 17 个 unkeyed 头（X-Forwarded-Host/X-Host/X-Forwarded-Scheme/X-Original-URL/X-HTTP-Method-Override 等）注入 / 后响应体恒 390464B、canary 零反射、canonical 恒 https://retro-refresh.com/；Host 伪造为 canary/localhost 一律 HTTP/2 403；③ 缓存欺骗后缀/路径混淆（/cart.js.css、/collections/all;.css、%00/%20/%2f、..;/、/cdn/ 前缀穿越）全部落 404/302 且 DYNAMIC；④ 唯一被 CF 缓存的是 Shopify CDN 静态资源 /cdn/shop/...（cache-control: public, max-age=31557600，cf-cache-status: HIT，age≈23.6 天），其内容不随任何 unkeyed 头/query 变化（缓存键丢弃未知 query 值、参数名大小写归一化）。原始输出落盘 /opt/artex/data/tasks/9/i1272/probe{1..6}.out。
- **tags**: cache-poisoning,web-cache-deception,shopify,cloudflare,negative,cf-cache-status,host-header
- **created_at**: 2026-11-11T16:17:14.318Z
- **engine**: https://retro-refresh.com
- **found_by**: vuln-scan

## 描述

给「Shopify SaaS 托管店 + Cloudflare 前置」的目标做缓存投毒/缓存欺骗面测绘时直接套用，避免重复投入。三步判据：① curl -sD- 看 cf-cache-status 与 cache-control——凡 DYNAMIC + private/no-store 即源站明示不缓存，投毒面不存在；② 注入 17 个 unkeyed 头（重点 X-Forwarded-Host/X-Original-URL/X-HTTP-Method-Override）+ canary，比对响应体长度与 canary 反射，Shopify 会剥离这些头；③ 追加静态后缀/路径混淆测缓存欺骗，动态路径返回 404/302 DYNAMIC 即封闭。注意 Shopify 自有 CDN 路径 /cdn/shop/ 是被 CF 缓存的（public max-age=1y, HIT），但其内容为固定静态文件、不反射任何输入，不构成投毒面。同型另一店 www.retro32.com 的 login_with_shop 端点亦实测 no-store+DYNAMIC（负面情报 code=shopify-login_with_shop-open-redirect-no-cache-poisoning），结论一致。
