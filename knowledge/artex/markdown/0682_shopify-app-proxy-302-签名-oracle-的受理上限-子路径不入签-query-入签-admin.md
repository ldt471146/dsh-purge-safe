# Shopify app proxy 302 签名 oracle 的受理上限：子路径不入签/query 入签，admin proxy 落点被 staff 门禁遮蔽（revize/download-pdf 两店实测阴性）

- **code**: shopify-app-proxy-302-签名-oracle-的受理上限-子路径不入签-query-入签-admin
- **kind**: methodology
- **category**: recon
- **component**: Shopify App Proxy (revize / Order Printer Pro download-pdf)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 在 thegamecollection.net 两店（www asset#815 / collect asset#3925）实测：GET /apps/revize 及 18 条子路径全 302 到 https://<shop>.myshopify.com/admin/apps/36895f0e7a8b165121bc0d677d0d9a5c/proxy<sub>?path_prefix=%2Fapps%2Frevize&signature=..&timestamp=..，跟随落点一律 302 /admin/auth/login；有效/全0/跨店/篡改extra/回拨3600s 五种签名响应完全相同（验签前 staff 门禁）；同秒对照 3/3 证明子路径不入签、query(extra) 入签；/apps/download-pdf 仅 /<template_guid>/orders|draft_orders/<id> 命中 OPP Rails 上游（404 852B ORDER NOT FOUND），随机 guid 为 Shopify 0B 404，order_id/security/sign/token/template_id/shop/POST 全组合无差异、无订单数据回显。证据落盘 /opt/artex/data/tasks/7/i2758/（enum1_w_revize.log、sig_probe2.log、sig_accept.log、enum4.log、opp_sec.log、cust_state.json、sso_probe.json）。
- **path**: pocs/shopify-app-proxy-302-签名-oracle-的受理上限-子路径不入签-query-入签-admin/poc.txt
- **tags**: shopify,app-proxy,appproxy,hmac,signature,admin-proxy,order-printer-pro,revize,negative,methodology
- **created_at**: 2026-11-11T20:55:11.911Z
- **engine**: https://www.thegamecollection.net

## 描述

用于判定 Shopify app proxy 302 暴露的 HMAC 签名是否可被匿名者用于读取数据面。结论：在 revize 这类「proxy 落点为 myshopify admin proxy」的 app 上，签名 oracle 无接收面——admin proxy 在验签之前先要求 staff 会话，所有签名状态响应一致；子路径不入签（同 timestamp/同 query 下不同子路径 signature 相同）、query(extra) 入签（同子路径改 query signature 变化）。download-pdf 这类直连上游的 app 则按模板 guid 路由，订单不存在/无权限统一 404 ORDER NOT FOUND，不构成存在性 oracle。

## 用法

```
复用时先跑三步：①GET 目标 /apps/<handle> 判 302/上游 404/未注册；②若是 302→myshopify admin proxy，直接判定该 app 数据面对匿名不可达（勿再花预算枚举子路径/重放签名）；③若是直连上游，按上游框架指纹找路由（如 OPP 为 /<template_guid>/orders/<id>），用不存在 order_id + 参数矩阵判存在性 oracle；没有自建订单时只能记 inferred 阴性，不要枚举真实订单号。
```

## 正文

```
## 判据（可复现）
1. GET https://<shop>/apps/<handle> 与 /apps/<handle>/api，看三类指纹：
   - 404 len=0 → 未注册；
   - 302 → Location=https://<shop>.myshopify.com/admin/apps/<api_key>/proxy<sub>?logged_in_customer_id=&path_prefix=%2Fapps%2F<handle>&signature=<64hex>&timestamp=<unix> → 已注册，落点为 admin proxy；
   - 404 有非主题长度/上游头（x-runtime、vary: Accept,X-Requested-With,Origin、link 指向 app 域名）→ 已注册且代理直连上游。
2. 签名语义拆变量（需同秒并发 2 条，仅此实验允许打破 3s 间隔）：
   - 同 timestamp、同 query、不同子路径 → signature 相同 ⇒ 子路径不入签；
   - 同 timestamp、同子路径、不同 query → signature 不同 ⇒ extra(query) 入签。
3. 受理面测试：把 302 Location 投回（有效 / signature 全0 / 跨店 / 篡改 extra / timestamp 回拨），比较响应。全部同一 302 /admin/auth/login ⇒ 该端点验签前先做 staff 门禁，签名 oracle 无可用接收面。

## 实测结果（thegamecollection.net 两店）
- revize：www/collect 全部子路径（含 /api/v1/orders、/returns、/portal、/rma、/graphql 等）均 302 admin proxy；POST 子路径为 404 Rails 默认页 1722B；无任何 200/JSON。
- download-pdf（Order Printer Pro）：仅 /<template_guid>/orders/<order_id> 与 /<template_guid>/draft_orders/<id> 命中上游（404 852B、title=Documents、正文 ORDER NOT FOUND、link 指向 orderprinterpro.com/assets）；随机/全零 guid → Shopify 0B 404；order_id=1/0/-1/abc/999999999/9999999999999、?security=/?security_token=/?token=/?s=/?template_id=/?shop=、POST、跨店 guid 全部 852B 同型，无错误差异。
- 客户态：已登录客户 cookie → revize 302 admin proxy 且 logged_in_customer_id=<customer_id>（客户身份入签）；持未登录会话 cookie → 302 /customer_authentication/sso_redirect?return_to=<同源>；完全无 Cookie → 直达上游/302 admin proxy（不触发 SSO）。sso_redirect 对外部/协议相对 return_to 一律退 account 首页或 OAuth，同源才直跳。
- 跨店：www 的 template guid 在 collect 店同样命中上游（模板 guid 全局），但订单数据仍 ORDER NOT FOUND。

## 证伪条件（出现任一条即结论需重开）
- admin proxy 端点对无效签名返回 403/400（而非统一 302 login）⇒ 验签可观测；
- 同 timestamp 同 query 不同子路径 signature 不同 ⇒ 子路径入签；
- 拿到任一自建订单号后匿名 GET 返回 200 PDF/HTML 含订单字段 ⇒ download-pdf 面成立；
- 取得 admin/staff 会话后 admin proxy 转发到 app 后端 ⇒ revize 面重开。

## 线索
app proxy customer-authentication 分支差异（无 cookie 直达上游 vs 持未登录 cookie 被 sso_redirect 拦）可外推到其它已注册 app proxy（如 /apps/secomapp_freegifts_get_order 匿名读车）复测。
```
