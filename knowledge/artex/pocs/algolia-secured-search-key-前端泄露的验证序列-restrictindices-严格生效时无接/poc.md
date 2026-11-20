# 前端泄露 Algolia secured search API key（受限只读，仅公开商品目录）

## 一、漏洞概述
目标网页前端把 Algolia 搜索服务的 **secured API key** 硬编码在浏览器可见位置：
- 前端 JS 变量 `window.searchKey`；
- 以及一个**非预期**即可读取的接口 `GET https://www.<target>/api/algolia/key`（返回该 key）。

该 key 属 Algolia（搜索 SaaS）客户端凭据：
- Algolia Application ID：`W2M9492DDV`（DSN：`W2M9492DDV-dsn.algolia.net`）
- 密钥本体为 base64，解码后内嵌限制参数：
  ```
  filters=disabled = 0 AND available_valid_from <= <ts>
          AND (available_valid_until = 0 OR available_valid_until > <ts>)
  &facetFilters=["included_regions:US"]
  &restrictIndices=fan,fan_alt_rank,fan_name,fan_latest_deals,...(共 21 个 fan* 索引)
  &validUntil=<短时窗时间戳>
  ```
- `validUntil` 为短时窗（样本约 10 分钟内有效）。

**结论：** 该 key 有效，但被 `restrictIndices` + `filters` + `validUntil` 严格限制，只能**只读搜索 fan* 索引中的公开商品目录**；无法读取其它索引（含用户索引）、无法列出索引、无法读写索引设置。属客户端公开凭据的过度暴露 / 硬编码密钥，不构成对 Algolia 账户或被保护数据的接管。

## 二、影响与危害
- **可用性**：任意第三方无需凭据即可复现对公开商品索引的搜索（数据与官网商品页同源，本身公开）。
- **影响面**：`fan` 索引 `nbHits=16603`（公开商品），facets = drm/type/genres/themes/features/languages/categories/developers。**未**触达用户、订单、礼品卡、支付或后台数据。
- **风险定级**：low（信息泄露 / 客户端密钥硬编码）。真实危害来自密钥管理不规范本身——若同一构建流程换成管理级/更宽 scope 的 key 即会造成实质泄露。
- **未取得**：非公开索引读取、写入、列索引、getSettings、任何用户/交易数据（均 403）。

## 三、复现步骤
前置条件：
1. Algolia Application ID（样本为 `W2M9492DDV`）；
2. secured search key（base64 字符串）——来自前端 `window.searchKey`，或未授权读 `GET /api/algolia/key`；
3. 注意 `validUntil` 时间窗（过期则 key 失效）。

```
# 步骤1：对受限索引做只读 search —— 证明 key 有效、可读公开商品目录
curl -s -X POST "https://<APPID>-dsn.algolia.net/1/indexes/fan/query" \
  -H "X-Algolia-Application-Id: <APPID>" \
  -H "X-Algolia-API-Key: <base64 secured key>" \
  -H "Content-Type: application/json" \
  --data '{"query":"","hitsPerPage":1}'
# 期望：HTTP 200，返回商品记录，如 name="Football Manager 27"、sku、price{GBP,EUR,USD}
# 规模：--data '{"query":"","hitsPerPage":0,"facets":["*"]}' → nbHits=16603

# 步骤2：打非受限索引（含用户索引）—— 证明 restrictIndices 生效
curl -s -X POST "https://<APPID>-dsn.algolia.net/1/indexes/_users/query" \
  -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <base64 secured key>" \
  -H "Content-Type: application/json" --data '{"query":"","hitsPerPage":0}'
# 期望：HTTP 403 {"message":"Index not allowed with this API key","status":403}

# 步骤3：列全部索引 —— 证明无 listIndices 权限
curl -s "https://<APPID>-dsn.algolia.net/1/indexes" \
  -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <base64 secured key>"
# 期望：HTTP 403 {"message":"Method not allowed with this API key","status":403}

# 步骤4：读索引设置 —— 证明无 settings 读/写权限（纯只读搜索态）
curl -s "https://<APPID>-dsn.algolia.net/1/indexes/fan/settings" \
  -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <base64 secured key>"
# 期望：HTTP 403 {"message":"Method not allowed with this API key","status":403}
```

## 四、证据 / PoC（2026-11-11 14:52 UTC，本机 curl 直连 dsn.algolia.net）
- 步骤1：`POST /1/indexes/fan/query` → **HTTP 200**，body 含 `"name":"Football Manager 27"` 等商品；`fan` 索引 `hitsPerPage=0` → `nbHits=16603`。
- 步骤2：`POST /1/indexes/_users/query` 与 `POST /1/indexes/products/query` → **HTTP 403** `Index not allowed with this API key`。
- 步骤3：`GET /1/indexes` → **HTTP 403** `Method not allowed with this API key`。
- 步骤4：`GET /1/indexes/fan/settings` → **HTTP 403** `Method not allowed with this API key`。
- 正例：`POST /1/indexes/fan_latest_deals/query` → **HTTP 200**（restrictIndices 白名单内）。

> 说明：以上请求经本机 curl 直连 dsn.algolia.net，未走平台记录代理，故无流量快照；证据以命令与响应回显为准。密钥原文由平台凭据库托管，此处不落地明文。

## 五、修复建议
1. **去掉未授权 key 分发接口**：`GET /api/algolia/key` 不应无鉴权返回搜索 key；如必须给前端，走服务端签名/短时效下发并绑定 Origin。
2. **密钥最小化**：前端只用 Algolia 的 search-only key，且严格 `restrictIndices` 到公开索引；切勿把具备 `listIndexes`/`addObject`/`settings` 权限的 key 下发到前端。
3. **收窄时间窗与配额**：`validUntil` 短窗 + Referer/Origin 限制 + 每 key 速率配额，降低被批量抓取商品数据的价值。
4. **构建期扫描**：CI 增加 secret scanning（trufflehog/gitleaks 等），阻止 `window.searchKey`、`/api/algolia/key` 之类客户端密钥进入生产构建。
5. **轮换**：把当前这对 App ID+secured key 视为已泄露，评估后轮换。
