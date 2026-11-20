# Algolia secured search key 前端泄露的验证序列（restrictIndices 严格生效时无接管价值）

- **code**: algolia-secured-search-key-前端泄露的验证序列-restrictindices-严格生效时无接
- **kind**: poc
- **category**: info-leak
- **component**: Algolia（搜索 SaaS，客户端 secured API key）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 14:52 UTC 本机 curl 直连 https://W2M9492DDV-dsn.algolia.net：POST /1/indexes/fan/query → HTTP 200 返回商品（Football Manager 27）；POST /1/indexes/_users/query 与 /1/indexes/products/query → HTTP 403 {"message":"Index not allowed with this API key"}；GET /1/indexes 与 /1/indexes/fan/settings → HTTP 403 {"message":"Method not allowed with this API key"}；POST /1/indexes/fan_latest_deals/query → HTTP 200。结论：key 有效但 restrictIndices 严格锁死为 fan* 只读搜索，无接管价值。
- **path**: pocs/algolia-secured-search-key-前端泄露的验证序列-restrictindices-严格生效时无接/poc.md
- **tags**: algolia,api-key,frontend-leak,info-leak,client-credential,saas,restrictIndices,read-only
- **created_at**: 2026-11-11T14:54:04.281Z
- **engine**: www.fanatical.com / W2M9492DDV-dsn.algolia.net
- **found_by**: internal

## 描述

目标前端 JS（window.searchKey）与未授权接口 GET /api/algolia/key 泄露 Algolia secured search API key（App ID W2M9492DDV）。key 为 base64，内嵌 restrictIndices=fan,...（21 个 fan* 索引）+ facetFilters + validUntil 短时窗。实测有效但严格受限：仅可只读搜索 fan* 公开商品索引，越界索引/列索引/getSettings/写 一律 403。判定为客户端公开凭据的过度暴露（密钥硬编码），低危，无接管价值。

## 用法

```
适用：前端 JS / 非预期接口泄露 Algolia App ID + secured search key（密钥为 base64，或直接形如 32位hex+参数拼接）时的只读判据与序列。三步走——①有效性与范围；②越界索引；③方法权限（写/列索引/settings）。

前置：拿到 App ID 与 key。DSN 端点 = https://{APPID}-dsn.algolia.net；请求头 X-Algolia-Application-Id / X-Algolia-API-Key。

# 1) 解 key 看内嵌限制（base64 解码，看 restrictIndices / filters / facetFilters / validUntil）
echo '<base64-key>' | base64 -d; echo

# 2) 只读 search 受限索引（确认 key 有效 + 读到的数据类型）
curl -s -X POST "https://<APPID>-dsn.algolia.net/1/indexes/<index>/query" \
  -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <key>" \
  -H "Content-Type: application/json" --data '{"query":"","hitsPerPage":1}'
# 期望 200 + hits；再看规模：--data '{"query":"","hitsPerPage":0,"facets":["*"]}' → nbHits/facets

# 3) 越界索引（证明 restrictIndices 生效，读不到用户/其它数据）
curl -s -X POST "https://<APPID>-dsn.algolia.net/1/indexes/_users/query" \
  -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <key>" \
  -H "Content-Type: application/json" --data '{"query":"","hitsPerPage":0}'
# 期望 403 {"message":"Index not allowed with this API key"}

# 4) 方法权限（纯只读证明：无 listIndices / getSettings / 写）
curl -s "https://<APPID>-dsn.algolia.net/1/indexes" -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <key>"        # 期望 403 Method not allowed
curl -s "https://<APPID>-dsn.algolia.net/1/indexes/<index>/settings" -H "X-Algolia-Application-Id: <APPID>" -H "X-Algolia-API-Key: <key>"  # 期望 403 Method not allowed

判据：若 2) 返回 200 且 3)/4) 全 403 ⇒ 纯只读受限 key，属低危信息泄露（客户端密钥硬编码），无接管价值；若 3) 返回 200 ⇒ 可跨索引读，立即评估是否含用户/订单/PII；若 4) 的写/settings 返回 200 ⇒ 高价值（可污染索引/改配置）。

坑：
- key 常带 validUntil 短时窗，过期后 2) 会 403/Unauthorized，先解码看时间戳再判定。
- 不要真做写操作（addObject/deleteIndex）验证——用 GET /1/indexes 与 /settings 的 403（Method not allowed）即可等价证明只读态，避免任何变更。
- 目标若经应用层代理（如 /api/algolia/* 转发），该代理本身可能另有注入面（见同 target 的 filters DSL 注入条目）。
```

## 正文

```
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

```
