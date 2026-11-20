# staging Algolia secured key：同生产，严格只读受限（已证否，勿重复）

## 结论
staging.fanatical.com 泄露的 Algolia secured search key（App ID **W2M9492DDV**，DSN `https://W2M9492DDV-dsn.algolia.net`）与生产 key 同款受限：
- `restrictIndices` 限定 21 个 `fan_staging*` 索引；
- `filters=disabled = 0 AND available_valid_from <= <now> AND (available_valid_until = 0 OR available_valid_until > <now>)` 服务端强制；
- `facetFilters=["included_regions:US"]`（GB 页签给 GB 变体）；
- `validUntil` 短时窗 ≈ 签发 +600s。

**只能只读搜索 staging 独立商品目录（354 条，生产 `fan` 为 16607 条，不含生产数据）**；无 listIndexes / getSettings / browse / keys / 写权限；记录字段与生产公开索引逐字段对比 staging 独有字段 0（无内部价格/成本字段，无未上架/embargo 记录）。

## 验证要点（可复现）
1) 取新鲜 key：key 为 SSR HTML 内联、10 分钟过期。CF Access 拦截普通 GET（302），但 `OPTIONS + Origin + Access-Control-Request-Method: GET` preflight 放行到 Heroku origin，返回 200/104632 的 `/en/` HTML，内含 `window.searchKey`（base64）。旧 key 全部过期时用此法重取。
2) 解码：`base64 -d | python -c urllib.parse.unquote` → 见 digest、filters、facetFilters、restrictIndices、validUntil。
3) 有效性与规模：`POST /1/indexes/fan_staging/query {"query":"","hitsPerPage":0,"facets":["*"]}` → 200, nbHits=354, 27 个 facet 键；20/21 白名单索引均 200/354，`fan_staging_manual_price_rank` 404（索引不存在，属配置漂移）。
4) 越界/方法权限：`POST /1/indexes/_users/query`（及 fan/products/fan_staging_users/批量 `*/queries`）→ 403 `Index not allowed with this API key`；`GET /1/indexes`、`GET /1/indexes/fan_staging/settings`、`GET /1/indexes/fan_staging/browse` → 403 `Method not allowed with this API key`；`GET /1/keys` → 403。
5) 注意 `GET /1/indexes/fan_staging` 返回 200/354 只是该索引的 search/list 端点（page 翻页取全 354 条），仍受 key filters 约束，**不是** listIndices 提升或 filter 绕过（逐条校验 future_from=0 / expired_until=0 / disabled=0）。

## 判据
与生产 key 完全同构的“公开只读低危”。若未来在 staging 见到 key 的 restrictIndices 出现非 `fan_staging*` 索引、或 `GET /1/indexes` / settings 返回 200，才需重新评估。