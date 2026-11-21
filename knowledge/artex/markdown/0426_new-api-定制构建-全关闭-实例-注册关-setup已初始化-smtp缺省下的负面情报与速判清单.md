# New API 定制构建「全关闭」实例：注册关/setup已初始化/SMTP缺省下的负面情报与速判清单

- **code**: new-api-定制构建-全关闭-实例-注册关-setup已初始化-smtp缺省下的负面情报与速判清单
- **kind**: poc
- **category**: info-leak
- **component**: New API (QuantumNous/new-api) v0.12.15-ledger-balance-probe 定制构建
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-18 在 example.com / example.com（同实例 203.0.113.19，New API v0.12.15-ledger-balance-probe）逐项实测：POST /api/setup → "系统已经初始化完成"；POST /api/user/register → "New user registration has been disabled by administrator"（双域名同）；root/admin×6 组全败且 CriticalRateLimit 429 坐实；/api/verification → "invalid SMTP account"；/api/rankings、/api/perf-metrics/* → 404 Invalid URL；/mj/image/1 与 /probe-x/mj/image/1 → 400 midjourney_task_not_found；/api/usage/token、/api/log/token 假 key → 401 Invalid token。拉取 v0.12.15 tag 全量源码逐行对照（controller/setup.go、misc.go、api-router.go、relay-router.go、common/init.go）确认上述判据。
- **path**: pocs/new-api-定制构建-全关闭-实例-注册关-setup已初始化-smtp缺省下的负面情报与速判清单/poc.md
- **tags**: new-api,one-api,信息泄露,负面情报,未授权面,注册关闭,setup假象,限速预算
- **created_at**: 2026-10-17T18:42:47.119Z
- **found_by**: vuln-scan

## 用法

```
对任何 New API/one-api 实例先跑三发判定：GET /api/setup（root_init=false 是假象，POST 一发验证）、POST /api/user/register（报 disabled 即全链断：明文key链/无限额度链全要账号）、GET /api/verification（SMTP 状态）。弱口令预算严格 20/20min（CriticalRateLimit），错误响应无用户枚举 oracle 就停。然后对照 /api/rankings /api/perf-metrics/summary 是否 404（定制构建可能没有）。
```

## 正文

```
# New API 定制构建「全关闭」实例排查清单（2026-10-18 example.com 实测）

## 快速判定流（拿到 version 后 15 分钟内可完成）
1. `GET /api/setup`：`{"status":true,"root_init":false,"database_type":""}` —— root_init 恒 false 是假象（controller/setup.go:31，Setup=true 提前 return）。直接 `POST /api/setup` 一发验证：`{"success":false,"message":"系统已经初始化完成"}` 即关闭，别再投入。
2. `POST /api/user/register` 一发：报 "New user registration has been disabled by administrator" ⇒ RegisterEnabled=false。**同用户名二连注册仍报 disabled 而非"用户名已注册"⇒ 无用户存在性 oracle，且第一条注册也没生效。**
3. 弱口令预算：CriticalRateLimit=20次/20min/IP（common/init.go:122，GlobalAPIRateLimit=180/180s 另算）。只给 root/admin 各 3 组。错误响应统一为 "Username or password is incorrect, or user has been banned"，无 oracle，喷洒无意义。
4. 密码重置：`GET /api/verification` 看 SMTP（本例 "invalid SMTP account"）；`/api/user/reset` 的 token=GenerateVerificationCode(0)=32 字符 UUID（misc.go:312/353），不可爆破；`GET /api/reset_password?email=` 恒 success:true（邮箱存在性被掩码）。
5. 版本面差集：非官方 tag 定制构建可能**没有** KB#7 清单里的 /api/rankings、/api/perf-metrics/*（本例 404 Invalid URL）。用 `curl -w '%{http_code}'` 复核再下结论。
6. /mj/image/:id 与 /<任意段>/mj/image/:id 未认证可达（relay-router.go:204 挂在 TokenAuth 之前）但仅 400 midjourney_task_not_found，无数据价值。
7. 前端 chunk 二次收割（主包+全部异步 chunk grep `/api/` 路径）确认无私有端点、无硬编码 key 后，Web 层即可收口。

## 链路依赖速查（为什么注册一关全链断）
- 明文 sk- key：`POST /api/token/:id/key` 挂 UserAuth（api-router.go:259）⇒ 必须有账号。
- 无限额度：`PUT /api/token/` 同样 UserAuth ⇒ 必须有账号。
- 渠道明文 key：`POST /api/channel/:id/key` 挂 RootAuth+SecureVerificationRequired（api-router.go:218）⇒ 必须 root。
- 管理员 access_token 直登：authHelper 走 Authorization 头（model/user.go:763）+ 头 New-Api-User=用户id ⇒ 只有 token 泄露才有输入。

## 本例最终判定
/info-leak/low 维持：/api/status 泄露 version/server_address/passkey_rp_id/start_time/配额定价/OAuth 开关（选型价值有限——该构建已关注册、关 OAuth、无 rankings 面，公开 N-day 前提全不成立）。DB key 需走服务器层或凭据泄露源，Web 层零路径。
```
