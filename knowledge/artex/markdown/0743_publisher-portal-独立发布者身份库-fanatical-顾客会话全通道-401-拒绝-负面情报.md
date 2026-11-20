# Publisher Portal 独立发布者身份库：fanatical 顾客会话全通道 401 拒绝（负面情报）

- **code**: publisher-portal-独立发布者身份库-fanatical-顾客会话全通道-401-拒绝-负面情报
- **kind**: poc
- **category**: auth-bypass
- **component**: Publisher Portal (React/Vite + Heroku Express)
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 五通道 x 12 端点实测：有效生产顾客 token（ws15 /api/user/refresh-auth 200）打 /api/publisher-portal/* 全 401/42B Invalid authorization header，零凭据 401/42B Missing；staging token 同；Cookie/查询/头名/路径归一化/登录注入全无效；无 403/200。2026-11-12 02:30-02:45 UTC，curl --noproxy '*' + --resolve 源站实测。
- **path**: pocs/publisher-portal-独立发布者身份库-fanatical-顾客会话全通道-401-拒绝-负面情报/poc.md
- **tags**: fanatical,publisher-portal,negative,customer-session
- **created_at**: 2026-11-12T02:45:44.463Z
- **engine**: https://www.fanatical.com/api/publisher-portal

## 描述

Publisher Portal 与店面顾客认证是两套独立身份/会话体系。有效生产顾客 token 在 /api/user/* 可用，但打 /api/publisher-portal/* 全部 401 Invalid authorization header，说明中间件只查发布者会话库。顾客会话进发布者权限不成立；RBAC/IDOR 必须持有真实发布者 pp_token 才能测。

## 用法

```
不要重复测。取任意生产有效顾客 token，以 Authorization 原值或 Bearer 打 /api/publisher-portal/me：401 Invalid = 独立身份库，关闭该面，转发布者自身邀请/登录/重置链。
```

## 正文

```
端点全集（prod 与 portal-staging bundle 一致，sha256 与 i2037 存档一致）：GET/PATCH /me、POST /me/password、POST /me/active-account、POST /auth/login|logout|forgot-password|reset-password|accept-invite、GET /auth/invite/{token}、GET /account、GET /account/users、POST /account/users/invite、PATCH/DELETE /account/users/{id}、POST /account/users/{id}/resend-invite、GET /reporting/embed-url。不存在 auth/me、user/profile、orders、keys、products、stats、publishers、invites（404）。
已试绕过全失败：Cookie pp_token/token/authorization/atok、查询参数 token、X-Auth-Token 等头名、路径归一化（双斜杠/点段/百分号/尾斜杠/大小写）、登录 NoSQL 与原型污染注入（zod 校验 400 或 401）。
后续测点：拿到真实发布者会话后，按 /me schema 的 permissions/role/account/accounts 打 /account/users 读写与 /me/active-account；/reporting/embed-url 的 Metabase supplierId 越权。
```
