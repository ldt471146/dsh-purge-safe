# Fanatical apiprelive/apitesting 店面用户自更新写面 adminRoles 注入证否（写生产 users 库）+ prelive 单活会话轮换

- **code**: fanatical-apiprelive-apitesting-店面用户自更新写面-adminroles-注入证否-写生
- **kind**: poc
- **category**: privesc
- **component**: Fanatical storefront API (Heroku fan-api-prelive/testing, Express+MongoDB)
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 02:00-02:15 CST，apiprelive/apitesting 源站直连 + 生产 www 经 CF，用 finding#3557 同一 prelive 会话（_id=6af51c16b72996b8b5a09097）对 #3239 的 10 条真实用户写路由各发 1 次 mega 体（adminRoles/adminRole/role/roles/permissions/$set 等 18 个候选字段 + 各路由合法字段）：apiprelive 10/10 200（save-dob 790B dob 落库、save-billing 848B 仅 address1/address2/postalCode 落库）、apitesting 10/10 200、生产 www 9/10 200（save-billing 需 locality/administrativeArea/countryCode 后 200/918B）；所有响应投影 role 恒 customer、无 adminRoles；每阶段写完用同一 token 打生产 admin 四条 RBAC（user:view / misc:rbac-audit / product:preview / misc:queues）全部 403，无一次 200。
- **tags**: fanatical,apiprelive,apitesting,mass-assignment,adminRoles,whitelist,negative,prelive,session-rotation
- **created_at**: 2026-11-12T02:18:26.974Z
- **engine**: apiprelive.fanatical.com / apitesting.fanatical.com

## 描述

目标②写侧路径的负面情报：prelive/testing 的 /api/user/* 自更新写面直写生产 users 集合（fact#3490），但对权限字段是严格白名单，无法注入 adminRoles 打开生产 admin RBAC。

## 用法

```
1) 取会话：GET https://apiprelive.fanatical.com/api/auth/fandom/?redirectUrl=%2Fen%2Faccount%2Flogin&lang=en（--noproxy '*' --resolve apiprelive.fanatical.com:443:3.33.161.45 -H 'Host: apiprelive.fanatical.com' -H 'X-Forwarded-Host: attacker.com' -H 'anonid: <uuid>'），浏览器走 Fandom OAuth 截 code（返回 URL 已改为 prelive.fanatical.com/en/fandom-auth-return），≤2s 内同 anonid POST /api/auth/fandom/ {code,state,snowplowId:'',snowplowSessionId:'',language:'en'}。2) 写面测试：POST /api/user/{save-site-preference|set-language|preference-rokt-ads|confirm|updatewishlistnotifications|updatecartnotifications|updatereviewreminders|updatekeyrevealreminders|save-dob|save-billing}，body=合法字段+mega 权限字段。3) 判据：响应投影 role 恒 customer（apiprelive/testing 917B/27 键；生产 www 918B），四条生产 admin RBAC（admin.fanatical.com@3.33.161.45 Host 直连）恒 403。4) 注意：①生产 www 的 /api/user/* 只能经 CF https://www.fanatical.com 访问，源站 Host: www.fanatical.com 只返 SPA；②save-billing 构建有差异：apiprelive 收 address1/address2/postalCode，生产 www 与 staging2 要求 address1/locality/administrativeArea/postalCode/countryCode；③同一 Fandom 账号单活会话：每次交换都会吊销该用户此前所有 token（多 worker 共用同账号会互相顶掉，'Invalid authorization header' 401/28B 不是封禁），要连续测试就在同一脚本内完成取码→交换→全部探测。
```
