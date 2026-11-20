# light-tech Sparrow 后台管理身份面：Google OAuth-only + JWT 弱密钥/alg=none 全阴性（无本地账号/注册/邀请面）

- **code**: light-tech-sparrow-后台管理身份面-google-oauth-only-jwt-弱密钥-alg-n
- **kind**: poc
- **category**: auth-bypass
- **component**: light-tech Sparrow（Node/Express + MongoDB 邮件管理后台）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 19:39–19:58 UTC，本机 curl -sk 直连 sparrow-captain-sparrow.light-tech.online：① 前端 Vite+React bundle 显示唯一登录为 Google GSI（client_id 504112649413-...），POST /api/auth/google {token:<GSI credential>} 返回 {email,token,name,picture,exp} 并作为 Bearer；② /api/auth/google 对 alg=none 伪 Google ID token（正确 aud/iss、4 个 email 候选、错 aud、过期）、HS256 弱 secret、字段变体、Wix instance/svSession/ctToken/mediaAuthToken/siteOwnerId/siteId 共 36 组全部 401 {"error":"Invalid token"}；③ 阳性门槛端点 GET /api/applications/14206e6f-4e6d-eecd-f424-86531c98386c/emails 在无 auth/Bearer junk/alg none/None/NONE/34 个弱 secret HS256/HS384/Wix 材料/Cookie/query/9 种自定义头共 70+ 组全部 401 {"error":"Unauthorized: token required for reading emails"}；④ POST /api/ab-test/* 伪造 JWT 全部 401 Unauthorized；⑤ 14 条注册/邀请/登录路径全部 404 Cannot POST。未取得管理员会话，emails 读面零权限增益。
- **path**: pocs/light-tech-sparrow-后台管理身份面-google-oauth-only-jwt-弱密钥-alg-n/poc.txt
- **tags**: sparrow,light-tech,google-oauth,jwt,alg-none,weak-secret,auth-bypass,negative-recon
- **created_at**: 2026-11-11T19:50:30.303Z
- **engine**: https://sparrow-captain-sparrow.light-tech.online

## 用法

```
遇到 sparrow-*.light-tech.online 时直接按本清单分工：① 认证唯一入口 POST /api/auth/google（body 只认 JSON 的 token 字段，值为 Google GSI ID token）；② 无本地账号/口令/注册/邀请面，默认凭据与匿名注册路线无对象，别浪费时间；③ 伪造 Google ID token 必须过 Google 私钥签名（alg=none/弱 HS256/错 aud/过期全部 401 Invalid token）；④ 服务端自签 Bearer 对 GET /api/applications/{appId}/emails 与 /api/ab-test POST 做校验，34 个常见弱 secret + alg 变体全阴；若拿到真实 token 样本才值得做签名/claims 比对；⑤ 后端只有 /api/applications、/api/ab-test、/api/auth/google 三族，其余 404 Cannot GET/POST；⑥ 既有匿名写面（POST/DELETE /api/applications、POST /emails）另见条目 sparrow-light-tech-api-applications-emails-unauth-write；⑦ 遗留：GET /api/ab-test/{真实testId} 匿名可读待验，非 JSON Content-Type 打 /api/auth/google 会 500（未捕获 TypeError）。
```

## 正文

```
# Sparrow 管理身份面阴性结论（2026-11-11，intent 2414）

## 认证实现
- Vite+React SPA，前端路由仅 `/`、`/application/:appId`；无 /login、/admin 静态页。
- 唯一登录：Google Identity Services，client_id `504112649413-ntas0dkjru60041m43cominotfgnamo9.apps.googleusercontent.com`。
- 流程：GSI credential → `POST /api/auth/google {"token": credential}` → 成功 `{email, token, name, picture, exp}` → localStorage.user → 后续 `Authorization: Bearer <token>`。
- 前端 bundle 无 client_secret / API key / 内嵌凭据。

## 路由面（Express + nginx/1.26.0）
- `POST /api/auth/google` → 无有效 Google ID token 时 401 `{"error":"Invalid token"}`（GET 404）。
- `GET /api/applications` 200 匿名；`POST /api/applications` 201 匿名；`DELETE /api/applications/{appId}` 200 匿名（既有 #2001）。
- `GET /api/applications/{appId}/emails` 与 `/emails/download` → 401 `Unauthorized: token required for reading emails`。
- `GET /api/ab-test/{testId}` → 200 `[]` 匿名；`GET /api/ab-test/{testId}/{key}` → 404 `A/B test not found` 匿名；`POST/PUT/DELETE /api/ab-test/*` → 401 `Unauthorized`。
- 其余 23+ 常见路径 404 `Cannot GET/POST`；注册/邀请/本地登录路径全 404。

## 阴性测试（全 401/404，无一条 200）
- /api/auth/google：空/{} /空 token/junk/三段 junk、alg=none 伪 Google ID token（正确 iss/aud/azp/sub/email_verified/exp，email 4 候选）、错 aud、缺 exp、过期、HS256 8 弱 secret、字段变体 credential/id_token/idToken/access_token/credential_token/googleToken、Wix 材料 instance/svSession/ctToken/mediaAuthToken/siteOwnerId/instanceId/siteId/metaSiteId/wixToken。
- emails 读：无 auth、Bearer junk、原始 JWT、alg none/None/NONE/无 alg/HS384/空 secret、HS256 34 个贴合弱 secret、Wix 材料 Bearer、Cookie svSession/token/access_token/user、query token/access_token/auth/jwt/id_token、自定义头 x-access-token/x-auth-token/x-api-token/token/X-Token/x-sparrow-token/x-google-token。
- ab-test 写：无 auth/alg=none/HS256 弱 secret → 401。

## 判据与边界
- 阳性门槛（admin 会话 或 可读 emails 的令牌）未达成；证伪条件=任一伪造返回 200 或错误消息变化。
- 弱密钥未命中不代表不存在（无真实 token 样本）；服务端 Bearer 若为随机串则弱密钥路线不适用；Google ID token 需 Google 私钥，不碰 Google 账号。
- 异常行为：非 JSON Content-Type → POST /api/auth/google 500（未捕获 TypeError）；非白名单 Origin → /api/applications 500（CORS 中间件抛错）。

## 遗留线索
1. `GET /api/ab-test/{真实testId}` 匿名可读性待验。
2. 500 未捕获异常若开 stack trace 可泄露源码路径。
3. sparrow-* 多租户，本结论仅覆盖本站实例。
```
