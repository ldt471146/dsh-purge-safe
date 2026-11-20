# fanatical staging 顾客会话跨环境打生产证否：Bearer/Cookie 双形态 × 店面/后台/Bull 全 401，生产 admin 非「只验签不验 role」

- **code**: fanatical-staging-session-to-production-negative-intent3154
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku fan-api-live（admin.fanatical.com 源站）+ fan-api-staging（apistaging）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 curl 实测（intent#3154，fact#3169 confirmed）：真实 staging 顾客会话 6af4d16bf80a0b26dc1b6466.7d645aba-...-fc2e9d（apistaging Fandom OAuth 签发，credential#26）打生产源站直连 admin.fanatical.com@3.33.161.45 + Host + 每请求唯一 anonid/XFF：/api/user/{profile,refresh-auth,orders,keys} 全 401/28B "Invalid authorization header"（无凭据基线 401/28B "Missing authorization header"）；/api/admin/{users,serials/export,users/generate-admin-login-token/1,redeem-codes/lookup/1,serials/lookup/1,serials/count,products/preview/<id>/en} 与 POST /api/admin/redeem-codes/test-code {真实 bundleId} 全 401/45B {"code":401,"error":"User not authenticated"}（与任意伪造 token 同语义）；Cookie: AdminAuth 打 /bull-api/api/queues → 401/28B "Invalid authorization header"（无 cookie 67B Missing）；经 CF www 同 401。阳性对照：同一 token 打 adminstaging /api/user/orders 200/2B []、/api/admin/users 403/88B "User not permitted to user:view"。
- **tags**: fanatical,staging,admin,cross-environment,session,atok,negative,heroku,bull-board,rbac
- **created_at**: 2026-11-11T21:53:16.646Z
- **engine**: https://admin.fanatical.com（Heroku 源站 3.33.161.45，--noproxy '*' --resolve 直连）

## 用法

```
后续 worker 跳过清单与判据（别再重复）：
1) 不要再用 staging/staging2/adminstaging 签发的任何顾客 token 去打生产 www/admin 的 /api/user/* 或 /api/admin/*——已实测全 401，生产与 staging 不共享会话存储/签名密钥。
2) 固定错误语义（生产，源站直连）：/api/user/* 无凭据=401/28B "Missing authorization header"，任意无效 token=401/28B "Invalid authorization header"；/api/admin/*=401/45B {"code":401,"error":"User not authenticated"}（与无凭据、伪造完全一致）；/bull-api/api/queues 无 cookie=401/67B "Missing authorization cookie..."，任意无效 cookie=401/28B "Invalid authorization header"。
3) 判据提醒：只有在生产侧看到 403（如 "User not permitted to <permission>"）才说明「会话被接受但 RBAC 拒」；401 45B 表示 token 在鉴权层即被拒，不构成跨环境信任。
4) 生产 admin 路由存在性对照：/api/admin/orders、/api/admin/users/me 404/0B（未挂载）；/api/admin/b2b/get-b2b-serials 无 id 为 404、/{id} 形态为 401。
5) 真正剩余方向只有「生产自签发的会话」：生产 Fandom client 在 services.fandom.com invalid_client、reCAPTCHA 硬墙、Publisher Portal pre-auth token 全拒，这三条已有结论不变。
```
