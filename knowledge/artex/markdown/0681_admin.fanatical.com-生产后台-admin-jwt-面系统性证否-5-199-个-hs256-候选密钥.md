# admin.fanatical.com 生产后台 admin JWT 面系统性证否：5,199 个 HS256 候选密钥 + alg=none/RS→HS/kid/jku 全矩阵恒 401，且 token 前端不解析（不透明会话令牌）

- **code**: admin.fanatical.com-生产后台-admin-jwt-面系统性证否-5-199-个-hs256-候选密钥
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku fan-api-admin + Cloudflare Zero Trust Access + AngularJS "amen" admin
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 20:2x-20:4x UTC 本机 curl + 自建 python 脚本实测：① 5,199 候选 HS256（项目词 1,313 + rockyou top）同一 token 双投递 /bull-api/api/queues（Cookie: AdminAuth=）与 /api/admin/users（Bearer），12 线程 10,398 请求 108.5s，hits=[] errors=[] errN=0，全程无 429；② alg=none/None/NONE/nOnE、两段式、空密钥、kid=1、重复 alg、内嵌 jwk、crit、RS256 头+HS256 签名（TLS 公钥 PEM）全 401/28B「Invalid authorization header」与 401/45B「User not authenticated」；③ kid 注入 14 种（穿越/命令/SQLi/URL）及 kid=/dev/null+空 key 全 401；④ jku/x5u 指向 http://192.0.2.1:81 黑洞仍 0.1s 返回 → 服务端不做动态取键；⑤ JWKS 路径 404/SPA；⑥ /api/admin/google-login/set 全参数形态 400「Invalid access token」；⑦ 当前构建 map /dist/modules.e9712d78.js.map 200/4811745B，444 sources 内无 jwt-decode/jsonwebtoken。
- **path**: pocs/admin.fanatical.com-生产后台-admin-jwt-面系统性证否-5-199-个-hs256-候选密钥/poc.txt
- **tags**: fanatical,admin,jwt,auth-bypass,negative,heroku,cloudflare-access,bull-board
- **created_at**: 2026-11-11T20:52:04.445Z
- **engine**: https://admin.fanatical.com（Heroku 源站 13.248.131.213 / 15.197.152.254 / 35.71.150.51，--noproxy '*' --resolve 直连）

## 用法

```
后续 worker 判据与跳过清单（别再重复手搓）：
1) 不要在该目标重跑 HS256 弱密钥/alg=none/kid 穿越/jku 取键——已 5,199+全矩阵证否。
2) token 契约：Bearer（localStorage 'token'）+ Cookie AdminAuth（path=/bull-api/），前端无 JWT 解码；不要假设 jose/jsonwebtoken 可解析 claim。
3) 唯一剩余可利用路径 = 先拿到任意 fanatical 用户会话（atok/pp_token）：admin app 与 www 共用同一 auth 中间件（两边 401 文案分别为 "Missing authorization header"/"Invalid authorization header"，28B 同构）；拿到后立刻用同一 token 打 /api/admin/users 与 /bull-api/api/queues，验证 admin 侧是否只验签不验 role/adminRoles。
4) 若继续 JWT 方向，优先资产是 adminstaging/其它 admin 环境的 google-login（唯一签发点，无 state，redirect_uri 固定），而不是生产弱密钥。
最小复现基线（可直接抄）：
  curl -sk --noproxy '*' --resolve admin.fanatical.com:443:13.248.131.213 -H 'Cookie: AdminAuth=abc' https://admin.fanatical.com/bull-api/api/queues   # 401/28 Invalid authorization header
  curl -sk --noproxy '*' --resolve admin.fanatical.com:443:13.248.131.213 -H 'Authorization: Bearer abc.def.ghi' https://admin.fanatical.com/api/admin/users  # 401/45 User not authenticated
```

## 正文

```
# admin.fanatical.com admin JWT 面证否（task#5 / intent#2724）

## 结论
生产后台 admin JWT 的签名/校验实现未见可利用缺陷：5,199 个 HS256 候选密钥、全部头部攻击形态、kid/jku 动态取键全部失败；服务端恒返两套固定 401 文案。token 在前端不被解析（无 jwt-decode），疑为不透明会话令牌，JWT 类攻击很可能根本不适用。

## 固定错误语义（做分叉判据用）
- /bull-api/api/queues：无 cookie → 401/67B `Missing authorization cookie - <a href="/">Log into admin again</a>`；任意 cookie → 401/28B `Invalid authorization header`
- /api/admin/users：无凭据或任意伪造 Bearer → 401/45B `{"code":401,"error":"User not authenticated"}`（Cookie: AdminAuth= 被完全忽略）
- /api/user/orders（admin 与 www/ws15 同）：无 token → 401/28B `Missing authorization header`；任意伪造 → 401/28B `Invalid authorization header`

## 已证否清单
- HS256 弱密钥：5,199 候选（项目词 + rockyou top；secret/changeme/fanatical/bundlestars/amen/fan-api-admin/heroku/jsonwebtoken 默认串/null/undefined/Sentry release/OAuth client_id）
- alg=none 族：none/None/NONE/nOnE、两段式、空签名、缺 alg、alg=none+HS 签名
- 密钥混淆：RS256 头 + HS256 签名（用 admin.fanatical.com 实际 TLS 公钥 PEM）
- kid 注入：路径穿越、file://、命令分隔符、反引号、SQLi、URL、Windows 路径、200B 填充、/dev/null+空 key、/proc/self/cmdline、/etc/hostname
- jku/x5u：指向黑洞 http://192.0.2.1:81 时响应 0.1s 内返回 ⇒ 服务端不取键
- JWKS 端点：/.well-known/jwks.json、/jwks.json、/api/admin/jwks.json、/api/admin/keys、/.well-known/openid-configuration → 404/SPA
- 签发绕过：/api/admin/google-login/set 对 code/access_token/token/id_token/email/{} 一律 400/22B `Invalid access token`

## token 契约（当前构建 /dist/modules.e9712d78.js.map，200/4,811,745B，444 sources）
GET /api/admin/google-login → 302 accounts.google.com（client_id 670578422488-chc8098u5tglr30cpum15bojae4f626i，scope=userinfo.email，redirect_uri 固定 /api/admin/google-login/callback，无 state）→ POST /set {code} 返回 {token, role, adminRoles|adminRole, _id, email, email_newsletter, email_confirmed} → localStorage 'token' + `Authorization: Bearer <token>` + `Cookie AdminAuth=<token>; path=/bull-api/; secure; sameSite=strict`。全量 app 源码无 jwt-decode/jsonwebtoken。

## 剩余路径（交规划者）
任一真实用户会话（atok/pp_token/magic-link cast 所得）→ 立即用同一 token 打 /api/admin/users 与 /bull-api/api/queues，测 admin 侧是否只验签不校验 role/adminRoles。admin app（fan-api-admin）与 www（fan-api-live）共用同一 auth 中间件错误语义，此路径成立即为整条 admin 面（serials/export、generate-admin-login-token、heroku-scripts/run、image/upload）一次性打开。
```
