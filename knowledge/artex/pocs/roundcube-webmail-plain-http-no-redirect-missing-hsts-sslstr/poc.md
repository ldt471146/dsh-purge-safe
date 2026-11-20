# Roundcube / Plesk Webmail：80 端口明文可达 + 缺失 HSTS（SSL-strip 降级面判定与复现）

## 结论
- `http://<webmail-host>/` 直接 `200 OK` 返回 Roundcube 登录页，**无 301/308 跳转**到 https；
- HTTP 响应下发的 `roundcube_sessid` cookie **不带 `Secure`**（仅 `HttpOnly`）；
- 登录表单 `action="/?_task=login"` 为**相对路径**，在 http 页面上提交即走明文；
- HTTPS 侧可用（HTTP/2 200），但响应头**缺失 `Strict-Transport-Security`**；
- 应用/组件：Plesk 承载的 Roundcube Webmail（webmail 虚主机）、后端 Apache。

## 影响
1. 处于受害者到目标网络路径上的验证者，可用 SSL-strip / 协议降级把 https 访问降为 http，受害者**无任何升级提示**。
2. 邮箱账号口令与 `roundcube_sessid` 全程明文，可被截获并重放登录 Plesk / Roundcube。
3. 判为 low 而非 info：不是「多一个明文端口」的冗余资产，而是可组合成实际降级验证的缺保护面。

## 复现（全部直连，勿经代理）

### 1) 明文口直接给应用、不跳转
```
curl -sS -D - -o /dev/null http://<webmail-host>/
```
```
HTTP/1.1 200 OK
Server: Apache
Set-Cookie: roundcube_sessid=<REDACTED>; path=/; HttpOnly
（无 Location / 无 301/308）
```
判据：**200 + 无 Location**。若 301/308 指向 https，本条即证伪。

### 2) 登录表单为相对 action（明文提交）
```
curl -s http://<webmail-host>/?_task=login | grep -i '<form'
```
```
<form id="login-form" method="post" action="/?_task=login">
```

### 3) 明文通道的登录提交被真实处理
```
POST http://<webmail-host>/?_task=login  (body: _task=login&_action=login&_user=<u>&_pass=<p>)
→ "Login failed."   （口令错误回显，证明明文提交被服务端处理）
```

### 4) HTTPS 侧缺 HSTS
```
curl -sk -D - -o /dev/null https://<webmail-host>/
```
```
HTTP/2 200
Set-Cookie: roundcube_sessid=<REDACTED>; path=/; secure; HttpOnly
（无 Strict-Transport-Security）
```
对照：HTTPS 侧同名 cookie 带 `secure`，HTTP 侧不带 —— 说明服务端**本就会按信道区分 cookie**，只是没有强制升级。

## 证伪条件
http 端口返回 301/308 指向 https，**或** https 响应带 `Strict-Transport-Security`。

## 利用方式
同网段 `sslstrip`（或 bettercap `caplets/sslstrip`）配合 ARP 欺骗，或将目标流量引入恶意热点；受害者在 `http://<webmail-host>` 登录后，明文口令与 `roundcube_sessid` 即可被抓取，随后直接重放登录 Plesk / Roundcube。

限制：信道级漏洞，单独不能获得命令执行；无真实用户从 http 登录则拿不到真实凭据样本。

## 修复建议
1. 边缘（nginx/Apache/Plesk）对 80 统一 `return 301 https://$host$request_uri;`，80 仅做跳转。
2. HTTPS 响应下发 `Strict-Transport-Security: max-age=31536000; includeSubDomains`（确认全子域 HTTPS 后加 `preload`）。
3. HTTP 侧不下发会话 cookie，或强制 `Secure`。

## 同类参照
kb 条目 id 485（Sub2API 站点 80 端口明文 + 缺 HSTS）为同一判定套路、不同产品，可互相参照。
