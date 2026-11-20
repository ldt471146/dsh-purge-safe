# Roundcube / Plesk Webmail 登录页 80 端口明文可达 + 缺失 HSTS（SSL-strip 凭据截获面）

- **code**: roundcube-webmail-plain-http-no-redirect-missing-hsts-sslstr
- **kind**: template
- **category**: info-leak
- **component**: Roundcube Webmail (Plesk webmail vhost)
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#11，2026-11-11 14:22-14:31 UTC 在本机 Windows 工作站用 curl 8.5.0 直连 88.208.224.249 实测：① GET http://<webmail-host>/ → HTTP/1.1 200 OK，Server: Apache，Set-Cookie: roundcube_sessid=<REDACTED>; path=/; HttpOnly（无 Secure），无 Location（不跳 443）；② GET http://<webmail-host>/?_task=login → 登录页 <form id="login-form" method="post" action="/?_task=login">（相对路径，明文提交）；③ GET https://<webmail-host>/ → HTTP/2 200，Set-Cookie 带 secure，但响应头无 Strict-Transport-Security；④ HTTP POST 登录被服务端真实处理，返回 "Login failed."。据此判定：明文口直接给应用、不跳转、HTTPS 侧无 HSTS，SSL-strip 降级面成立。
- **path**: pocs/roundcube-webmail-plain-http-no-redirect-missing-hsts-sslstr/poc.md
- **tags**: hsts,strict-transport-security,plaintext-http,ssl-strip,downgrade,roundcube,plesk,webmail,session-cookie,transport-layer,info-expose,tls
- **created_at**: 2026-11-11T14:33:52.734Z
- **engine**: webmail.goffsgames.co.uk (88.208.224.249)

## 描述

判定 Plesk 承载的 Roundcube Webmail 登录页「80 端口明文直接 200 且不重定向 443 + HTTPS 响应缺失 Strict-Transport-Security + HTTP 会话 cookie 无 Secure + 登录表单为相对 action」这一类传输层保护缺失，可直接推出 SSL-strip 降级利用面：网络中间位置的验证者可拦截邮箱账号口令与 roundcube_sessid，为后续登录 Plesk/Roundcube 采集凭据。仅需网络可达、无需账号；属信道级问题，单独不能获得命令执行，需真实用户从 http:// 登录才有样本。

## 用法

```
【三步判据，任一步不成立即证伪】
1) 明文口是否直接给应用：curl -sS -D - -o /dev/null http://<webmail-host>/ → 出现 200 + Roundcube 登录页且 **无 Location/301/308** 即成立；若 301 跳 https 则本条不适用。
2) HTTP 会话 cookie 是否缺 Secure：看上面响应头 Set-Cookie: roundcube_sessid=...; path=/; HttpOnly —— **无 secure** 即成立（HTTPS 侧同名 cookie 应带 secure，可作对照）。
3) HTTPS 侧是否缺 HSTS：curl -sk -D - -o /dev/null https://<webmail-host>/ | grep -i strict-transport-security → 无输出即成立。多打几次并把全部响应头落盘 grep 求零命中，避免偶发。
【补充核验】
- 登录表单 action：curl -s http://<webmail-host>/?_task=login | grep -i '<form' → action 为相对路径 "/?_task=login"，在 HTTP 页面上提交即走明文。
- 表单确被真实处理：POST http://<webmail-host>/?_task=login 带 _task=login/_action=login/_user/_pass，返回 "Login failed."（口令错误）即证明明文通道提交被处理。
- 若走系统代理/企业代理会拿到代理侧头，必须 --noproxy '*'（Linux/Windows curl 同）。
【落地利用】同网段 ARP 欺骗 + sslstrip（或 bettercap caplets/sslstrip），或把受害者流量引入恶意热点；受害者以 http:// 打开 webmail 登录后，可抓取明文账号口令与 roundcube_sessid 会话，随后直接重放登录 Plesk/Roundcube。
【常见失败原因】① 目标 80 口已 301 跳 https → 已修，不适用；② 只看首页不看登录页/表单 action，漏掉明文字段提交路径；③ 只抓一次响应头就下结论，易把偶发当缺失；④ 走了代理导致响应头不真实。
【修复建议】边缘（nginx/Apache/Plesk）对 80 统一 return 301 https://$host$request_uri; 全站 HTTPS 响应下发 Strict-Transport-Security: max-age=31536000; includeSubDomains（全子域就绪后加 preload）；HTTP 侧不下发会话 cookie 或强制 Secure。
【同类参照】kb 条目 id 485（Sub2API 明文 HTTP + 缺 HSTS）为同一判定套路、不同产品，可互相参照。
```

## 正文

```
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

```
