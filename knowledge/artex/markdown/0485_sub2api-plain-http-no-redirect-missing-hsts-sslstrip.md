# Sub2API 站点 80 端口明文 HTTP 直接 200 无跳转 + 全站缺失 HSTS（SSL-strip 降级面判定与复现）

- **code**: sub2api-plain-http-no-redirect-missing-hsts-sslstrip
- **kind**: template
- **category**: env
- **component**: Sub2API 0.2.x + Photon-Edge 边缘（HTTPS/plain-HTTP 双栈部署）
- **versions**: 0.2.19（应用侧版本，可从 /api/v1/settings/public 读出）
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#609，2026-11-01 06:31-07:43 UTC 在本机 Windows 用 curl --noproxy '*' 直连实测：① GET http://target485.example.com/ → HTTP/1.1 200 OK，text/html，无 Location/无 301/308；② GET http://target485.example.com/api/v1/settings/public → 200 application/json（业务 API 明文可达）；③ GET https://target485.example.com/home → 200，有 CSP/X-Frame-Options: DENY/nosniff/Referrer-Policy，但无 Strict-Transport-Security；④ 本地落盘 39 份响应头（D:\ARTEX\data\tasks\609\i6691\*.hdr）grep Strict-Transport-Security 命中 0；⑤ http/https 首页正文均 3288 字节、Etag 与 Server 相同，证明是同一应用而非残缺镜像。另证：index bundle 里 localStorage.setItem("auth_token"/"refresh_token")，令牌对同源 JS 可读，故明文信道可被中间人直接取走。
- **path**: pocs/sub2api-plain-http-no-redirect-missing-hsts-sslstrip/poc.md
- **tags**: hsts,strict-transport-security,plaintext-http,ssl-strip,downgrade,misconfiguration,sub2api,photon-edge,transport-layer
- **created_at**: 2026-11-01T07:52:52.151Z
- **engine**: http://target485.example.com/ (80/tcp)

## 描述

判定「80 端口明文提供完整应用 + 全站无 HSTS」这一类传输层保护缺失，可直接推出 SSL-strip 利用面：浏览器首次以 http:// 进入后无任何升级信号，口令与 Bearer/refresh token 全程裸奔。仅需网络可达、无需账号。注意这是信道级问题，单独不能 getshell，需真实用户登录才能拿到令牌样本。

## 用法

```
【三步判据，任一步不成立即证伪】
1) 明文口是否直接给应用：curl --noproxy '*' -sS -D - -o NUL http://T/  → 出现 200 + text/html 且**无 Location/301/308** 即成立；若返回 301 跳 https 则本条不适用。
2) 业务 API 是否同样明文可达：curl --noproxy '*' -sS -D - http://T/api/v1/settings/public  → 200 application/json（Sub2API 为 /api/v1/* 前缀；其他产品换成任一免认证公开接口）。顺便再打 /api/v1/auth/me 应得 401，「Authorization header is required」说明未加认证头，正常。
3) HTTPS 侧是否缺 HSTS：curl -sk -D - -o NUL https://T/ | grep -i strict-transport-security → 无输出即成立。多打几次排除偶发，并把全部响应头落盘 grep 一遍求零命中。
【等价性核验（区分「缺保护」与「残缺镜像」）】分别取 http/https 首页正文长度与 Etag/Server：等长且同 Etag 即同一应用，降级无损、用户无察觉，危害才成立。
【令牌暴露面确认】抓前端 bundle grep localStorage.setItem("auth_token" / "refresh_token")；存在即说明令牌可被同源 JS 读，明文信道下中间人可直接取。
【落地利用】同网段 ARP 欺骗 + sslstrip（或 bettercap caplets/sslstrip），或把流量引入恶意热点；受害者在 http 登录后抓 POST /api/v1/auth/login 的明文口令与其响应中的 access_token/refresh_token，再 Authorization: Bearer <token> 重放。refresh_token 长效，失窃窗口远大于会话本身。
【常见失败原因】① 目标 80 口 301 跳转 → 已修，无需入库利用；② 走了系统代理/企业代理，拿到的是代理侧响应头 → 必须 --noproxy '*'；③ 只看首页不看 API，漏掉真正敏感的信道；④ 只抓一次响应头就下结论，容易把偶发当成缺失。
【修复建议】80 口统一 return 301 https://$host$request_uri；全站下发 Strict-Transport-Security: max-age=31536000; includeSubDomains（全子域就绪后加 preload）；refresh_token 改 HttpOnly; Secure; SameSite=Strict Cookie。
```

## 正文

```
# 80 端口明文提供完整应用 + 全站缺失 HSTS（SSL-strip 利用面）

## 结论
- `http://<target>:80` 直接 `200 OK` 返回完整 SPA 与业务 API，**无 301/308**；
- HTTPS 侧所有响应**均无 `Strict-Transport-Security`**；
- http 与 https 是**同一应用**（首页正文等长、Etag/Server 相同、安全头一致），降级后功能无损，用户无察觉；
- 应用把 access_token / refresh_token 存 localStorage 并以相对 origin 调 API，令牌对同源 JS 可读 ⇒ 明文信道下可被中间人直接取走。

## 影响
1. SSL-strip / 协议降级：浏览器首次以 `http://` 进入后没有任何升级信号，登录口令、Bearer、refresh_token 全程明文。
2. 同网段攻击者（ARP 欺骗 / 恶意热点 / 上游代理）即可拿到一次性口令与**长效 refresh_token**，重放接管账号；失窃窗口远大于会话本身。
3. 判定为 low 而非 info：不是「多一个明文端口」的冗余资产，而是可组合成实际降级攻击的缺保护面。

## 复现（全部 --noproxy 直连，勿经代理）

### 1) 明文口直接给应用、不跳转
```
curl.exe --noproxy "*" -sS -D - -o NUL http://<target>/
```
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Server: Photon-Edge
Etag: "4fd048c036095271-c03ee9a328086de0"
（无 Location / 无 301/308 / 无 Strict-Transport-Security）
```
判据：**200 + 无 Location**。若为 301/308 指向 https，本条即证伪。

### 2) http 与 https 同一应用（正文等长）
```
http_len=3288  https_len=3288     # 两端口同一 Etag、同一 Server、同一组 CSP / XFO: DENY / nosniff
```

### 3) 业务 API 明文可达
```
curl.exe --noproxy "*" -sS -D - http://<target>/api/v1/settings/public
→ HTTP/1.1 200 OK, application/json, 返回完整公开配置 JSON（含 "version":"0.2.19"）

curl.exe --noproxy "*" -sS http://<target>/api/v1/auth/me
→ 401 {"code":"UNAUTHORIZED","message":"Authorization header is required"}
```

### 4) 凭据接口在明文与 HTTPS 行为完全一致（只少了加密层）
```
POST http://<target>/api/v1/auth/login  {"email":"a@b.c","password":"wrong"}
→ 401, Content-Length: 81, {"code":401,...,"reason":"INVALID_CREDENTIALS"}
POST https://<target>/... 同 body → 401, Content-Length: 81, 同一 JSON

POST http(s)://<target>/api/v1/auth/refresh {"refresh_token":"junk"} → 两边均 401, Content-Length: 79
```

### 5) HSTS 缺失
```
curl.exe --noproxy "*" -sk -D - -o NUL https://<target>/
→ 有 CSP / X-Frame-Options: DENY / X-Content-Type-Options: nosniff / Referrer-Policy，唯独无 Strict-Transport-Security
```
连续 3 次均无；把全部响应头落盘后 `Select-String Strict-Transport-Security` 命中 0（39 份捕获）。

### 6) 令牌暴露面
index bundle 内 `localStorage.setItem("auth_token", ...)` / `setItem("refresh_token", ...)` ⇒ 令牌可由同源 JS 读取，明文 HTTP 下同样暴露。

## 证伪条件
http 端口返回 301/308 指向 https，**或** https 响应带 Strict-Transport-Security —— 实测两者均缺失。

## 利用方式
同网段 `sslstrip`（或 bettercap `caplets/sslstrip`）配合 ARP 欺骗，或将目标流量引入恶意热点；受害者在 `http://<target>` 登录后，明文口令与 `POST /api/v1/auth/login` 响应中的 `access_token`/`refresh_token` 即可被抓取，随后直接 `Authorization: Bearer <token>` 重放。

限制：信道级漏洞，单独不能 getshell；无已知账号口令时拿不到真实被窃 token（需真实用户登录才有样本）。

## 对照项（说明缺的只是传输层强制）
CSP `frame-ancestors 'none'`、X-Frame-Options: DENY、nosniff、Referrer-Policy 均在位；logout 下发的 23 个 `oauth_*` cookie 均为 `HttpOnly; Secure; SameSite=Lax`。即：应用层安全头齐备，唯独缺「升级强制」与 HSTS。

## 修复建议
1. 边缘（nginx/CDN）对 80 统一 `return 301 https://$host$request_uri;`，80 仅做跳转。
2. 所有 HTTPS 响应下发 `Strict-Transport-Security: max-age=31536000; includeSubDomains`（确认全子域 HTTPS 后加 `preload` 并提交 hstspreload）。
3. refresh_token 改为 `HttpOnly; Secure; SameSite=Strict` Cookie，降低 XSS 与明文信道双面暴露。

## 落盘证据
39 份响应头捕获（*.hdr），http/https 双端口对照正文与头，全部为 --noproxy 直连、finding traffic binding 为空，证据以命令回显为准。

```
