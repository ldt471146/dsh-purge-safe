# artex 0.4.5 /api/health 未授权泄露服务名与精确版本 + CORS 通配（ACAO:*）

- **code**: artex-api-health-unauth-version-leak-cors-wildcard
- **kind**: poc
- **category**: info-leak
- **component**: artex（自研 Web 服务，HTTP :8787，version 0.4.5）
- **versions**: 0.4.5
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#664 / finding 1324，2026-11-10T19:52:28Z 在本机 Windows 用 curl.exe --noproxy '*' 直连 127.0.0.1:8787 实测：GET /api/health → HTTP 200 / Content-Length 48，body 为 {"ok":true,"service":"artex","version":"0.4.5"}，响应头含 Access-Control-Allow-Origin: * 与 Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS；同批对照 GET /api/version → 401 Unauthorized / {"error":"非预期"}（22B），OPTIONS /api/health → 204 且回 ACAO:*，证明是单接口鉴权缺口而非全局无鉴权。原始报文落盘 b__api_health.bin 与 b__api_version.bin。
- **path**: pocs/artex-api-health-unauth-version-leak-cors-wildcard/artex-api-health-version-leak-cors.md
- **tags**: artex,api/health,version-fingerprint,info-disclosure,cors-wildcard,acao,unauth,recon
- **created_at**: 2026-11-10T19:54:21.986Z
- **engine**: http://127.0.0.1:8787

## 描述

artex 服务的健康检查端点 /api/health 不需要任何凭据即返回服务名与精确版本号（0.4.5），并带 Access-Control-Allow-Origin: *，任意网页的 JS 可跨域读取该指纹；同类接口 /api/version、/api/status 均需鉴权（401），说明这是该单接口的鉴权缺口。价值在于零噪音拿到精确版本，供后续按 0.4.5 匹配版本级问题，并可作为 CORS 通配的证据链。

## 用法

```
1) 一律加 --noproxy '*' 直连，本机若有记录代理（如 127.0.0.1:25101）会把回环请求变成伪造 502 空体，直接造成假阴性。
2) 取指纹：curl.exe -sS -i --noproxy '*' http://127.0.0.1:8787/api/health
   命中：HTTP 200，body {"ok":true,"service":"artex","version":"0.4.5"}，Header 含 Access-Control-Allow-Origin: *。
3) 做鉴权对照（证明是单接口缺口）：curl.exe -sS -i --noproxy '*' http://127.0.0.1:8787/api/version → 期望 401 {"error":"非预期"}。
4) 验证浏览器端可跨域读：curl.exe -sS -i --noproxy '*' -X OPTIONS http://127.0.0.1:8787/api/health → 期望 204 + ACAO:*，即预检放行任意源。
5) 判据三条同时成立才算命中：/api/health 200 且 body 含 service+version；响应头 ACAO:*；相邻 /api/version 返回 401。
6) 后续动作：把 version 当作精确版本锚点去比对上游 release/changelog 与 Nday；CORS 通配只作证据与浏览器侧侦察面，别把它当独立可利用漏洞夸大。
7) 若只见版本不见 ACAO，先怀疑反向代理剥离响应头；若 /api/health 也 401，则说明该版本已收敛，本条判据不成立。
```

## 正文

```
# artex /api/health 未授权版本指纹 + CORS 通配（实测 0.4.5）

## 前置条件
- 目标 HTTP 可达（本次为回环 http://127.0.0.1:8787）。
- 不需要 Cookie / Token / 会话。
- 必须绕过本机记录代理：`--noproxy '*'`。经代理访问本机会得到伪造 502 空体，是典型的假阴性来源。

## 1. 取指纹（核心请求）
```
GET /api/health HTTP/1.1
Host: 127.0.0.1:8787
User-Agent: <UA>
Accept: */*
```
响应：
```
HTTP/1.1 200 OK
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Access-Control-Allow-Origin: *
Content-Type: application/json
Content-Length: 48

{"ok":true,"service":"artex","version":"0.4.5"}
```

## 2. 鉴权对照（证明是单接口缺口，不是全局无鉴权）
```
GET /api/version HTTP/1.1
Host: 127.0.0.1:8787
User-Agent: <UA>
Accept: */*
```
响应：
```
HTTP/1.1 401 Unauthorized
Access-Control-Allow-Origin: *
Content-Type: application/json
Content-Length: 22

{"error":"非预期"}
```
同类 /api/status 同样要求鉴权。

## 3. 预检放行（浏览器端跨域读取成立）
```
OPTIONS /api/health HTTP/1.1
Host: 127.0.0.1:8787
User-Agent: <UA>
```
响应：
```
HTTP/1.1 204 No Content
Access-Control-Allow-Headers: Content-Type
Access-Control-Allow-Methods: GET,POST,PUT,DELETE,OPTIONS
Access-Control-Allow-Origin: *
```

## 4. 一键命令
```bash
T=http://127.0.0.1:8787
curl.exe -sS -i --noproxy '*' "$T/api/health"
curl.exe -sS -i --noproxy '*' "$T/api/version"
curl.exe -sS -i --noproxy '*' -X OPTIONS "$T/api/health"
```

## 判据
三条同时成立即命中：
1. `/api/health` 返回 200，body 含 `service` 与 `version`；
2. 响应头含 `Access-Control-Allow-Origin: *`；
3. 相邻 `/api/version`（或 `/api/status`）返回 401，形成鉴权对照。

## 失败时的常见原因
- 走了记录代理 → 502 空体：加 `--noproxy '*'`。
- 端口或 Host 不对 → 连接拒绝 / 404。
- 网关把 ACAO 头剥了 → 只剩版本泄露，CORS 部分不成立。
- 目标已收敛该接口 → `/api/health` 也 401，本条判据作废。

## 影响面与后续
- 零噪音拿到精确版本 0.4.5，可直接作为版本锚点比对上游 changelog / Nday。
- ACAO:* + 预检放行意味着任意网页 JS 可跨域读取版本信息，属浏览器侧侦察面。
- 严重度 low：只泄露服务名与版本，未到可利用层；价值在情报精准度。

```
