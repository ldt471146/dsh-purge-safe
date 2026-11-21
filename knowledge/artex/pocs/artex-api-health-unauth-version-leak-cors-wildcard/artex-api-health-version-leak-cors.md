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
