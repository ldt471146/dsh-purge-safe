# Cloudflare 源站 IP 直连暴露：CDN 绕过判定与复现

## 结论
目标域名走 Cloudflare，但真实源站 `23.147.164.112` / `23.147.164.132` 的 **80 与 443 端口都对公网直接开放**，直连返回与 CDN 相同长度的同一 Sub2API（Gin）应用，响应头 `Server: Photon-Edge` 且**不含任何 Cf-* 头**；`/cdn-cgi/trace` 在源站上是应用 404。攻击者可完全绕过 Cloudflare 的 WAF、速率限制、Bot 挑战与源站隐藏，直接对 `/api/v1/*` 做测试。源站 80 明文 200 且不跳转 HTTPS（该明文/HSTS 面单独见 kb#485）。

## 前置条件
- 目标域名解析落在 CDN：响应带 `Server: cloudflare` + `CF-RAY` + `cf-cache-status`。
- 已拿到候选源站 IP：CT 日志、DNS 历史、子域解析、C 段反查、前端配置/`api_base_url` 泄露、证书 SAN 反查。
- 本机不要走 HTTP 代理（代理会按 Host 分流，制造「Host 命中源站」的假象）。统一 `--noproxy "*"` + `--resolve`。
- 只做只读判定；后续业务测试自行控制频率与范围。

## 四步判定（缺一不可）

### 1) CDN 基线
```bash
curl -sS -D - -o cdn_body.html https://<TARGET>/
sha256sum cdn_body.html
```
期望：`Server: cloudflare`、`CF-RAY: ...-XXX`、`cf-cache-status: DYNAMIC`、`Alt-Svc: h3=":443"`。

### 2) 直连候选源站 443
```bash
curl -sk --noproxy "*" --resolve <TARGET>:443:<ORIGIN_IP> \
  -D - -o origin_body.html https://<TARGET>/
sha256sum origin_body.html
```
成立表现（实测）：
```
HTTP/1.1 200 OK
Content-Length: 798
Content-Type: text/html
Server: Photon-Edge
Etag: "6ae84cda-31e"
Last-Modified: Mon, 02 Nov 2026 08:42:02 GMT
（无 CF-RAY / cf-cache-status / cf-* 任何头）
```
两个源站 IP（.112/.132）头与 body 逐字节一致；`.113` 历史解析同样指回同一实例，可作第三入口旁证。

### 3) 动态性 + 同一应用
```bash
# 连续两次，X-Request-Id / CSP nonce 应每次变化
curl -sk --noproxy "*" --resolve <TARGET>:443:<ORIGIN_IP> -D - https://<TARGET>/api/v1/settings/public -o /dev/null
curl -sk --noproxy "*" --resolve <TARGET>:443:<ORIGIN_IP> -D - https://<TARGET>/api/v1/settings/public -o /dev/null
```
实测：两次 `X-Request-Id` 不同、CSP `nonce-...` 不同；`/api/v1/settings/public` 直连源站为 `200 application/json`，与 CDN 路径 body 一致 → 打到的是活的应用，不是静态镜像或缓存。
动态标记 + 与 CDN body 的长度/Etag/Last-Modified 对齐，才说明「同一应用、两个入口」。

### 4) 反向探针 `/cdn-cgi/trace`
```bash
curl -sk --noproxy "*" --resolve <TARGET>:443:<ORIGIN_IP> https://<TARGET>/cdn-cgi/trace
```
源站返回应用自身 404（本例 `18B` `404 page not found`），而不是 Cloudflare 的 `fl=... h=... ip=...` trace 文本。

### 5) 可选：证书一致性
源站证书 `CN=<TARGET>`，`SAN=<TARGET>, www.<TARGET>`，Issuer `LiteSSL RSA CA 2025`，有效期 2026-10-31→2027-01-29；两 IP 证书序列号相同 → 同一源站集群。

## 成立判据
四条同时满足：
1. 直连 443 返回**真实业务响应**（非 CDN 错误页/默认站点），且响应头无 `cf-*`；
2. 同域名经 CDN 访问有 `CF-RAY`，body 与直连一致但响应头/可达性不同；
3. 动态标记（X-Request-Id、CSP nonce）随请求变化 → 活源站；
4. 源站证书 CN/SAN 覆盖目标域名 → 不是别人家的服务器。

## 影响
- 绕过 CF 的 WAF / 300 RPM 级限流 / Bot 挑战 / 地域封禁，直接测后端 API，避免 CDN 的 456/429 干扰。
- 源站 80 明文承载应用与 Bearer/refresh token（本例明文 http 上 `/api/v1/user/profile` 带合法 JWT 返回 200 JSON），可与 kb#485 的 SSL-strip 面组合。
- 直连后原 CDN 侧「按来源 IP」的逻辑可被请求头伪造击穿（`CF-Connecting-IP`，见 kb#584）；管理端 IP 白名单也需同样复核。

## 常见失败原因
- 走了系统/企业代理 → 拿到的是代理侧响应（必须 `--noproxy "*"`）。
- 只改 `Host` 不 `--resolve`/不改 SNI → 仍走 CDN。
- Windows schannel TLS 1.3 握手失败 → `-k` 或 `--tlsv1.2`。
- 把 Photon-Edge 边缘 IP 当源站（本例 `.111/.121/.126` 为边缘）→ 用 Server 头、证书、动态标记区分。
- 源站 Host 白名单：异常 Host 会被边缘/源站直接 RST，必须真实域名 Host + 正确 SNI。
- 目标 80 已改 301 → 只剩 443 可绕，明文面不适用。
- 只看一次响应就下结论 → 至少两次，确认动态标记变化。

## 与既有条目的差异
- kb#94：从 TLS 证书 CN 反查不走 CDN 的子域来找源站（子域枚举路线）；本条是「已有候选 IP 的直接暴露判定」。
- kb#485：80 明文 + 缺 HSTS（SSL-strip）面；本条核心是 443/80 双端口直连绕过 CDN，明文只作旁证。
- kb#583/#584：以「源站可直连」为前提的应用层 API Key oracle / CF-Connecting-IP 绕过，不重复源站发现判定。
