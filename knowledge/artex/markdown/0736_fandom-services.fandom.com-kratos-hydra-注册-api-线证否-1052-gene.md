# Fandom（services.fandom.com）Kratos/Hydra 注册 API 线证否：1052 generic-user-data-missing + auth.fandom.com 全站 CF 挑战，无法用纯 HTTP 取 fanatical OAuth code

- **code**: fandom-services.fandom.com-kratos-hydra-注册-api-线证否-1052-gene
- **kind**: poc
- **category**: auth-bypass
- **component**: Fandom Ory Kratos / Hydra
- **source**: self
- **verified**: 1
- **verified_note**: 实测于 fanatical.com 靶标（2026-11-11/12）：GET https://services.fandom.com/kratos-public/self-service/registration/browser → 302 flow；POST flow.action（csrf_token+method=password+traits.username+traits.email+password，Origin: auth.fandom.com）→ 302 auth.fandom.com/register?flow=<new>，该 flow GET 返回 ui.messages=[{"id":1052,"text":"generic-user-data-missing"}]；约 30 组变体（traits.birthdate/birthday/context/geo/cookie/UA/XFF/邮箱域/用户名、form vs JSON、API flow）全部同质。auth.fandom.com/api/captcha-request 实测 403 cf-mitigated:challenge。
- **tags**: fandom,kratos,hydra,oauth,cloudflare,negative,fanatical
- **created_at**: 2026-11-12T01:54:22.609Z
- **engine**: services.fandom.com

## 描述

已证否路线：想通过 Fandom SSO 拿 fanatical atok 时，纯 HTTP/API 建 Fandom 账号不可行。判据：错误 csrf → 303 auth/error，正确 csrf → 302 回 register?flow=… 且新 flow 带 1052，说明请求到达 Kratos 但被其后的 Fandom 自定义 hook 拒（非 schema 校验失败，缺字段是 node 级 "Property X is missing"）；API flow 的 ui.action 被 Envoy 重写成 browser 端点（JSON POST→400 品牌页，POST /self-service/registration/api→405）。负面情报：别再枚举注册 traits/context/geo/cookie 变体，别再试图用 /self-service/registration/api 提交。

## 用法

```
复用前先判断：若目标链路依赖 Fandom SSO → fanatical /api/auth/fandom/，此路线已证否，改走 headful 浏览器通关 auth.fandom.com CF 后走 UI 会话，或改用第三方 OIDC（需已授权的 Discord/Twitch 账号 cookie 或自有域名邮箱）。已抓到的静态参数可直接用：fanatical client_id=511097b2-be3f-4dd5-9452-69c1718ebed3，redirect_uri=https://www.fanatical.com/en/fandom-auth-return（注意 /en 段），Hydra authorize=services.fandom.com/oauth-public/oauth2/auth，token 端点需 client secret（裸 client_id+code → 401 invalid_client）。
```
