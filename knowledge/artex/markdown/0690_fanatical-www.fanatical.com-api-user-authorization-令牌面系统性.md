# Fanatical www.fanatical.com /api/user/* Authorization 令牌面系统性证否（5,199 HS256 + JWT 头注入全矩阵恒 401，令牌疑为不透明服务端会话）

- **code**: fanatical-www.fanatical.com-api-user-authorization-令牌面系统性
- **kind**: poc
- **category**: auth-bypass
- **component**: Fanatical 主站 API（Heroku fan-api + Cloudflare Worker 前端）
- **source**: self
- **verified**: 1
- **verified_note**: 实测于 2026-11-11：ws15 源站直连与 www 边缘两通道，alg=none 全变体/HS256 5199 弱密钥字典(56.6s,0×429,0命中)/kid 穿越与外部 URL/jku x5u 指向 webhook.site sink(零回连，sink 自测对照正常)/jwk 内嵌(oct+自签RSA)/TLS 公钥 RS→HS 混淆 全部返回 401 "Invalid authorization header"；Cookie/query/body.atok 形态一律 "Missing authorization header"
- **tags**: fanatical,jwt,authorization,negative,opaque-session,api-user,hs256
- **created_at**: 2026-11-11T21:09:27.231Z
- **engine**: https://www.fanatical.com/api/user/orders

## 描述

后续 worker 判据与跳过清单：不要在 www.fanatical.com /api/user/* 重跑 JWT 伪造矩阵（含 alg=none、HS256 弱密钥字典、kid、jku/x5u、JWK 注入、RS→HS 公钥混淆）。若要继续该面，必须换维：先取得真实 token 样本（注册链/密码重置成功响应）再做 claim 结构与算法判定。

## 用法

```
1) 判据端点：GET /api/user/orders（ws15 直连 --noproxy --resolve ws15.fanatical.com:443:3.33.161.45 + Host: ws15.fanatical.com + X-Forwarded-Host: www.fanatical.com + 合法 UUIDv4 anonid）。
2) 错误语义二分：无 Authorization/空值 → 401 28B "Missing authorization header"；任意非空值 → 401 28B "Invalid authorization header"（content-type text/html, server: Heroku）。Cookie/query/body 形态恒 Missing。
3) 静态事实：前端 src/api/index.js `headers.append('Authorization', token)` 原值直传无 Bearer；state.auth 经 redux-persist 持久化在 localStorage['bsauth']；atok 是 login body 字段/localStorage['bsatok']，与 Authorization 无关；AdminLoginAs 需已登录后 GET /admin/login-as/{token} 且 200 响应整体展开为新身份。
4) 若要做真实 token 判定：拿 token 后看是否三段式 JWT（eyJ 开头）并 base64url 解 header/payload；无 JWKS 端点（/.well-known/jwks.json 等全 404）。
```
