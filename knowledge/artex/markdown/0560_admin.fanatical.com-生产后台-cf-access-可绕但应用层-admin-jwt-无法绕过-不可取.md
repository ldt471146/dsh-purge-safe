# admin.fanatical.com 生产后台：CF Access 可绕但应用层 admin JWT 无法绕过（不可取得会话/数据，负面情报）

- **code**: admin.fanatical.com-生产后台-cf-access-可绕但应用层-admin-jwt-无法绕过-不可取
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku + Cloudflare Zero Trust Access + AngularJS admin (fan-api-admin)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 15:3x-15:4x UTC 本机 Git Bash curl（--noproxy '*' --resolve 源站直连）实测：254 个 /api/admin/* 方法化目标中除 /api/admin/google-login(302)、/api/admin/google-login/set(400 "Invalid access token") 外一律 401 {"code":401,"error":"User not authenticated"}；8 种身份头变体(Cf-Access-Authenticated-User-Email/Cf-Access-Jwt-Assertion/X-Forwarded-User/Authorization Basic|Bearer/Cookie AdminAuth)全 401；/.env /.git/config /server.js 等返回 SPA(200/5251B)；X-Forwarded-Host 不改变 OAuth redirect_uri；当前构建 source map 444 源无任何密钥。结论：边缘绕过可利用上限=源码/接口面泄露，取不到会话。
- **tags**: fanatical,heroku,cloudflare-access,auth-bypass,negative,jwt,source-map
- **created_at**: 2026-11-11T15:45:13.168Z
- **engine**: https://admin.fanatical.com (Heroku 源站 13.248.131.213 / 15.197.152.254 / 35.71.150.51)

## 用法

```
用于判断「Heroku 源站直连摘 CF Access」在这类 AngularJS+服务端 JWT 后台上的天花板：摘边缘门≠拿到后台。深度利用时直接跳过下列已证否路径，别再手搓：① 边缘身份头(Cf-Access-*/X-Forwarded-User)伪造后端不认；② 敏感静态文件(SPA history fallback 恒 200/5251B)；③ Host 头改 OAuth redirect_uri(已固定 admin.fanatical.com，不反射)；④ 想从 source map 挖签名密钥/DB 串(0 命中)。唯一残留口是 /api/admin/google-login 预鉴权 OAuth，缺 state/无 hd，但 /set 只收 Google 真实签发的 code，无 Google 身份无法闭环。判据：现有 admin 接口 401 且 map 无密钥 → 该面到此为止。注意应用层用「方法+路径」路由，探测时须按源码里的真实 HTTP 方法发，否则拿 Express 404 误判。
```
