#!/usr/bin/env bash
# Spring Boot / Springfox 静态壳未授权暴露探针（只读 GET，不含任何写操作）
# 用法: bash swagger_static_shell_probe.sh <host> <port> [http|https]
set -u
HOST="${1:?host}"; PORT="${2:?port}"; SCHEME="${3:-https}"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
BASE="$SCHEME://$HOST:$PORT"

get() {  # get <path> <outfile>  -> 打印 status / len / sha16 / content-type
  local p="$1" f="$2"
  curl -k -s -D "$f.h" -o "$f" --http1.1 --max-time 25 \
       -A "$UA" -H 'Accept: */*' -H 'Connection: close' "$BASE$p"
  local code len ct sha
  code=$(head -1 "$f.h" | awk '{print $2}')
  len=$(wc -c < "$f" | tr -d ' ')
  ct=$(grep -i '^content-type:' "$f.h" | tr -d '\r' | cut -d' ' -f2-)
  sha=$(sha256sum "$f" | cut -c1-16)
  printf '%-46s %s  %8sB  %s  %s\n' "$p" "${code:-ERR}" "$len" "$sha" "$ct"
}

echo "== [0] 404 兜底基线（必须先取，后面全靠它反证） =="
get "/__artex_nope__" base404.bin
BASE_LEN=$(wc -c < base404.bin | tr -d ' ')
BASE_SHA=$(sha256sum base404.bin | cut -c1-16)
echo "baseline: ${BASE_LEN}B sha16=${BASE_SHA}  body=$(head -c 200 base404.bin)"
echo

echo "== [1] swagger-ui 静态壳（命中=版本泄露成立） =="
get "/swagger-ui.html" swui.html
grep -oE 'springfox[^"'\'']*\.(css|js)\?v=[0-9][^"'\'']*' swui.html | sort -u
grep -oE '<title>[^<]*</title>' swui.html
echo

echo "== [2] webjars 静态资源（大体积 JS 证明由 Spring 后端直服） =="
VER=$(grep -oE 'springfox\.js\?v=[0-9.]+' swui.html | head -1 | cut -d= -f2)
VER="${VER:-2.9.2}"
get "/webjars/springfox-swagger-ui/springfox.js?v=$VER" springfox.js
echo

echo "== [3] 文档清单面：与基线同长同 sha ⇒ 被应用 404 处理器吞掉（未泄露） =="
for p in "/v2/api-docs" "/v2/api-docs?group=default" "/swagger-resources" \
         "/swagger-resources/configuration/security" "/swagger-resources/configuration/ui" \
         "/swagger-ui/index.html" "/doc.html"; do
  get "$p" "x_$(echo "$p" | tr '/?=&' '____').bin"
  L=$(wc -c < "x_$(echo "$p" | tr '/?=&' '____').bin" | tr -d ' ')
  S=$(sha256sum "x_$(echo "$p" | tr '/?=&' '____').bin" | cut -c1-16)
  if [ "$L" = "$BASE_LEN" ] && [ "$S" = "$BASE_SHA" ]; then
    echo "    ^^ 判定: SWALLOWED (等于基线) → 不成立"
  else
    echo "    ^^ 判定: 与基线不同 → 人工看内容，出现 paths/definitions 即 API 清单泄露"
  fi
  sleep 6
done

echo
echo "== [4] actuator / 管理面（同样用基线反证） =="
for p in "/actuator" "/actuator/env" "/actuator/heapdump" "/actuator/mappings" \
         "/actuator/jolokia" "/actuator/jolokia/list" "/druid/index.html" "/manager/html"; do
  get "$p" "a_$(echo "$p" | tr '/?' '__').bin"
  L=$(wc -c < "a_$(echo "$p" | tr '/?' '__').bin" | tr -d ' ')
  S=$(sha256sum "a_$(echo "$p" | tr '/?' '__').bin" | cut -c1-16)
  [ "$L" = "$BASE_LEN" ] && [ "$S" = "$BASE_SHA" ] \
    && echo "    ^^ 判定: SWALLOWED → 未暴露" \
    || echo "    ^^ 判定: 与基线不同 → 打开文件确认是否真 actuator/heapdump（heapdump 应为 MB 级）"
  sleep 6
done
