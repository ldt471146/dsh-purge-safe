# 前端资源投毒可行性判定法：客户端渲染资金字段 + 无 SRI/无 CSP/资源域写方法（含正确分级口径）

- **code**: 前端资源投毒可行性判定法-客户端渲染资金字段-无-sri-无-csp-资源域写方法-含正确分级口径
- **kind**: script
- **category**: frontend-reverse
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com 实测：首页 HTML（13140B）`integrity=` 出现 0 次（无 SRI）；/ 与 /assets/*.js 响应头无 Content-Security-Policy；JS/CSS 全为同源 /assets/*（Server: nginx、X-Debug-Static: asset、Cache-Control: public, max-age=604800）；二维码取值为 chunk 内 `value: order.toAddress||order.imgUrl, QRcode:!0`（客户端零校验）；资源域 example.com / example.com 回 `ACAO: https://example.com` + `Allow-Credentials: true` + `Allow-Methods: PUT, GET, POST, DELETE, HEAD, OPTIONS, PATCH`。按口径定级 medium（前置条件具备、资源写权限未取得）。
- **path**: pocs/前端资源投毒可行性判定法-客户端渲染资金字段-无-sri-无-csp-资源域写方法-含正确分级口径/poc.sh
- **tags**: 前端投毒,SRI,CSP,资源域,CORS,二维码,资金链路,可行性判定
- **created_at**: 2026-10-10T19:49:30.759Z
- **found_by**: vuln-scan

## 描述

资金类站点“改前端 JS = 全站收款二维码被换”路径的可行性判定流程：客户端渲染零校验证据 + SRI/CSP/资源来源/CORS 写方法/缓存的六项检查，并给出“前置条件具备 but 缺资源写权限”时的正确分级口径。

## 用法

```
按 1)→4) 顺序跑，各步骤均只需 1 个请求（浏览器 UA + 隧道）：
1) grep bundle 里的资金字段渲染点；2) curl 首页 HTML 与 /assets/*.js 头，判 SRI 与 CSP；
3) curl -X OPTIONS 资源域图片，判 CORS 写方法；4) 看静态资源 Cache-Control/X-Cache。
最后按“前置条件是否具备 + 是否已有资源写权限”两段式定级。
```

## 正文

```
# 目标
判定“改前端 JS 就能把全站访客的收款二维码/地址换掉”这条路是否具备前提条件（用于资金类站点投毒可行性评估）。

# 1) 先确认渲染层是否“客户端零校验”
在前端 bundle 里定位资金字段的渲染点（本例：二维码/地址）：
  grep -n "toAddress\|QRcode:!0\|value:.*toAddress" chunks/*.js
命中形如：
  {label:"C2C"===walletType?"支付宝收款码":"二维码", value: order.toAddress||order.imgUrl, QRcode:!0}
结论句式：**地址/二维码取值 100% 来自服务端订单对象，且渲染前无签名校验、无地址白名单** →
JS 一旦被替换，服务端“逐单随机地址”的防护即被绕过。

# 2) 完整性校验三项判定（各 1 个请求）
a) SRI：抓首页 HTML，统计 `integrity=` 出现次数
   curl.exe -s -k -A "<浏览器UA>" --proxy <隧道> -D hdr.txt -o example.com https://TARGET/
   PowerShell: ([regex]::Matches((Get-Content example.com -Raw),'integrity=')).Count
   0 → 无子资源完整性校验。
b) CSP：看 hdr.txt 是否有 `Content-Security-Policy`
   无 → 任何被注入/被替换的脚本都能执行；有则看 script-src 是否 'unsafe-inline'/通配。
c) 资源来源与指纹：列出 HTML 中全部 `<script src>`/`<link href>`
   全为同源 /assets/*（Vite 构建哈希文件名）→ 篡改点 = 站点静态根；若为第三方桶/CDN → 篡改点 = 该桶写权限。

# 3) 资源域 CORS 写方法判定（1 个 OPTIONS）
   curl.exe -s -k -I -A "<浏览器UA>" --proxy <隧道> -X OPTIONS https://<资源域>/<任意图片> \
     -H "Origin: https://TARGET" -H "Access-Control-Request-Method: PUT"
看是否回 `Access-Control-Allow-Origin: https://TARGET` + `Allow-Credentials: true` +
`Allow-Methods` 含 PUT/POST/DELETE/PATCH → 允许带凭据的跨域**写**方法（配合站内 XSS 或写接口即打通）。

# 4) 缓存层
看静态资源响应头 `Cache-Control`/`X-Cache`/`X-Debug-Static`
max-age 越大 → 篡改对老客户端生效越慢（本例 604800=7 天），评估时须写清。

# 结论模板
· 无 SRI + 无 CSP + 客户端零校验 + 资源同源 → **前置条件全部具备**；
· 此时 severity 取决于“资源写权限”是否取得：
  - 已能写 /assets 或替换 example.com 引用（上传落盘到站点根 / 静态目录写 / 备份还原）→ **critical（全站资金投毒）**；
  - 尚未取得 → 记 **medium**，把“缺什么写权限”写成明确卡点，不要写成已可利用。

```
