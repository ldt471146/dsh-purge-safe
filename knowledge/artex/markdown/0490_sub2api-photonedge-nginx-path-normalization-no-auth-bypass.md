# Photon-Edge CDN + nginx/gin 的路径-协议归一化差异不构成 sub2api admin 鉴权绕过（50+ 变体全阴性；%2f 编码前缀可绕字面匹配）

- **code**: sub2api-photonedge-nginx-path-normalization-no-auth-bypass
- **kind**: poc
- **category**: auth-bypass
- **component**: sub2api / Photon-Edge CDN / nginx / gin
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: www.dahurj999.top：curl --path-as-is 与 python 裸 socket 双工具、50+ 变体 × http/https 全部停在 adminAuth 之外（401 58B UNAUTHORIZED / 50B INVALID_TOKEN / 18B gin 404 / SPA 200 HTML），0 例 200 JSON 或 403 Admin access required；%00 回 nginx 400 页，证明源站 nginx 透传原始路径、Photon-Edge 不改写。
- **path**: pocs/sub2api-photonedge-nginx-path-normalization-no-auth-bypass/poc.txt
- **tags**: sub2api,photon-edge,nginx,gin,path-normalization,auth-bypass,negative,server-timing
- **created_at**: 2026-11-02T05:42:35.696Z
- **engine**: https://www.dahurj999.top

## 描述

用途：判断“CDN 与源站路径归一化差”能否让未认证请求直达 admin handler。结论：不能（本栈），但记录三条可复用判据。① 响应族三分法：58B {"code":"UNAUTHORIZED"} = 无凭据分支；加 bogus Bearer 得 50B INVALID_TOKEN、bogus x-api-key 得 62B INVALID_ADMIN_KEY = 证明真的进了 adminAuth（防 WAF 伪造 401）；18B "404 page not found" = gin 未匹配；200 HTML = 落到 SPA。② 该栈只在“路径末尾单一点段”归一化（/. 与 %2e → 401），中间 /./ 、//、/../、%2e%2e 都不归一化（→404/SPA）；编码斜杠 %2f 会被解码后路由（/api%2fv1%2fadmin%2fbackups → 401），可作为“绕开按字面 /api/v1/admin 匹配的前置规则”的原语。③ 头类 X-Original-URL / X-Rewrite-URL / X-Forwarded-Prefix / X-Forwarded-Uri / X-Middleware-Subrequest / X-HTTP-Method-Override 全部不生效；Server-Timing 仅出现在 Access-Control-Expose-Headers 声明里，实测从不回，不能用于判断鉴权阶段。设置 Host: 127.0.0.1 → nginx 默认站 404。

## 用法

```
先做三态判别（58/50/62B + 18B 404 + 200 html），再决定是否值得打归一化；若要绕 WAF 字面规则用 %2f 编码前缀而不是 // 或 /./。
```

## 正文

```
# 阴性结论（勿重复）
50+ 变体全部 401/404/301/200-HTML/400，无 200 JSON、无 403 Admin access required。
- 归一化掉（→401，仍走 adminAuth）：仅尾 `/.` 与尾 `/%2e`
- 不归一化（→gin 404）：`//`（段内）、`/./`（中间）、`/../`、`%2e%2e`、尾分号 `;x=1`、`.json`、`%20`、`%09`
- 落 SPA 200 HTML：前导 `//`、`/%2f`、`/%2f%2f`、`/./` 前缀、全大写 `/API/V1/ADMIN/BACKUPS`、双编码 `/%2561pi`
- 400：`%00`（nginx 页，暴露源站 nginx）

# 可用原语
`%2f` 编码整条前缀 `/api%2fv1%2fadmin%2fbackups` 仍命中同一 handler（401），可绕按字面前缀匹配的 WAF 规则。

# 判据
无凭据 58B UNAUTHORIZED；bogus Bearer 50B INVALID_TOKEN；bogus x-api-key 62B INVALID_ADMIN_KEY；18B 404 page not found=未匹配；200 text/html=SPA（Go 渲染版 3.4KB 带 __APP_CONFIG__，nginx 静态版 798B 带 Last-Modified）。
```
