# webman+nginx 站群：/app/admin/** 被 nginx 静态 location 遮蔽——路径/头/方法/差分编码/vhost 全不可绕（阴性）

- **code**: webman-nginx-站群-app-admin-被-nginx-静态-location-遮蔽-路径-头-方
- **kind**: markdown
- **category**: unauthorized
- **component**: nginx webman PearAdmin
- **severity**: info
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 443 实测：pear.css=200/1067B(静态文件)、/app/admin/component/=403/564B(目录存在)、/app/admin/api/game-category/index=404/564B；而 /api/、/app/、/app/api/ 均代理到 webman(378/JSON)。30+ 路径变体(含 %2e/%252e/%2f/大小写/尾点/分号/反斜杠/矩阵段)、X-Original-URL/X-Rewrite-URL/X-Forwarded-Prefix 等头、POST/PUT/OPTIONS/HEAD/TRACE、HTTP/2、绝对URI、overlong UTF-8(%c0%af)/%u002f/CRLF/%09 全部无法到达 webman 的 /app/admin/api 路由；打破前缀(反斜杠/分号/%252e)可到 webman 但路由未命中(378)。
- **tags**: nginx,webman,vhost-admin,path-bypass,negative,static-location
- **created_at**: 2026-10-13T11:04:49.546Z

## 描述

当 nginx 同时配了 `location /app/ {proxy_pass webman}` 和更长的静态 `location /app/admin/ {root public}`（后者遮蔽前者），/app/admin/** 会走静态文件：真实文件 200、目录 403、缺失文件 404/564B。这类 404 不是可绕的 location 级 deny/return 404 过滤器（否则同前缀下真实静态文件也会 404），因此路径规范化/编码/头/方法一律无效。判据：同前缀真实静态文件仍是 200 + 目录仍返回 403 → 静态服务语义，非封锁。复活后台面应改用直连 webman 源站端口（默认 8787）绕过 nginx，而非路径绕过。

## 用法

```
复核命令（判定静态 vs 封锁）：
curl -sS -k --path-as-is --resolve <Host>:443:<IP> https://<Host>/app/admin/component/pear/css/pear.css   # 200/1067 → 静态
curl -sS -k --path-as-is --resolve <Host>:443:<IP> https://<Host>/app/admin/component/                       # 403/564 → 目录存在
curl -sS -k --path-as-is --resolve <Host>:443:<IP> https://<Host>/app/admin/api/<route>                       # 404/564 → 静态未命中
对照：/api/agent/commissionRates → 200/481(webman JSON) 说明 webman 活着、只是该前缀被静态遮蔽。
```
