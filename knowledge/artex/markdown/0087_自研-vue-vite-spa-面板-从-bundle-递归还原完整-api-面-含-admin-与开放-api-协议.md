# 自研 Vue/Vite SPA 面板：从 bundle 递归还原完整 API 面（含 /admin 与开放 API 协议）

- **code**: 自研-vue-vite-spa-面板-从-bundle-递归还原完整-api-面-含-admin-与开放-api-协议
- **kind**: template
- **category**: frontend-reverse
- **severity**: low
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 449918-com 靶标 203.0.113.90「DNS智能解析管理」平台上实战：44 个 chunk 全量下载 → 提取 519 条调用 → 还原出 13 个 /admin/* 管理端接口、用户侧 /domains /records /apikeys /ns-servers /lines/tree 全套接口，并从 ApiDocs chunk 挖出内建的"兼容 DNSPod 协议开放 API"（http://<IP>:8080/api/v1/?c=…&uid=&api_key=，uid 由客户端自填）——该线索是本次唯一可能一步拿下控制面的入口（公网不可达，已转为内网第一优先待办）。
- **tags**: spa,vite,vue,recon,api-surface
- **created_at**: 2026-09-28T21:54:04.822Z
- **found_by**: vuln-scan

## 描述

对 Vite/Vue SPA 站点（压缩后的前端）做 API 面还原的通用流程：①拉首页取 /assets/index-*.js；②从 bundle 里用 __vite__mapDeps 列表递归下载全部 chunk；③用正则提取 `.get/.post/.put/.delete("路径")` 与 `url:"路径"` 得到完整接口清单（含 /admin/* 管理端）；④从 client chunk 里提取鉴权机制（axios baseURL / Authorization 头 / 401 跳转）；⑤从文档类 chunk（如 ApiDocs）里提取未在前端调用的"开放 API"定义。这套流程在自研系统上常能挖出 ffuf 字典扫不到的管理端接口与开放 API 协议。

## 用法

```
1) UA 必须伪装 Chrome（默认 UA 常被拦）：-A "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/203.0.113.48 Safari/537.36"\n2) curl -s -A "$UA" http://TARGET/ → 取 /assets/index-XXXX.js\n3) $t=Get-Content index.js -Raw; [regex]::Matches($t,'"assets/([A-Za-z0-9_\-\.]+\.js)"') 得到 chunk 名并逐个下载（间隔 400ms 防限流）\n4) 正则提取接口：'\\.(get|post|put|delete|patch)\\(\\s*["`'']([^"`''\\s,\\)]{2,90})["`'']'  与  'url\\s*:\\s*["`'']([^"`''\\s,\\)]{2,90})["`'']'\n5) 找 client chunk 里的 baseURL/interceptors（鉴权方式）；找 ApiDocs/Swagger 类 chunk 里的开放 API 表与认证参数
```
