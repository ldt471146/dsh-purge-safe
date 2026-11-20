# CN7/gameplat /api/config/promote/* 是推广跳转(catch-all 302)而非受门控的配置管理组——无 host/租户绕过面

- **code**: cn7-gameplat-api-config-promote-是推广跳转-catch-all-302-而非受门控
- **kind**: poc
- **category**: auth-bypass
- **component**: CN7 gameplat 5.3.0-RELEASE (Spring Boot + nginx)
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.16:10666 实测：/api/config/promote/{list,save,get,set,...任意段} 一律 302 Location: https://null/ 且 X-Custom-Check:true；非 GET→405；31 头+35 参数+44 Host 变体+SNI 全不改 Location；/api/config/promote/../../config/system→200 与直连同体（规范化逃逸但过不了鉴权过滤器）；真实推广管理 API 在 /api/agent/promote/{list,save}（XML Result，持 token 恒 code500 泛化错误）。
- **created_at**: 2026-10-10T05:30:15.802Z
- **found_by**: vuln-scan

## 描述

判死一条常见误判：CN7/gameplat 上 /api/config/promote/* 看似"受 host/租户解析门控的管理配置组"（302 + X-Custom-Check），实则是一个匹配 /api/config/promote/** 的无条件跳转处理器（推广链接跳转），不存在 list/save 配置接口，也没有可绕过的 host/租户判据。

## 用法

```
遇到 CN7/gameplat 的 /api/config/promote/* 时按此判死，勿再当门控配置面消耗预算：
1) 判据：任意子路径 GET/HEAD 一律 302，Location 为服务端按路由写死的推广域值——直连 /api 路由为 https://null/，经 nginx 坏 location ^/r→/api/config/promote 的 /r 路由恒为 https://<server_name>/（本案 203.0.113.16）；非 GET 返回 405。
2) 绕过判定：Location 不随任何请求输入变化（Host/X-Forwarded-Host/X-Custom-Check/tenantCode/tenantId/license/SNI/UA/协商头均无效），故无 host/租户 gating 绕过；它本就是可公开访问的跳转服务。
3) nginx ^/r 是裸前缀替换（/resources→/api/config/promoteesources，可作指纹）；/api/config/promote/..%2f..%2fX 的 `..` 被 nginx 规范化可逃逸到任意 /api/X，但不绕过全局鉴权过滤器（受保护目标仍 401），编码 .. / %2f / `;` 被 404/WAF 403 拦。
4) 真正要找推广/配置管理写面，应去 /api/agent/promote/{list,save}（XML <Result> 后端，代理鉴权）与 /api/config/{system,register,virtual_currency,...}（未授权可读）。
```
