# CN7/gameplat 5.3.0-RELEASE 无公开版本级 Nday + 同产品实例全为静态 CDN 克隆 + nginx ^/api 前缀路由测绘 — 版本指纹 Nday 匹配判死清单

- **code**: cn7-gameplat-5.3.0-无公开版本级-nday-同产品实例静态克隆-nginx-api-前缀路由
- **kind**: poc
- **category**: info-leak
- **component**: CN7 CMS / gameplat 5.3.0-RELEASE (Spring Boot + nginx + OpenResty /ecb 网关)
- **severity**: low
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-10 在 https://203.0.113.16:10666 实测：① /api/version 无鉴权返回 5.3.0-RELEASE/builder 2026-10-06/profile prod/license 375；② /api/tool/gen、/api/system/user/list、/api/monitor/server、/api/v2/api-docs、/api/druid/websession.html、/api/actuator/jolokia/list 全部 401；/install /setup /admin /manage /backup.zip /db.sql /.git/config /actuator/* 全部 SPA 兜底 92709B 或 WAF 403；③ /report→404 path=/api/config/promoteeport 证明 nginx ^/r*→/api/config/promote* 映射；/apidoc、/api2/version→后端 401 证明 ^/api(正则无边界)前缀路由；④ 同品牌域 0255501.vip→203.0.113.137 对 /api/version 返回 S3 AccessDenied，为静态 CDN 克隆；⑤ 多租户 getConfig/config 传 tenantCode/id/header 无法横向读取 kc528-1 等。无版本级 RCE/后台接管。
- **tags**: CN7,gameplat,博彩CMS,版本指纹,Nday,nignx路由,多租户
- **created_at**: 2026-10-09T18:22:26.084Z

## 描述

给同族 CN7/gameplat 靶标做「产品+版本级 Nday」时的判死清单与省时口径：该产品闭源私有，互联网无 CVE/漏洞库条目，公开可枚举的同产品实例均为静态 CDN 克隆（无后端），版本号驱动的 Nday 路线在本类目标上无产出。

## 用法

```
遇到 CN7/gameplat 靶标要走「版本 Nday」时按此判死，勿重复消耗：
1) 先取指纹：GET /api/version（无鉴权）→ 5.3.0-RELEASE；前端 Next.js 静态 + webpack(.1787221950252.*)，后端 Spring Boot。
2) 公开源：GitHub 搜 "gameplat cms"=0 仓库；搜索引擎无 CVE；KB 仅有 /api/img/upload(未授权上传，非 RCE) 与 /jumpto/img(SSRF，内网不可达)。故不存在公开版本号对应 CVE，不必查 CVE 库。
3) 同产品实例：FOFA body="gameplat" 多为 gameplay 误匹配；同品牌域(0255501/60-64.vip 等)多为静态 S3/CDN(203.0.113.137 → /api/* 返回 S3 AccessDenied)，无活后端，勿去直连这些“兄弟站”找 Nday。
4) 目标框架级 Nday 一次性判定：/api/{tool/gen,system/user/list,monitor/server,v2/api-docs,druid/*,actuator/*} → 统一 401（全局鉴权过滤器）；非 /api 的 install/setup/admin/backup/db.sql/.git → SPA 兜底或 WAF 403。
5) nginx 路由口径（省时关键）：`^/api`（正则【无右边界】）前缀一律路由到后端并由全局过滤器 401，所以 /apidoc、/apidoc.json、/api2/version 这类“貌似非 /api”的路径其实都命中后端、非未授权面；`^/r*` 被坏 regex 映射到 /api/config/promote*（/report→404 path=/api/config/promoteeport；/api/config/promote/list→302 坏跳转），亦不可利用。
6) 多租户隔离：/api/tenant/setting/getConfig、/api/config/system 的租户由 Host 绑定，传 tenantCode/code/id/tenant/name 参数或 X-Tenant 头均无效，无横向 IDOR。
结论：版本级 Nday 无路；转向 VPN 内网或凭据侧。
```
