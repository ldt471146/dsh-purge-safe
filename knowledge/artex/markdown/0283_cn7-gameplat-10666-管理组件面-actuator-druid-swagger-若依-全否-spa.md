# CN7/gameplat 10666 管理组件面（actuator/druid/swagger/若依）全否 — SPA 兜底 + Spring 全局鉴权过滤器 + 版本泄露 5.3.0-RELEASE

- **code**: cn7-gameplat-10666-管理组件面-actuator-druid-swagger-若依-全否-spa
- **kind**: poc
- **category**: info-leak
- **component**: CN7 CMS / gameplat 5.3.0-RELEASE (Spring Boot + nginx + OpenResty /ecb 网关)
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-09 在 https://203.0.113.16:10666 实测全否：GET /、/actuator、/actuator/env、/actuator/heapdump、/actuator/jolokia/list、/druid/example.com、/swagger-ui/example.com、/v2/api-docs、/tool/gen、/common/download、/jolokia/list、/heapdump 全为 200+92709B text/html(SPA 兜底)；/api/actuator/env、/api/druid/example.com 等 401 {\"code\":401,\"message\":\"您的登录会话已过期\"}(Spring 全局鉴权过滤器)。方法变换/路径归一化/头伪造(X-Custom-Check/X-Forwarded-*/Xign)/Host 伪造(502) 全无效。经 /ecb/{AES-OFB-hex}(key=iv=6758725226829023) 网关打 api/actuator/env 仍 401、api/../actuator/env=404、http://169.254.169.254/=404(无 SSRF)。端口面仅 80/10666。唯一增量：GET /api/version 无鉴权泄露 <b>version:5.3.0-RELEASE</b>/builder 2026-10-06/profile prod/license 375；POST /api/tenant/setting/getConfig 无鉴权。管理后台应用(/static/<admin|manage|...>/ 全 SPA 壳)、vhost(admin.* 502)、管理 API(/api/<ns>/* 全 401 或 404) 均无未授权入口。
- **created_at**: 2026-10-09T16:05:07.412Z

## 用法

```
遇到同族 CN7/gameplat 靶标时的判据与省时清单：
1) 管理组件面基本为死路：非 /api 路径一律被 SPA 兜底吞掉(200 + 92709B example.com)，/api/* 由 Spring 全局鉴权过滤器统一 401 {\"code\":401,...}，二者都不代表真实组件暴露。不要再逐条盲打 actuator/druid/swagger/tool/gen，一次性判定即可。
2) 快速指纹三连：GET /api/version(拿版本 5.3.0-RELEASE)；GET /api/config/system(未授权平台配置，含 upgradeUrl/customerUrl 等真实域名)；POST /api/tenant/setting/getConfig body={} (未授权全量设置)。
3) 加密通道 /ecb/{AES-128-OFB hex, key=iv=6758725226829023} 只路由 api/*；非 api 路径=openresty 404，无路径穿越、无 SSRF。
4) Host 伪造一律 502(nginx 严格 server_name)，无 vhost 直达管理面。
5) /api/config/promote/list 是真实内部运营路由(经 nginx 坏 location /r* 映射)但 302→https://null/ 坏跳转，不可利用。
6) 本机环境若设了 ALL_PROXY/HTTP(S)_PROXY=127.0.0.1:8788，跟随跳转会 \"Tunnel failed 502\"，直连请 trust_env=False 或 --noproxy。
```
