# CN7/gameplat 多租户博彩 SaaS 未授权跨租户配置泄露 (getPersonalCenter/getConfig)

- **code**: cn7-gameplat-多租户博彩-saas-未授权跨租户配置泄露-getpersonalcenter-getcon
- **kind**: http
- **category**: info-leak
- **component**: CN7 gameplat 5.3.0-RELEASE (Spring Boot + nginx/OpenResty)
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10 实测：GET /api/tenant/setting/getPersonalCenter 无任何鉴权(无 Authorization 头)返回 200 {"code":0,...} ，data[] 同时含 tenant="oottt" 与 tenant="kc375" 两个租户的 personal_center 行，含 updateBy=admin/yase 跨租户操作员；同站 /api/helpCenter/list 回显 createBy=admin555。/api/tenant/setting/getConfig 亦无鉴权。
- **tags**: multi-tenant,broken-tenant-isolation,unauthorized,CN7,gameplat,info-leak
- **created_at**: 2026-10-09T19:37:41.088Z
- **found_by**: work

## 描述

该产品为多租户 SaaS（每实例一个 tenant，window.CONFIG.tenant=<code>，license=<数字>，域名规律 <tenant>-<index>.<域>）。多个 /api/tenant/setting/* 与 /api/config/* 接口无需鉴权即可读；其中 getPersonalCenter 的查询未按调用方租户过滤，一次响应泄露多个租户的配置行与跨租户运营/管理员用户名，可用于枚举平台全部租户与运营身份。租户上下文参数(tenant/brandId)在 getScenario6/float/list 上被识别但无法指向其它租户行；无未授权写入口。

## 用法

```
1) 指纹：GET /api/version（无鉴权）→ 5.3.0-RELEASE/profile/build/license。2) 枚举租户：curl -sk "https://<host>:10666/api/tenant/setting/getPersonalCenter" 看 data[].tenant 与 updateBy。3) 读本租户配置：GET /api/tenant/setting/getConfig、/api/config/system、/api/tenant/domain/list(响应体 AES-OFB 加密，key=iv=6758725226829023)。4) 跨租户写不存在：/api/tenant/setting/{save,update,add,edit} 全 404。
```
