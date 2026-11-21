# 会员注册接口服务端校验缺失（空口令可注册并可登录、pwd1 不校验） @ thbac1dsua6v.gwtkx5hgk5.xyz

- **code**: 会员注册接口服务端校验缺失-空口令可注册并可登录-pwd1-不校验-thbac1dsua6v.gwtkx5hgk5
- **kind**: poc
- **category**: weak-password
- **severity**: low
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: ARTEX 已确认（finding#1323 / 任务#648）：/Home/Index/register 无任何服务端口令校验：不传 pwd 也注册成功并以 md5('') 入库，可用空口令直接登录；pwd/pwd1 不匹配同样注册成功（pwd1 前端字段根本不提交）。攻击者可无成本批量创建空口令会员账号。
- **path**: pocs/会员注册接口服务端校验缺失-空口令可注册并可登录-pwd1-不校验-thbac1dsua6v.gwtkx5hgk5/poc.md
- **tags**: low,weak-password
- **created_at**: 2026-11-09T19:09:49.568Z
- **engine**: thbac1dsua6v.gwtkx5hgk5.xyz
- **found_by**: work#5

## 描述

/Home/Index/register 无任何服务端口令校验：不传 pwd 也注册成功并以 md5('') 入库，可用空口令直接登录；pwd/pwd1 不匹配同样注册成功（pwd1 前端字段根本不提交）。攻击者可无成本批量创建空口令会员账号。

## 正文

```
# /Home/Index/register 服务端口令校验缺失 —— 实际利用结论

## 一、漏洞复现（成立）
直连源站 `45.151.135.176` + `Host: usertobbs.thb.mysqbbthisgoodsfor33333user.top`。不传 `pwd` 注册 → `200 {"userid":"1263#d41d8cd98f00b204e9800998ecf8427e",...,"ok":1,"ms":"注册成功"}`；`pwd=` 空口令登录 → `{"ok":1,"ms":"登录成功"}` + PHPSESSID。`md5('')` 与回显哈希一致，证明空口令入库。`pwd1` 服务端不校验。

## 二、实际利用尝试与边界（全部实测，均否定）
1. **SQL 注入**：注册 `name` 含引号/布尔/`UNION`/`SLEEP` 全部 `200/142B` 固定文案（字符校验拒绝，非 SQL 结果）；字符集仅 `[A-Za-z0-9_]`；登录注入统一 100B 报错；`other` 时间盲注 baseline 816ms vs SLEEP(3) 1065/1630ms 无延迟。
2. **mass-assignment**：balance/status/isadmin/level/uid 等 12 字段全部被忽略，登录余额恒 0。
3. **空口令接管存量账号**：admin/admin1/root/administrator/webmaster/kefu/service/guanli/the/thb/test 共 11 个存在用户名空口令登录全部失败；`/Index/user?uid=N` 参数无效，无法枚举用户。
4. **会员会话横向**：`/Home/Index/user` 200/21312B 只读；`a=user` 200 vs `a=nonexistzz` 404 证明路由生效，而 `a=setinfo/upimg/upload/order/pay/...` 共 14 个动作全 404/146，无上传/写文件面；会员 Cookie 访问 `/Admin/*` 全部 302 回登录页。
5. **喂模板 RCE 链（kb#383）**：注册名不在 get_html1 烘焙源 `/List/index`（295236B，0 命中）；`other` 标记在 user/list/bbs 三页 0 命中，且用户名禁元字符 → 无法闭合「admin 哈希→edit_cont 写 title→get_html1→模板编译」。

## 三、影响判定
真实影响仅限无成本批量建号、空口令会员账号、绕过前端 pwd1 校验；未取得管理权限、文件写入、命令执行或存量账号接管。相对「脚本驻留入口」目标不可利用。

## 四、修复建议
服务端强制 pwd 非空+强度校验与 pwd1 比对；参数化查询 + 字符白名单；注册/登录加验证码与频控；排查重置 `pwd=md5('')` 的存量账号。
```
