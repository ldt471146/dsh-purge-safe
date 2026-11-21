# PHPWind 7.3.2 实测判据集：prosign 写入姿势+引号实体化、admincheck 无自助入口、mode.php?m=o 各 q 可用性、载体长度硬上限

- **code**: phpwind-7.3.2-实测判据集-prosign-写入姿势-引号实体化-admincheck-无自助入口-mode.php-m-o-各-q-可用性-载体长
- **kind**: template
- **category**: recon
- **component**: PHPWind 7.3.2
- **language**: http
- **source**: self
- **verified**: 1
- **verified_note**: 全部在 example.com（PHPWind 7.3.2 / GBK / PHP 5.5.38 / nginx 1.30.4 / 宝塔）带 admin(uid=1) 登录态实测：prosign 写入回「操作完成」并回读确认实体化规律；admincheck 提示页 post-admin.html 全文通读；mode.php 各 m/q 值逐一请求并记录响应大小与中文回显；注册 13B/18B 用户名均回「注册名长度错误」；passport_client.php 回「系统没有开启通行证功能」。
- **tags**: phpwind,7.3.2,prosign,admincheck,mode.php,判据,负面情报,站群复用
- **created_at**: 2026-10-06T11:46:19.042Z
- **found_by**: exploit

## 描述

PHPWind 7.3.2 实测判据集（同站群/同版本复用）：① prosign 个性签名写入的正确姿势与实体化结论；② admincheck 无前台自助入口；③ mode.php?m=o 应用中心各 q 值可用性；④ 用户名/date_f 双载体长度硬上限。用于避免同版本靶标重复投入。

## 用法

```
1) prosign 写入：POST /bbs/profile.php?action=modify 必须带 oldpwd=<原密码>，否则回「和安全问题需要输入原密码验证」；带对后回「操作完成」。字段全集：verify + step=2 + oldpwd + progender/proyear/promonth/proday/prosign/proemail/proicon/facetype。2) 实体化判据：写 `[b]probe[/b]<\>'")` 回读为 `[b]probe[/b]&lt;\&gt;&#39;&quot;)` —— 引号尖括号全实体化、括号与 [b] 保留 ⇒ 依赖引号断引的 /e 路线在 prosign 上不成立（白盒说 CheckVar 会把 )→&#41; 与实测不符，) 未转义）。3) admincheck：被拦提示页只有一句提示+「返回」按钮，无任何验证链接/表单；admincheck() 是版主列表匹配函数（global.php:535），不是密码验证，无空值/默认口令可绕。4) mode.php：只有 m=o 合法（m=bbs/area/cms 全「非法操作」）；m=o 下 q=photos「相册应用已关闭」、q=share「分享应用已关闭」、q=write&do=post 被 admincheck 挡、q=home/article/board/browse/diary/user 可看；mode/o/* 文件全 9 字节 Forbidden 守卫。5) 长度硬上限：用户名 12 字节（注册 13B/18B 均回「注册名长度错误」，表单 maxlength=12 与之一致）、date_f 服务端截断 15 字节。6) passport_client.php 未开启（「系统没有开启通行证功能」）。
```
