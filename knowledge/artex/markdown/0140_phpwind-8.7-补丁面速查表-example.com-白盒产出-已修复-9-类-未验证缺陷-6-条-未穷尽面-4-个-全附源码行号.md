# phpwind 8.7 补丁面速查表（example.com 白盒产出）：已修复 9 类 + 未验证缺陷 6 条 + 未穷尽面 4 个（全附源码行号）

- **code**: phpwind-8.7-补丁面速查表-example.com-白盒产出-已修复-9-类-未验证缺陷-6-条-未穷尽面-4-个-全附源码行号
- **kind**: template
- **category**: app-audit
- **component**: phpwind 8.7 (含 example.com/20110913 与 8.7beta 同源分支)
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 验证方式 = **对目标实拉源码逐行审计**（runs/hklot/pw-src，3881 文件，与目标 898/1852 双实例同源）+ **环境实测**（GBK 字符集经 GET / 响应 `<meta charset="gbk" />` 确认；install.php 经 curl 实测 404；upupw.php/upupw/ 经 curl 实测双实例均 404）。\n\n**明确区分**：本速查表 A 区（已修复）与 B 区（白名单）为**源码级确证**；C 区 6 条为**代码级确认的缺陷但未在目标上取得利用**（每条已注明前置条件）；D 区 4 个面为**未穷尽的方向**，不是已确认漏洞。\n\n本轮**未在目标上获得任何权限或得分**，本条目沉淀的是判断依据与搜索面，不得据此声称目标存在可利用漏洞。
- **path**: pocs/phpwind-8.7-补丁面速查表-hk000999.com-白盒产出-已修复-9-类-未验证缺陷-6-条-未穷尽面-4-个-全附源码行号/poc.php
- **tags**: phpwind,8.7,补丁面,白盒审计,速查表,GBK,宽字节,addslashes,复用,同圈子,源码行号
- **created_at**: 2026-09-30T16:43:45.265Z
- **found_by**: vuln-scan

## 描述

phpwind 8.7 补丁面速查表：已修复 9 类 / LFI 白名单点 / 6 条未验证代码缺陷 / 4 个高价值未穷尽面（含源码行号），供同圈子同版本站点复用

## 正文

```
## phpwind 8.7 白盒速查表（example.com 2026-09-30 全量审计产出）

源码基线：`runs/hklot/pw-src/upload/`（3881 文件，从目标实拉，**与目标 898/1852 双实例同源**）
环境实测：PHP 5.3.29 / nginx / **GBK**（`GET /` 正文 `<meta charset="gbk" />`）

---

### A. 已被官方修复 —— 不要再试（每条附源码行号）

| 原手法 | 源码现状 | 行号 |
|---|---|---|
| 前台 SQL 注入 `actions/ajax/leaveword.php` | 原拼接语句被注释，改用占位符绑定 | `leaveword.php:80`(注释) / `:81`(pwQuery::buildClause) |
| 头像上传写马 `example.com?action=uploadicon&step=2&filename=x.php` | 扩展名白名单 + 落盘名硬编码 + 内容校验 | `uploadicon.php:26,30-38,48,59` |
| BBCode `[code]` 的 `preg_replace /e` RCE | 该语句已随 `/e` 全面清除（全站 `rg '/[a-z]{1,4}e[a-z]{0,3}["\']'` 无命中） | — |
| `include/require` 型 LFI（122 处） | 每处都有 `in_array` 白名单或 `file_exists` 前置 | 见下 B 区 |
| `install.php` 重装写配置链 | **目标上该文件返回 404（不存在）**，链断 | 目标实测 |
| `checkpass1()` 本地口令校验（可绕 yz） | **死代码，全站无调用点** | `checkpass.php:160-249` |
| `apps.php` 的 `preg_replace(...,'/eis')` | `([0-9]+)` 锚定，eval 内容只能是 `upload('<数字>')` | `apps.php:86` |
| `mawhole.php` / `getinfo` 的 `eval("...TOP$topped")` | `$topped`/`$type` 经 `intval` 或 `in_array(1,2,3)` | `mawhole.php:921,992,1023`；`getinfo.class.php:293-294,304` |
| XFF 绕过后台锁定（WOOYUN-2014-080327） | `pwGetIp()` 的 `$db_xforwardip=0`，站不信任 XFF | `require/common.php:59-73` |
| phpwind 后门名 / 备份名（46 个） | 双实例全无（黑盒阶段已排除） | — |

### B. LFI 白名单点（`S::escapePath` 挡 `..`/`://`/`\0` 但放绝对路径，唯白名单救场）

`u.php:15`、`m/example.com:5-8`、`thread.php:25`、`apps.php:17`、`example.com:12/46`、`pweditor.php:14`、`pw_example.com:138`、`profile.php:30`、`example.com:72`
—— **`S::escapePath` 本身（`require/security.php:185-193`）只挡 `://`、`\0`、`..`，放行绝对路径；攻破的钥匙是"找一个没有 in_array/file_exists 前置的 include 点"，本轮未找到，但这是值得延续的搜索面。**

### C. 仍成立但需权限/未验证的代码缺陷（本轮新增）

1. **弱转义原语**：`S::sqlEscape`(`security.php:303`)、`S::slashes`(`:257-267`)、`UC::escape`(`uc_client/class_core.php:105-117`) 全用 **`addslashes`**，非 `mysql_real_escape_string` ⇒ **GBK 宽字节注入原语成立**。当前实际防线只有 `S::escapeStr`(`security.php:227-234`，把 `'`→`&#39;`)。**搜索方向：找不经 `S::gp`/`InitGP` 而直接进 SQL 的 `$_POST`/`$_GET`**（候选：`apps.php:172,185`、`sendpwd.php:17`）。
2. **`questcode()` 第二因子可绕**：`checkpass.php:250-253`，`$question` 为空返回 `''`，与未设安全问题账号的 `safecv=''` 恒等 ⇒ 传空 question/answer 即过。影响 `sendpwd.php:37-43`、`login.php:111`、`info_safe.php:102`、`info_binding.php:35`。**仍需正确口令，不能单独登录**。
3. **手机版校验分叉**：`m/include/wap_mod.php:151` 只挡 `yz>2`，主站 `checkpass.php:105` 挡 `yz>1` ⇒ 手机版可放行未激活账号，但主站 `global.php:462` 复核同样挡 `yz>1`，**无法提升到主站**。
4. **`updatecache_sy()` 文件名可控写入**：`admin/cache.php:687` `pwCache::setData(D_P."data/style/$name.php", ...)`，`$name` 来自 `pw_example.com?action=setstyle` 的 `setskin`；`S::escapePath` **不拦 `/`**。写入内容由 DB 行 `pw_var_export()` 拼接 ⇒ **内容不可控，非 RCE**；需 `groupid` 3/4 且 `rightset['setstyles']`。
5. **游客可达反序列化（不可提权）**：`actions/ajax/bubble.php:11-14` `unserialize(stripslashes(GetCookie('bubble')))`，`bubble` 在 `pw_example.com:32` 游客白名单。**但全站仅 1 个 `__destruct`**（`lib/framework/errors.class.php:52`，受 `SHOWLOG` 约束只写 `data/error.log`），**零 `__wakeup`** ⇒ **无 gadget 链，不足以 RCE**。
6. **`admin/level.php:596`** `eval("\$html = \"".addcslashes($html,'"')."\";")` —— `addcslashes` 只转 `"`，`\` 未转 ⇒ 输入 `\"` 可构造 `\\"; system(...); //` 逃逸。**`$html` 来源与可控性本轮未跟完，列为待验证。**

### D. 高价值未穷尽面（建议后续投入）

1. **`pw_api.php`**（robots 禁用）：`require_once S::escapePath(R_P."require/db_$database.php")`（`:23`），`$database` 未定义 ⇒ 直接访问应 Fatal；**若配置中有 `database` 变量则可 LFI**。真正价值在 `api/class_base.php:98` `unserialize($request['params'])` + `:118` `call_user_func_array` —— **任意 API 方法调用**，唯门槛是 `$sig = md5($arg.$apikey)`，`$apikey=$db_siteownerid`（app）或 `$uc_key`（uc）。**若能拿到 `db_siteownerid` 即通吃**。
2. **`apps.php?q=updata`**：**无登录检查**（仅需 `cid`/`tid`），读取任意 tid 帖子内容并 POST 到 `http://app.phpwind.net/pw_app.php`，`Showmsg($backdata)` 回显外部响应 ⇒ 未授权触达 + 外部响应回显。
3. **`require/updateset.php:4-34` 的 `write_config()`**：`foreach($newconfig as $k=>$v) ${$k}=$v;` + `\$dbhost='$dbhost';` **零转义拼接写入 `data/sql_config.php`**（每次请求必 require）⇒ **一旦找到网络可达的调用点即持久化 RCE**。当前调用点：`install.php:222`（404，不可用）、`admin/advanced.php:138`、`admin/manager.php:68,127,169`（需后台）。**这是本站最值得继续找入口的一条链。**
4. **`require/bbscode.php` 的 `/e`**：父指挥提示 `preg_replace("/\[code\](.+)?\[\/code\]/eisU","phpcode('\\1')")` 卡在需可发帖账号 —— 本轮 `rg` 未命中该串，**建议以实际文件行号为准确认后再投入**。

```
