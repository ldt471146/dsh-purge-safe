# PHPWind 写 .php 缓存文件判死边界速查表（含 bank_sort 例外与字段长度表）

- **code**: phpwind-写-.php-缓存文件判死边界速查表-含-bank_sort-例外与字段长度表
- **kind**: payload
- **category**: app-audit
- **component**: PHPWind 7.3.2 / 7.5SP3
- **severity**: high
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 PHPWind 7.3.2 源码（runs/pw-admin-sinks/utf8/）逐条实测确认：97 处「目标 .php + 内容含变量」写点中 96 处判死（转义 30 / key_cv 13 / db_cv-str_replace 4 / 其余 pw_var_export 12 / die 前缀 10 / 整数常量 20 / 注释块内），唯一例外为 hack/bank/example.com:74 的 bank_sort（与既有结论一致）。字段长度取自 runs/pw-src-732/pw75sp3_utf8/lang/install_wind.sql 的 CREATE TABLE 原文。零发包。
- **path**: pocs/phpwind-写-.php-缓存文件判死边界速查表-含-bank_sort-例外与字段长度表/phpwind-write-sink-deadlist.md
- **tags**: phpwind,白盒审计,判死边界,缓存写点,bank_sort,字段长度
- **created_at**: 2026-10-06T22:25:20.459Z
- **found_by**: vuln-scan

## 描述

PHPWind 7.3.2 全部「写 .php 缓存文件」写点的判死边界速查：转义函数清单、手工转义位置、die 前缀、整数数据源、注释块内的死代码、缓存目录 include 密度、唯一例外 bank_sort 及其 15 字节瓶颈、关键字段长度表。后人重扫前先查此表，避免重复劳动。

## 用法

```
重扫 PHPWind 写 .php 文件类 sink 前先读此表；判死项直接跳过，只对表中未列出的写点做人工分析。表内「唯一真例外」hack/bank/example.com:74 为已知 RCE，攻击面在 pw_members.username 的 15 字节长度限制。
```

## 正文

```
# PHPWind 7.3.2「写 .php 缓存文件」判死边界速查表（实测确认）

## 完整转义（凡用它的写点直接跳过）
- `pw_var_export`   require/common.php:456
  = `"'".str_replace(array("\\","'"),array("\\\\","\'"),$input)."'"`
  → 单引号串完整转义。30/97 处写点靠它封死。
- `db_cv`           admin/cache.php:1114
  = `str_replace(array("\\","'"),array("\\\\","\'"),$value)`
  → 注意：它【只转义 \ 和 '】，不转义 $ { }。若外层是【双引号串】则仍危险（bank_sort 正是此型）。
- `key_cv`          admin/cache.php:1124 = `preg_replace('/[^\d\w\_]/is','',$key)` → 键名只留 \d\w_
- `Char_cv`         require/common.php:646 → ' → &#39;  " → &quot;  < → &lt;
  → 但后台（P_W=='admincp'）的 CheckVar 不做任何替换

## 变量赋值链上常见的手工转义（要逐个回溯，别只看写点那一行）
- `admin/cache.php:60`  $fname = str_replace(array("\\","'",'<','>'),array("\\\\","\\'",'&lt;','&gt;'), strip_tags($forums['name']))
  → 保护 forumcache.php 的 $forumcache（行 152）与 $cmscache
- `admin/cache.php:340` 写入前对 $forumcache 再做一次 str_replace 转义
- `admin/app.php:420` / `api/class_Other.php:172`  $class['name'] 的 ' " → &#39; &quot;

## 落点确定但内容不可执行
- `<?php die;?>` 前缀：admin_cache.php、dblog.php、ip_cache.php、set_cache.php、online.php/guest.php、
  medals_list.php —— include 时立即 die，其后内容永不解析（10 处）
- 数据源为整数：pw_forums.fid(smallint unsigned)、pw_medaluser.uid(mediumint unsigned)、
  在线计数、COUNT/SUM 统计（20 处）
- 整段在注释块内：admin/cache.php:840-851（updatecache_cy）、admin/setstyles.php:136-155（editcss 链）

## 缓存目录 include 落点密度（实测统计）
data/bbscache 310 处 · data/groupdb 16 处 · data/style 9 处 · data/forums 0 处
最热：forum_cache.php 74 · forumcache.php 24 · level.php 19 · ol_config.php 15 · o_config.php 12 · area_config.php 9

## 唯一真例外
hack/bank/example.com:362-373 savearray()
  `$arraydb .= '"'.addslashes($value2).'",';`
  → 双引号串 + 只 addslashes（不转义 $ { }）⇒ `${expr}` 求值 ⇒ RCE
  数据源 pw_members.username —— 【varchar(15)】，payload 只有 15 字节，这是本链真实瓶颈
  同请求 include：hack/bank/example.com:76

## 关键字段长度（lang/install_wind.sql，7.5SP3）
pw_members.username varchar(15) ← bank_sort 瓶颈
pw_forums.name 255 · pw_smiles.name 255 / descipt 100 / path 255
pw_styles.name 50 / tplpath 50 · pw_usergroups.grouptitle 60
pw_medalinfo.name 40 · pw_setform.name 30 · pw_customfield.title 50
pw_announce.subject 100 · pw_credits.name/unit 30 · pw_tools.name/filename 20
pw_forumdata.lastpost 135
pw_config.db_value / pw_hack.hk_value = text(65535) ← 长度最宽松

```
