# PHP /e 三类替换串（形态 A 死 / 形态 B 语法可行 / 形态 C 真危险）+ Char_cv 不处理括号与 CheckVar 白名单的实测印证

- **code**: php-e-修饰符引擎级否证-捕获组被-php_addslashes-转义-return-前缀-断引攻击不成立-php_pcre.c-961
- **kind**: script
- **category**: rce
- **component**: PHP 5.x /e 修饰符引擎语义（php-src 官方源码铁证）
- **severity**: info
- **language**: php
- **source**: self
- **source_url**: https://github.com/php/php-src/blob/PHP-5.5/ext/pcre/php_pcre.c#L961
- **verified**: 1
- **verified_note**: 引擎部分（形态 A/B/C 的判定依据）引自 php-src PHP-5.5 官方源码，本机已下载并逐行阅读 php_pcre.c:920-997 与 zend_execute_API.c:1139-1151，无须目标验证。清洗部分的目标实测判据（prosign 括号保留、引号实体化）由利用端在目标 7.3.2 上取得，与 require/target105.example.com:646-679 及 target116.example.com:53-57 的源码完全吻合。
- **path**: pocs/php-e-修饰符引擎级否证-捕获组被-php_addslashes-转义-return-前缀-断引攻击不成立-php_pcre.c-961/poc.php
- **tags**: php,/e,preg_replace,php_addslashes,preg_do_eval,引擎级判据,否证
- **created_at**: 2026-10-06T11:44:57.002Z

## 描述

（2026-10 更新：加入形态 A/B 分类与目标实测判据）preg_replace 的 /e 修饰符在 php-src PHP-5.5 里的执行语义，决定了三类替换串的命运完全不同。障碍一（对所有 backref 无条件生效）：ext/pcre/php_pcre.c:922-997 preg_do_eval() 是 /e 的唯一执行路径，第 945 行把 \1 与 $1 两种反向引用都认出来，第 961 行对每一个 match 无条件调用 php_addslashes()，转义 ' " \ NUL 四个字符，无例外分支。障碍二：Zend/zend_execute_API.c:1139-1151 显示 zend_eval_stringl 在代码前拼 "return "，即 /e 等价于 eval("return <替换后串>;")。形态 A（\1 落在引号内，如 phpcode('\1')）：php_addslashes 把 ' 变 \' → 无法闭合字符串 → 死，且与站点清洗无关。形态 B（\1 落在函数参数位/表达式位置，如 func(\1)）：payload 不含引号时不触发 addslashes，理论上可行，但必须绕开 return 的单表达式限制（return 后跟逗号表达式是语法错误），可行形态是用运算符连接，例如捕获组 1)+(phpinfo())+(1 使 eval 得到 return func(1)+(phpinfo())+(1);。形态 C（替换串里在 preg_replace 调用之前就有变量插值，如 copyctrl('$read[colour]')）：不受 addslashes 影响，是真正危险形态。另附目标实测判据：Char_cv（require/target105.example.com:646-666）只实体化 " ' < > 与折叠制表符/双空格，不处理括号；CheckVar（require/target105.example.com:667-679）确实把 ) = < .. 换成实体，但 target116.example.com:53-57 的 5 个字段名白名单（atc_content / atc_title / prosign / pwuser / pwpwd）完全豁免 CheckVar —— 目标上 prosign 实测括号原样保留、引号被实体化，正是这两条规则叠加的结果。

## 用法

```
这是"前置判据"型知识，无需对目标发包。审计任何 PHP 5.x 站点时按此顺序判 /e：
1) 替换串里有没有【在 preg_replace 调用之前】就存在的变量/数组插值（PHP 双引号插值、字符串拼接、sprintf）？
   - 有 → 该点危险，按变量可控性继续追（PHPWind 7.5 全站只有 2 处：target191.example.com:345 与 target192.example.com:409，均为 $read['colour']）
   - 没有，只有 \1 / $1 捕获组 → 【直接判死，不必再追清洗链】，因为 php_addslashes 在引擎层挡住断引
2) 想自查该结论，可用本机任一 PHP 5.x 跑：
     var_dump(preg_replace('/(x)/e','"a"  . "\\1"','x'));   // 观察 \\1 内容被转义
   本机无 PHP 时可读 runs/pw-src-732/php-src-verify/php_pcre.c 第 920-997 行。
3) 注意区分：PCRE 的 /e 已随 PHP 7 移除；PHP 8 下同样代码会因未知修饰符而 warning 并退化为普通替换。
```

## 正文

```
// ==================================================================
// preg_replace /e 三类替换串的命运（php-src PHP-5.5 官方源码 + 目标实测）
// 源码已下载：runs/pw-src-732/php-src-verify/php_pcre.c (62042B) / zend_execute_API.c (51408B)
// ==================================================================

// ---- 引擎语义 ----
// ext/pcre/php_pcre.c:922-997  preg_do_eval() —— /e 的唯一执行路径
945:         if ('\\' == *walk || '$' == *walk) {          // \1 与 $1 都算反向引用
961:                         esc_match = php_addslashes(match, match_len, &esc_match_len, 0 TSRMLS_CC);   // ★ 无条件
970:                 smart_str_appendl(&code, esc_match, esc_match_len);
988:     if (zend_eval_stringl(code.c, code.len, &retval, compiled_string_description TSRMLS_CC) == FAILURE) {

// Zend/zend_execute_API.c:1139-1151
1148:     Z_STRLEN(pv) = str_len + sizeof("return ;") - 1;
1150:     memcpy(Z_STRVAL(pv), "return ", sizeof("return ") - 1);
1151:     memcpy(Z_STRVAL(pv) + sizeof("return ") - 1, str, str_len);
// → /e 对每个匹配等价于 eval("return <替换后的串>;")

// ---- 形态 A：\1 落在引号内（死）----
// 替换串： phpcode('\\1')       实际字符串： phpcode('\1')
// 捕获组含 ' → php_addslashes 变 \' → 插进去是 \' → 已转义引号 → 无法闭合 → Parse error
// 【与站点清洗无关，纯引擎行为】

// ---- 形态 B：\1 落在函数参数位/表达式位置（语法上可行）----
// 替换串： func(\1)
// 捕获组： 1),phpinfo(),strtolower(1     → eval("return func(1),phpinfo(),strtolower(1);")
//   ✗ 这是语法错误：PHP 的 return 只接受单个表达式，逗号在表达式级不是运算符
// 捕获组： 1)+(phpinfo())+(1              → eval("return func(1)+(phpinfo())+(1);")
//   ✓ 合法：单个表达式，phpinfo() 在执行过程中被调用
// 捕获组： 1)+(system)(id)+(1             → 反引号版：1)+(`id`)+(1  → 系统命令执行
// 要点：形态 B 的 payload 不含 ' " \ NUL，因此绕过 php_addslashes；
//       但必须用运算符（+ . && || 等）把所有片段连成【一个】表达式，不能出现裸分号或逗号。

// ---- 形态 C：替换串在 preg_replace 调用前已有变量插值（真正危险）----
// reg = preg_replace($p, "func('$v')", $s)      ← $v 在前一次 PHP 双引号插值时就已进入，不过 addslashes
// PHPWind 7.5 全站只有 2 处：require/target191.example.com:345 与 lib/target192.example.com:409，均为 $read['colour']

// ---- 目标实测判据（7.3.2，prosign 字段，落库回读）----
// 写入 [b]prosign_probe_7k2[/b]<\>'")
// 回读 [b]prosign_probe_7k2[/b]&lt;\&gt;&#39;&quot;)
// → < > ' " 全部实体化；【( ) 原样保留】
// 源码对应：
//   require/target105.example.com:646-666 Char_cv：str_replace(array('%3C','<'),'&lt;')、('%3E','>')→'&gt;'、
//        ('"',"'","\t",'  ')→('&quot;','&#39;','    ','&nbsp;&nbsp;')  ← 【不碰 ( )】
//   require/target105.example.com:667-679 CheckVar：str_replace(array('..',')','<','='),array('&#46;&#46;','&#41;','&#60;','&#61;'))
//        ← 确实处理 )，但——
//   target116.example.com:53-57：if (!in_array($_key,array('atc_content','atc_title','prosign','pwuser','pwpwd'))) { CheckVar(...); }
//        ← prosign 在白名单里，【完全跳过 CheckVar】
// → 实测结果 = "Char_cv 不处理括号" + "prosign 豁免 CheckVar" 两条规则的叠加，与源码完全一致，无矛盾。
// → 推论：CheckVar 的 ) 实体化只对【非白名单字段】生效；白名单字段要单独看其 InitGP 的 cvtype。
```
