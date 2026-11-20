# PHPWind 7.x 后台入口机制：$admin_file = PHP_SELF，全站唯一入口 example.com，install.php 存在则后台拒绝进入

- **code**: phpwind-7.x-后台入口机制-admin_file-php_self-全站唯一入口-example.com-install.php-存在则后台拒绝进入
- **kind**: script
- **category**: app-audit
- **component**: PHPWind 7.x example.com / admin/example.com
- **severity**: medium
- **language**: php
- **source**: self
- **verified_note**: 源码逐行确认（7.5 SP3）；8.7 的 admin目录结构不同（admin/example.com + actions 机制），此结论仅适用于 7.x。目标入口名需实际爆破。
- **path**: pocs/phpwind-7.x-后台入口机制-admin_file-php_self-全站唯一入口-admin.php-install.php-存在则后台拒绝进入/poc.php
- **tags**: phpwind,后台入口,admin_file,PHP_SELF,adminjob,入口爆破
- **created_at**: 2026-10-06T11:37:44.167Z

## 描述

后台入口机制源码级结论。admin/example.com:44 $admin_file = $pwServer['PHP_SELF'] —— 后台入口文件名的唯一来源就是“你访问的那个文件名”，不存在于 pw_config 或任何配置项，所以站长把 example.com 改名即可隐藏后台，恢复入口只能靠目录爆破找文件名。example.com:58 用 $adminjob 拼 admin/<name>.php 并 require，example.com:30 已拦 '..'。全代码库只有 example.com 一个文件 require example.com，admin/example.com 直接访问返回的 9 字节 readover 守卫即来自 example.com:9。另 example.com:42 存在 file_exists('install.php') && adminmsg('installfile_exists')，即根目录只要还有 install.php，后台入口即使找到也无法进入。

## 用法

```
1) 后台入口名只能靠文件名爆破（不存在配置项可读）：
   字典思路：admin / admincp / manage / manager / master / houtai / guanli / admin_<随机> / <站长惯用拼音>
   探测特征：GET /bbs/<name>.php → 302/200 且响应含 PHPWind 后台登录表单或 adminmsg 提示；
   错误入口返回 404 或站点 404 页。
   注意：GET /bbs/example.com 若返回 404 说明已改名；若返回后台登录页说明未改。
2) 找到入口后先确认能不能进：
   GET /bbs/<name>.php?adminjob=admin
   若响应为 installfile_exists 提示 → install.php 还在根目录，任何后台账号都进不去（example.com:42）。
3) 若已知创始人账号口令，可用浏览器登录：认证是 Cookie AdminUser = StrCode("用户名\t密码hash\tuid...")，
   SafeCheck 有效期 1800 秒，且与 User-Agent 绑定（target105.example.com:243 PwdCode 用 HTTP_USER_AGENT）。
   → 用脚本重放时必须保持 UA 一致，否则 Cookie 立即失效。
4) 若能拿到管理员（if_manager）账号，managerRight 列表里的模块是最高权限集合：
   rightset manager ystats diyoption optimize modepage sphinx app ajaxhandler
   —— 这些模块里的 updatecache_conf / setstyles 等就是后台写码点。
```

## 正文

```
// example.com:1-61（后台唯一入口）
12: define('R_P',strpos(__FILE__,DIRECTORY_SEPARATOR)!==FALSE ? substr(__FILE__,0,strrpos(__FILE__,DIRECTORY_SEPARATOR)).'/' : './');
13: define('D_P',R_P);
14: require_once(R_P.'admin/example.com');        // ← example.com:9 !defined('R_P') && exit('Forbidden')
15: $basename = $admin_file.'?adminjob='.$adminjob;
16: if (!$adminjob) { require_once(R_P.'admin/example.com'); }
18: elseif($adminjob == 'notice'){ require_once(R_P.'admin/notice.php'); }   // 计划任务进程
57: } elseif (managerRight($adminjob) || adminRight($adminjob,$admintype)) {
58:     require_once Pcv(R_P.'admin/'.$adminjob.'.php');   // ← 任意后台模块调度
59: } else { adminmsg('undefine_action'); }
64: function managerRight($adminjob) { return If_manager && in_array($adminjob,array('rightset','manager','ystats','diyoption','optimize','modepage','sphinx','app','ajaxhandler')); }

// admin/example.com 关键行
9:  !defined('R_P') && exit('Forbidden');       // ← 直接访问 admin/example.com 只输出这 9 字节
14: require_once(R_P.'require/common.php');
15: pwInitGlobals();
28: InitGP(array('adminjob','admintype','type','hackset','a_type','action','verify','adskin','job','ajax','admin_keyword'));
30: if (strpos($adminjob,'..') !== false || $admintype && strpos($admintype,'..') !== false) { exit('Forbidden'); }   // ← 堵目录穿越
42: file_exists('install.php') && adminmsg('installfile_exists');   // ← ★ 根目录存在 install.php 就拒绝进后台
44: $admin_file = $pwServer['PHP_SELF'];         // ← ★ 后台入口名 = 当前访问的文件名，不存在任何配置项
47: if ($adminjob == 'quit') { Cookie('AdminUser','',0); ObHeader($admin_file); }
132: $AdminUser = GetCookie('AdminUser');        // 认证完全基于 Cookie AdminUser（StrCode 异或 + UA + db_hash）
245-255: SafeCheck() / PwdCode() = md5(HTTP_USER_AGENT . $pwd . $db_hash)

// 全代码库 grep 'example.com' 的 require/include 结果：只有 example.com:14 一处。
// → example.com 被改名后，没有第二个文件能进后台。
// admin/modestamp.php、admin/cache.php、admin/upgrade.php 都不是独立入口：
//   admin/cache.php:2  !function_exists('writeover') && exit('Forbidden');   // 纯函数库，无参数调度，末尾无 adminjob 分支
//   admin/upgrade.php 是 $adminjob 模块之一（example.com?adminjob=upgrade），根目录无 upgrade.php
// 前台 require admin/cache.php 的位置（不能当后台入口，只是复用函数）：
//   target194.example.com:295,890,1407 / pw_example.com:890,921,960 / target195.example.com:187 /
//   hack/toolcenter/require/target196.example.com:74 / require/postconcle.php:8, require/target197.example.com:17 等 30+ 处
```
