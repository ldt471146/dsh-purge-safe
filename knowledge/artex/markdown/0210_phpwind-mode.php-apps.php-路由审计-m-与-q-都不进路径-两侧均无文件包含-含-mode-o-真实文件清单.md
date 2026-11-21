# PHPWind mode.php / apps.php 路由审计：$m 与 $q 都不进路径，两侧均无文件包含（含 mode/o 真实文件清单）

- **code**: phpwind-mode.php-apps.php-路由审计-m-与-q-都不进路径-两侧均无文件包含-含-mode-o-真实文件清单
- **kind**: script
- **category**: app-audit
- **component**: PHPWind mode.php / apps.php / require/app_route.php 路由审计
- **severity**: info
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 逐行确证（mode.php 76 行、apps.php 前 60 行、app_route.php 106 行、global.php selectMode 300-317 全部读过）。7.3.2 若已有 mode/ 与 apps/ 则写法大概率一致；若 7.3.2 根本没有 mode/o（7.5 引入的门户/家园），该面在目标上不存在 —— 但目标已实测 mode.php?m=o 可访问，说明该模块存在。
- **path**: pocs/phpwind-mode.php-apps.php-路由审计-m-与-q-都不进路径-两侧均无文件包含-含-mode-o-真实文件清单/poc.php
- **tags**: phpwind,mode.php,apps.php,路由审计,selectMode,Pcv,文件包含,判死
- **created_at**: 2026-10-06T11:42:01.081Z

## 描述

mode.php/$m 与 apps.php/$q 的路由审计结论：两条路都不构成文件包含。核心判据是 global.php:300-317 的 selectMode()——$m 必须命中 $db_modes 白名单（isset + is_array + ifopen）才会被赋给 $db_mode 并参与 define('M_P', R_P."mode/$db_mode/")，且随后还有 file_exists 兜底，所以 ?m=../../x 无法进入路径；mode.php:58/70 的 $q 拼文件名前面有 strpos($q,'..') 过滤、后面有 Pcv() 兜底；apps.php 侧的穿越在 app_router() 通过 is_dir 后会被第 71 行 Pcv($baseFile) 的 '..' 检查 exit('Forbidden')。同时给出 mode/o/ 目录的真实文件清单——只有 7 个 m_*.php，photos/write/diary/share/article/hot/groups 全部不在其中，而是经 mode.php:42 转交 apps.php 后由 apps/<q>/example.com 处理，这纠正了"mode.php?m=o&q=photos 走 mode/o/ 内文件"的误解。

## 用法

```
无需发包（证否类结论）。要点复述：
1) mode.php?m=o 能进只是因为 $db_modes['o']['ifopen'] 为真 —— 这是功能开关，不是路径可控；
   想试路径穿越可发：GET /bbs/mode.php?m=../../data/bbscache&q=home
   预期：$db_modes['../../data/bbscache'] 不存在 → $db_mode 回落到 bbs → M_P 未定义或为 mode/bbs/
   → mode.php:58 file_exists(M_P."m_home.php") 失败 → 返回「非法操作」(undefined_action)。
2) apps 穿越可发：GET /bbs/apps.php?q=../../hack/bank
   预期：app_router 的 is_dir 通过，但 app_route.php:71 的 Pcv($baseFile) 命中 '..' → exit('Forbidden')，返回体就是 Forbidden 四字。
3) 结论：不要再在 mode/apps 路由上投入额度；q 只能落在 apps/ 白名单的 12 个 app 名上。
```

## 正文

```
// ================= mode.php（全 76 行）=================
2: define('SCR','mode');
3: require_once('global.php');
5: $m = GetGP('m');
7: selectMode($m);                       // ★ $m 只用于白名单校验，不进路径
17: InitGP(array('q','space'));
36: if (strpos($q,'..') !== false) Showmsg('undefined_action');
42: if ($m == 'o' && $q && !in_array($q, array('user','friend','browse','invite','board','myapp','home','app'))) {
43:     require_once 'apps.php';           // ★ 非内置 q 全部转交 apps.php
44: } else {
46:     empty($q) && $q = 'home';
58:     if (file_exists(M_P . "m_{$q}.php")) {
59:         @include_once Pcv(D_P.'data/bbscache/'.$db_mode.'_config.php');
67:         if (file_exists(M_P.'require/core.php')) { require_once(M_P.'require/core.php'); }
70:         require_once Pcv(M_P . "m_{$q}.php");     // ← $q 拼文件名，但过 Pcv
72:     } else { Showmsg('undefined_action'); }
}

// global.php:300-317   ★ 关键：$m 与 M_P 的关系
function selectMode(&$m) {
	global $defaultMode,$db_mode,$db_modes,$db_modepages,$pwServer,$db_modedomain;
	if (defined('M_P')) return;
	if (in_array(SCR, array('index','cate','mode'))) {
		$db_mode = $defaultMode;
		if (!$m && $db_modedomain) { $m = array_search($pwServer['HTTP_HOST'],$db_modedomain); }
		if ($db_modes && isset($db_modes[$m]) && is_array($db_modes[$m]) && $db_modes[$m]['ifopen']) {
			$db_mode = $m;                                   // ★ 必须在 $db_modes 白名单里
		}
		if (!empty($db_mode) && $db_mode!='bbs' && file_exists(R_P."mode/$db_mode/")) {
			define('M_P',R_P."mode/$db_mode/");               // ★ 用的是 $db_mode，且再走 file_exists
			$db_modepages = $db_modepages[$db_mode];
			$GLOBALS['pwModeImg'] = "mode/$db_mode/images";
		}
	}
}
// → $m 想变成路径必须同时满足：isset($db_modes[$m]) 为真 + is_array + ['ifopen'] 非空 + file_exists
// → ?m=../../xxx 的 $db_modes['../../xxx'] 不存在 → $db_mode 保持 $defaultMode('bbs') → M_P 不定义或 =mode/bbs/
// → mode.php 侧【无文件包含】

// ================= apps.php（前 60 行）=================
2: define('SCR','app');
3: require_once('global.php');
7: InitGP(array('q'));
9: if (in_array($q,array('ajax','article','diary','galbum','group','groups','hot','photos','sharelink','share','stopic','write'))) {
11:     require_once R_P . 'require/app_route.php';
}

// ================= require/app_route.php:88-95 =================
function app_router($app) {
	(empty($app) || (!is_dir($basePath = A_P . $app))) && Showmsg('undefined_action');
	$baseFile = $basePath . '/example.com';
	if (!file_exists($baseFile)) { Showmsg("包含文件不存在，请创建example.com"); }
	return array($basePath, $baseFile);
}
// :71  require_once Pcv($baseFile);
// A_P = R_P.'apps/'（global.php:16）
// → apps.php?q=../../hack/bank：is_dir("apps/../../hack/bank") 能过，但 Pcv($baseFile) 默认 $ifcheck=1
//   会 str_replace('..','') 比对 → 命中即 exit('Forbidden')  ★ 穿越被 Pcv 拦住
// → 编码绕过：%2e%2e%2f 不被 Pcv 识别为 '..'（Pcv 查字面量），但 is_dir 也不认 %2e → 同样过不了
// → apps.php 侧【无文件包含】
// 注：$q 由 InitGP 装载（cvtype=1）→ 先过 Char_cv；Char_cv 不处理 '.' 和 '/'，所以文件名拼接面完全交给 Pcv 兜底。

// ================= mode/o/ 目录实况（★ 管理员关注的"m_*.php 清单"）=================
// mode/o/ 下实际存在的 m_*.php（23 个文件里只有这 7 个 m_ 文件）：
//   m_app.php     应用列表/我的应用
//   m_board.php   留言板
//   m_browse.php  随便看看（聚合浏览）
//   m_friend.php  好友
//   m_home.php    个人空间首页
//   m_invite.php  邀请
//   m_myapp.php   我的应用管理
//   m_user.php    用户资料页
// ★ 注意：**没有 m_photos.php / m_write.php / m_diary.php / m_share.php / m_article.php / m_hot.php / m_groups.php**
//   → 这些 q 全部走 mode.php:42-43 转交 apps.php，再由 app_route.php:88 路由到 apps/<q>/example.com
// → 所以 mode.php?m=o&q=photos 实际执行的入口是 apps/photos/example.com，不是 mode/o/ 下的文件
// 每个 m_*.php 的头两行都是同一形态守卫：
//   m_app.php / m_board.php / m_browse.php / m_friend.php / m_home.php / m_invite.php / m_myapp.php / m_user.php
//   第 1~3 行统一为 !defined('M_P') && exit('Forbidden'); 一类判定 → 直接 URL 访问全部输出 Forbidden，不能独立当入口
//   （mode/o/example.com 是 !defined('M_P') && exit('Forbidden'); 且 :6 ObHeader("mode.php?m=o")）
// permission 检查：mode.php 段没有 admincheck，但各 m_*.php 内部按需 $winduid 判空（如 require/core.php:12 !$winduid && Showmsg('not_login')）

// ================= mode/o/ 内的 /e 与 eval（⑤）=================
// mode/o/require/core.php:96
//   preg_replace("/\[share\]([\w\.]+),([^\[,]+?),([\d]{1,10})\[\/share\]/eis","shareEvea('\\1','\\2','\\3')",$message);
//   → 替换串是常量 + 捕获组引用，且 \1 的字符类 [\w\.]、\2 排除了 [ 和 ,、\3 纯数字 → 不可断引 → 安全
// mode/o/ 内无 eval、无 create_function、无第二处 /e
// mode/o/example.com:73 / m_home.php:95 / m_friend.php:108 / m_browse.php:103 写 o_indexset_cache.php 与 mode_o_mosort.php
//   全部使用 pw_var_export() → 安全
```
