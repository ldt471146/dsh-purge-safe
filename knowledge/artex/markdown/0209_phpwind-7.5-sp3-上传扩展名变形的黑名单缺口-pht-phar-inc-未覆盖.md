# PHPWind 7.5 SP3 上传扩展名变形的黑名单缺口（pht/phar/inc 未覆盖）

- **code**: phpwind-7.5-sp3-上传扩展名变形的黑名单缺口-pht-phar-inc-未覆盖
- **kind**: poc
- **category**: file-upload
- **component**: PHPWind lib/upload/*.class.php 扩展名变形
- **severity**: medium
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 源码逐行确认变形函数与黑名单缺口。利用成立还需目标 $db_uploadfiletype 放开对应后缀，且 nginx 解析该后缀 —— 属外推，未对目标验证。
- **path**: pocs/phpwind-7.5-sp3-上传扩展名变形的黑名单缺口-pht-phar-inc-未覆盖/poc.php
- **tags**: phpwind,附件上传,扩展名变形,pht,后台白名单
- **created_at**: 2026-10-06T11:40:33.728Z

## 描述

PHPWind 附件上传的扩展名变形机制与残余缺口。两道变形/校验：target53.example.com:175 与 target51.example.com:30 用 preg_replace('/(php|asp|jsp|cgi|fcgi|exe|pl|phtml|dll|asa|com|scr|inf)/i',"scp_\\1",$ext) 把危险后缀前缀化；lib/target52.example.com:152 的 postupload() 只堵 '..'、'.php.'、'.php$'。黑名单未覆盖 .pht / .phtm / .phar / .inc / .shtm，因此若后台附件白名单 $db_uploadfiletype 里出现这些后缀即可原样落地；能否解析取决于宝塔 nginx 是否把它们交给 PHP-FPM。落盘后 @chmod 0777。

## 用法

```
前置：目标后台 $db_uploadfiletype 含 pht（或 phar/inc），或 7.3.2 的变形函数更弱。
判定（1-2 包，需已登录且该用户组有上传权限）：
  1) 发帖页确认附件上传入口：GET /bbs/post.php?fid=<fid>，看有无类型下拉/上传按钮（$_G['upload'] 权限）。
  2) POST /bbs/example.com?action=upload（或 post.php 的上传流程）上传 x.pht，内容含 <?php phpinfo();?>
  3) GET /bbs/attachment/<dir>/<fid>_<uid>_xxxxx.pht  看是否被当 PHP 解析。
回显：phpinfo 表格说明 nginx 把 .pht 交给了 PHP-FPM。
注意：这条与 front-end 的"扩展名变形"是同一道墙的两侧，若后台白名单不含 pht 则整条不通；不要为此单独爆破后台。
```

## 正文

```
// 附件/图片上传的扩展名"变形"防护（7.5 SP3）
// lib/upload/target53.example.com:175
$filename = $this->forum->fid . "_{$this->uid}_$prename." . preg_replace('/(php|asp|jsp|cgi|fcgi|exe|pl|phtml|dll|asa|com|scr|inf)/i', "scp_\\1", $currUpload['ext']);
// lib/upload/target51.example.com:30
$filename = "0_{$this->uid}_$prename." . preg_replace('/(php|asp|jsp|cgi|fcgi|exe|pl|phtml|dll|asa|com|scr|inf)/i', "scp_\\1", $currUpload['ext']);
// lib/upload/target53.example.com:98（另一处，与扩展名无关）
$rt['fileuploadurl'] = $filename = $thumbname = preg_replace('/^0_/', "{$this->forum->fid}_", $rt['attachurl']);

// 黑名单覆盖：php asp jsp cgi fcgi exe pl phtml dll asa com scr inf
// 注意：php5/php3/php4/php7/phps 会被子串 "php" 先命中 → 变 scp_php5，仍被拦。
// 未覆盖且常见的 PHP 可解析后缀：pht（还有 phtm、phar、inc、shtm、shtml）
//   → 若后台 $db_uploadfiletype（附件白名单）里出现 pht，则 .pht 能原样落地。
//   是否被 PHP-FPM 解析取决于宝塔 nginx 站点配置（默认只解析 .php，AddHandler 型配置则会解析 pht）。
// 另两道更前置的墙：
//   lib/target52.example.com:31  if (empty($upload['ext']) || !isset($bhv->ftype[$upload['ext']])) uploadmsg('upload_type_error');
//   lib/target52.example.com:152 if (strpos($filename,'..')!==false || strpos($filename,'.php.')!==false || eregi("\.php$",$filename)) exit('illegal file type!');
//   → postupload() 只堵 .. / .php. / .php$，并未堵 .pht / .php5 / .php3（大小写由 eregi 处理）
//   → 但真实文件名由 attupload/mutiupload 用白名单 ext 拼出，只有 $db_uploadfiletype 放开才有机会。
// 落盘目录：$attachdir/$dir（默认 attachment/），@chmod($dstfile,0777)（lib/target52.example.com:134/137/157/160/166）
// $db_uploadfiletype 的默认值集合不在 install_wind.sql 硬编码里（由后台 optimize/upload 设置生成）。
```
