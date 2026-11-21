# 166 KindEditor 上传/文件管理接口未授权（可零凭证上传 html/图片并回读 + 目录列举）

- **code**: 166-kindeditor-上传-文件管理接口未授权-可零凭证上传-html-图片并回读-目录列举
- **kind**: poc
- **category**: file-upload
- **severity**: medium
- **source**: manual
- **tags**: file-upload
- **created_at**: 2026-10-28T19:41:01.758Z

## 描述

45.151.135.166（SomCNS/ThinkPHP3.1.3，docroot=/www/wwwroot/kkjjer_com）的 KindEditor 上传接口 /Public/main/js/kindeditor/php/upload_json.php 与文件管理接口 file_manager_json.php 无任何鉴权：零 Cookie 即可上传 jpg/txt/html 等文件到 /Upload/<dir>/YYYYMMDD/ 并原样回读，同时可零凭证列举 /Upload/ 下 12 个业务目录（含 List、qrcode、vlive 等）。实测上传 MARKER604IMG.jpg 与 .txt/.html 后回读内容一致，上传回显还泄露站点配置域名 kjadmin.com。扩展名白名单（image: gif/jpg/jpeg/png/bmp；file: doc/docx/xls/xlsx/ppt/htm/html/txt/zip/rar/gz/bz2）与目录名白名单有效，未取得 PHP 代码执行。
