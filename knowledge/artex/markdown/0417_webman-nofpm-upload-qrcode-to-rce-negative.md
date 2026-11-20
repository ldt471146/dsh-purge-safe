# webman 站群(无PHP-FPM) upload-qrcode 上传→RCE 判死：/uploads 的 .php 硬403且不可绕、替代后缀只回源码、全 vhost 无解释器

- **code**: webman-nofpm-upload-qrcode-to-rce-negative
- **kind**: poc
- **category**: file-upload
- **component**: webman / workerman / nginx
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com（203.0.113.95，nginx/1.18.0 Ubuntu + webman，站群含 example.com/example.com/example.com/example.com/example.com/example.com）实测：已上传 .php5 GET 回源码原文(application/octet-stream)、POST 405 Not Allowed；已上传 .php GET 403 Forbidden(564B)，路径/大小写/%2e/%00/%252e/::DATA/..;/ 等十余种变体全 403 或 404，无一解析；同一 .php 经 --resolve 打到全部 vhost 均 403(同 docroot)；根路径 .php 落 SPA try_files(200 example.com)。第二上传点 /api/v1/recharge/upload-voucher 认证后 .php 被 400「只支持 jpg、png、gif、webp 图片」挡。
- **tags**: webman,file-upload,rce,negative,nginx,no-fpm,php后缀
- **created_at**: 2026-10-16T06:30:23.993Z

## 描述

用途：快速判死纯 webman(无 FPM) 站群的「上传→WebShell」路线，避免后人重复投入。判据三件套：①根路径任意 .php 落 SPA try_files(200 example.com)而非 FPM 404/502 ⇒ 无解释器；②已上传 .php5 POST 返回 405 ⇒ nginx 当静态文件；③/uploads 的 .php 403 且任何路径变形不可绕。结论：换后缀(.php5/.phtml/.pht/.phar/.inc)只得到公开源码泄露/同源文件投放点，得不到 webshell；上传文件名扩展名被 pathinfo 清洗不可穿越，extra 字段(dir/path/savePath)被忽略。执行只在 webman Monitor 监听目录(config/ 等)有效，而上传落点 public/uploads 不在其中。

## 用法

```
判定命令：curl -k -s -D- -o- "https://T/uploads/x.php5" # 源码原文=不执行；curl -k -X POST -d "0=echo OK;" "https://T/uploads/x.php5" # 405=静态；curl -k -o- "https://T/zzz.php" # SPA example.com=无FPM。若三判据成立，放弃上传→RCE，转自动路由/越权读数据或同源 XSS 打运营会话。
```
