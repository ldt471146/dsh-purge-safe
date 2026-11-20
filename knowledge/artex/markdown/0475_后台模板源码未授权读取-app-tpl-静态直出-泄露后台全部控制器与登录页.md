# 后台模板源码未授权读取（App/Tpl 静态直出，泄露后台全部控制器与登录页）

- **code**: 后台模板源码未授权读取-app-tpl-静态直出-泄露后台全部控制器与登录页
- **kind**: poc
- **category**: info-leak
- **severity**: medium
- **source**: manual
- **tags**: info-leak
- **created_at**: 2026-10-28T19:41:01.842Z

## 描述

零凭证请求 /App/Lib/Action/Home/OrderAction.class.php/（尾部斜杠触发 fastcgi_split_path_info）即把该 .class.php 直接交给 PHP-FPM 执行，Fatal error 回显站点绝对部署路径 /www/wwwroot/thisthbweb_com/，且 display_errors 开启。该缺陷本身为低危信息泄露，但它证明 nginx 对 /App/ 下 .php 无 deny、docroot 内任意 .php 落地即执行，是后续拿后台/写文件后最短 RCE 闭环的关键条件。
