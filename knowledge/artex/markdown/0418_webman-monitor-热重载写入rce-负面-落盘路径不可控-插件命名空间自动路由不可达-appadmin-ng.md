# webman「写入 Monitor 监听目录→热重载 RCE」判死：落盘路径不可控 + 插件 admin 命名空间自动路由不可达 + /app/admin 被 nginx 遮蔽（example 站群）

- **code**: webman-monitor-热重载写入rce-负面-落盘路径不可控-插件命名空间自动路由不可达-appadmin-ng
- **kind**: poc
- **category**: rce
- **component**: webman / workerman / Pear Admin
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 2026-10-16 在 example.com/example.com(203.0.113.95) 实测：① 源码 work/example/boyue-full/boyue 核 config/process.php monitorDir 含 app_path()/config_path()/plugin/*/{app,config,api}、Monitor.php 热重载逻辑；② 全部写 sink 落盘固定(uniqid/时间戳)，AuthController:262 的 $userId 来源 AuthMiddleware:101 =$payload->uid 而非请求参数；③ POST /api/v1/withdraw/upload-qrcode filename=../../../../config/x.php → {\"code\":0,...,\"url\":\"/uploads/qrcode/20261016/<hex>_1435.php\"}(固定)；④ VPS 直连 /app/admin/api/statistics/overview、/app/admin/withdraw-account/select、/app/admin/api/game-category/index 全 [404 564] nginx；⑤ /api/install/step1、/api/table/crud、/api/financeApi/* 零凭证 → webman {\"code\":404,\"msg\":\"404 Not Found\"}。写进 Monitor 目录的 .php 落盘不可达，上传→热重载 RCE 判死。
- **tags**: webman,workerman,monitor,热重载,file-write,自动路由,命名空间,nginx,negative
- **created_at**: 2026-10-16T07:05:00.656Z

## 描述

webman(无 PHP-FPM) 目标「写入 Monitor 监听目录→热重载 RCE」链的判定：需同时满足(1)存在可控落盘路径/文件名且落入 monitorDir(app/、config/、process/、support/、resource/、.env、plugin/*/{app,config,api})，(2)该写点路由可达。两层判据与本次阴性证据。

## 用法

```
1) 先确认 Monitor 开：源码 config/process.php monitor.monitorDir + app/process/Monitor.php enable_file_monitor( Linux 且未带 -d )；无源码时以“能否写进 app/config”这一唯一执行机制为口径。2) grep 全站 file_put_contents / ->move( / ZipArchive::extractTo，逐点看路径是否含可注入的 $request 变量(尤其 $request->userId —— webman AuthMiddleware 常用 $request->userId=$payload->uid 绑 JWT，不取请求参数，不可注入)。3) 判“写点路由可达”：插件 admin 的写原语(TableController::crud、InstallController::step1 注入 DB 配置、PluginController::install 解压)均注册在 /app/admin/* 且属 plugin\admin\app\controller 命名空间——webman 自动路由 /api/<ctrl>/<act> 只解析 app\controller\*(返回 code404 即证明不覆盖插件命名空间)；若 nginx 有 location ^~ /app/admin 静态遮蔽，则该前缀恒 404，写原语全不可达。4) 阴性判定三连：上传/avatar 实测 filename=../../../../config/x.php 回显固定路径；/app/admin/* 全 404(564B nginx)；/api/install/step1、/api/table/crud 返 webman code404。
```
